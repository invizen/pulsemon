package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// restartHarness saves and restores the two seams that touch the live system
// (detectRestart / performRestart) and records what the restart path did.
// A unit test must NEVER run systemctl against the host it runs on.
//
// These tests call handleRestart directly — NOT runUpdate — because
// runUpdate's install step renames the downloaded binary over
// os.Executable(), which under `go test` is the cached test binary
// (/tmp/go-build.../pulsemon.test). Going through handleRestart keeps the
// install path entirely out of the tests, so no fake payload ever lands on
// the test binary and the suite has no dependency on the build cache
// self-healing a clobbered binary.
type restartHarness struct {
	detectBus  string // what detectRestart returns
	restarted  []string
	restartErr error
}

func withRestart(t *testing.T, h *restartHarness) {
	t.Helper()
	oldDetect, oldPerform := detectRestart, performRestart
	detectRestart = func() string { return h.detectBus }
	performRestart = func(bus string) error {
		h.restarted = append(h.restarted, bus)
		return h.restartErr
	}
	t.Cleanup(func() {
		detectRestart, performRestart = oldDetect, oldPerform
	})
}

// setHealthzTarget points PULSEMON_ADDR at an httptest server's host:port so
// waitHealthy's default healthzTarget derivation reaches it.
func setHealthzTarget(t *testing.T, srv *httptest.Server) {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	t.Setenv("PULSEMON_ADDR", u.Host)
}

// TestHandleRestartHappy pins the --restart happy path: a detected user-bus
// service is restarted, the new binary comes up healthy, and the stage
// returns 0 reporting success.
func TestHandleRestartHappy(t *testing.T) {
	h := &restartHarness{detectBus: "user"}
	withRestart(t, h)

	healthz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer healthz.Close()
	setHealthzTarget(t, healthz)

	code, out := captureOutput(t, func() int { return handleRestart("/opt/pulsemon/pulsemon", true) })
	if code != 0 {
		t.Fatalf("handleRestart = %d, want 0: %s", code, out)
	}
	if len(h.restarted) != 1 || h.restarted[0] != "user" {
		t.Fatalf("restarted = %v, want [user]", h.restarted)
	}
	if !strings.Contains(out, "restarting pulsemon (user service)") {
		t.Errorf("output missing the restart line: %s", out)
	}
	if !strings.Contains(out, "up and healthy") {
		t.Errorf("output missing the healthy confirmation: %s", out)
	}
}

// TestHandleRestartUnhealthy pins the monitor-blind-spot guard: when the
// service restarts but does NOT come up healthy, the stage must return 1 and
// point the operator at journalctl — a bad new version must surface a
// failure, not a silent "done".
func TestHandleRestartUnhealthy(t *testing.T) {
	h := &restartHarness{detectBus: "user"}
	withRestart(t, h)

	// The restarted service is up but reports 503 — "restarted but not
	// healthy". Shrink the poll window so the test is fast.
	healthz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer healthz.Close()
	setHealthzTarget(t, healthz)
	oldTimeout := healthzTimeout
	healthzTimeout = 1 * time.Second
	t.Cleanup(func() { healthzTimeout = oldTimeout })

	code, out := captureOutput(t, func() int { return handleRestart("/opt/pulsemon/pulsemon", true) })
	if code != 1 {
		t.Fatalf("handleRestart unhealthy = %d, want 1: %s", code, out)
	}
	if len(h.restarted) != 1 {
		t.Fatalf("restarted = %v, want [user] (restart was attempted)", h.restarted)
	}
	if !strings.Contains(out, "not answering healthz") {
		t.Errorf("output missing the unhealthy warning: %s", out)
	}
	if !strings.Contains(out, "journalctl --user -u pulsemon") {
		t.Errorf("output missing the journalctl pointer: %s", out)
	}
}

// TestHandleRestartFails pins the systemctl-restart-failure path: the
// service is detected but the restart command fails, so the stage returns 1
// with a restart-failed diagnostic and does NOT proceed to the health check.
func TestHandleRestartFails(t *testing.T) {
	h := &restartHarness{detectBus: "user", restartErr: errForTest}
	withRestart(t, h)

	code, out := captureOutput(t, func() int { return handleRestart("/opt/pulsemon/pulsemon", true) })
	if code != 1 {
		t.Fatalf("handleRestart failing = %d, want 1: %s", code, out)
	}
	if len(h.restarted) != 1 {
		t.Fatalf("restarted = %v, want [user]", h.restarted)
	}
	if !strings.Contains(out, "restart failed") {
		t.Errorf("output missing the restart-failed diagnostic: %s", out)
	}
}

// errForTest is a sentinel error the performRestart stub returns.
var errForTest = &testError{msg: "systemctl: Unit pulsemon.service not found"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

// TestHandleRestartNoService pins the safe default: when no live service is
// confidently detected (detectRestart returns ""), the stage must NOT
// restart and must fall back to the hint, returning 0.
func TestHandleRestartNoService(t *testing.T) {
	h := &restartHarness{detectBus: ""}
	withRestart(t, h)

	code, out := captureOutput(t, func() int { return handleRestart("/opt/pulsemon/pulsemon", true) })
	if code != 0 {
		t.Fatalf("handleRestart no service = %d, want 0: %s", code, out)
	}
	if len(h.restarted) != 0 {
		t.Fatalf("restarted = %v, want empty (no service, so no restart)", h.restarted)
	}
	if !strings.Contains(out, "no live pulsemon service detected") {
		t.Errorf("output missing the no-service hint: %s", out)
	}
}

// TestHandleRestartContainer pins the container case: exe == "/pulsemon"
// means the running image's binary is unchanged, so the --restart path must
// NOT attempt a restart — only the rebuild warning.
func TestHandleRestartContainer(t *testing.T) {
	h := &restartHarness{detectBus: "user"}
	withRestart(t, h)

	code, out := captureOutput(t, func() int { return handleRestart("/pulsemon", true) })
	if code != 0 {
		t.Fatalf("handleRestart(container, --restart) = %d, want 0: %s", code, out)
	}
	if len(h.restarted) != 0 {
		t.Fatalf("container case restarted a service = %v, want none", h.restarted)
	}
	if !strings.Contains(out, "--restart ignored") {
		t.Errorf("output missing the container --restart-ignored warning: %s", out)
	}
}

// TestHandleRestartNoRestartByDefault pins the default contract: without
// --restart, the post-install stage must NOT restart anything — it only
// prints the hint. This is the mixed-fleet safety the whole feature rests on.
func TestHandleRestartNoRestartByDefault(t *testing.T) {
	h := &restartHarness{detectBus: "user"} // a service exists…
	withRestart(t, h)                       // …but the default must still not restart it.

	code, out := captureOutput(t, func() int { return handleRestart("/opt/pulsemon/pulsemon", false) })
	if code != 0 {
		t.Fatalf("handleRestart(default) = %d, want 0: %s", code, out)
	}
	if len(h.restarted) != 0 {
		t.Fatalf("default run restarted the service = %v, want none (hint only)", h.restarted)
	}
	if !strings.Contains(out, "restart with:") {
		t.Errorf("default run should print the restart hint: %s", out)
	}
}

// TestHealthzTarget pins the PULSEMON_ADDR → host:port derivation (must match
// install.sh, which healthchecks the same way).
func TestHealthzTarget(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{"", "localhost:9299"},
		{":9299", "localhost:9299"},
		{":8443", "localhost:8443"},
		{"127.0.0.1:9299", "127.0.0.1:9299"},
		{"10.99.99.5:9300", "10.99.99.5:9300"},
		{"9299", "localhost:9299"},
	}
	for _, c := range cases {
		t.Setenv("PULSEMON_ADDR", c.addr)
		if got := healthzTarget(); got != c.want {
			t.Errorf("healthzTarget() with PULSEMON_ADDR=%q = %q, want %q", c.addr, got, c.want)
		}
	}
}

// TestWaitHealthyReachesServer pins that waitHealthy actually polls a live
// endpoint and returns ok on a 2xx — the positive half of the post-restart
// health check.
func TestWaitHealthyReachesServer(t *testing.T) {
	healthz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer healthz.Close()
	setHealthzTarget(t, healthz)

	oldTimeout := healthzTimeout
	healthzTimeout = 3 * time.Second
	t.Cleanup(func() { healthzTimeout = oldTimeout })

	ok, detail := waitHealthy()
	if !ok {
		t.Fatalf("waitHealthy = false, want true (server is up): %s", detail)
	}
}

// TestSystemctlActiveBoundedByTimeout proves the restart path can't hang on a
// wedged dbus: a fake `systemctl` that sleeps past the timeout must cause
// systemctlActive to return false (treated as "no live service"), not stall.
// Without the context bound this test would hang for the fake's full sleep.
func TestSystemctlActiveBoundedByTimeout(t *testing.T) {
	// A fake systemctl that ignores args and sleeps — simulates a wedged dbus
	// that never answers `is-active`.
	dir := t.TempDir()
	fake := filepath.Join(dir, "systemctl")
	script := "#!/bin/sh\nsleep 30\n"
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathSeparator)+os.Getenv("PATH"))

	oldActive, oldRestart := activeTimeout, restartTimeout
	activeTimeout = 1 * time.Second
	restartTimeout = 1 * time.Second
	t.Cleanup(func() { activeTimeout, restartTimeout = oldActive, oldRestart })

	start := time.Now()
	if got := systemctlActive("user"); got != false {
		t.Fatalf("systemctlActive = %v on a wedged bus, want false", got)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("systemctlActive took %v, want < 5s (bounded by activeTimeout)", elapsed)
	}
}

// TestRunRestartBoundedByTimeout proves the restart command is also bounded: a
// fake `systemctl` that sleeps past the timeout must cause runRestart to
// return an error promptly, not hang.
func TestRunRestartBoundedByTimeout(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "systemctl")
	script := "#!/bin/sh\nsleep 30\n"
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathSeparator)+os.Getenv("PATH"))

	oldActive, oldRestart := activeTimeout, restartTimeout
	activeTimeout = 1 * time.Second
	restartTimeout = 1 * time.Second
	t.Cleanup(func() { activeTimeout, restartTimeout = oldActive, oldRestart })

	start := time.Now()
	err := runRestart("user")
	if err == nil {
		t.Fatalf("runRestart = nil on a wedged bus, want an error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("runRestart took %v, want < 5s (bounded by restartTimeout)", elapsed)
	}
}

// TestWaitHealthyTimesOutOnDeadPort pins the negative half: a port with
// nothing listening must time out (fast, via the shrunk healthzTimeout) and
// return not-ok. The port is deterministic — it's an httptest server's port
// right after Close(), so connections are refused for the whole poll window.
func TestWaitHealthyTimesOutOnDeadPort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	u, _ := url.Parse(srv.URL)
	port := u.Host
	srv.Close() // free the port so subsequent connections are refused

	t.Setenv("PULSEMON_ADDR", port)
	oldTimeout := healthzTimeout
	healthzTimeout = 1 * time.Second
	t.Cleanup(func() { healthzTimeout = oldTimeout })

	start := time.Now()
	ok, detail := waitHealthy()
	if ok {
		t.Fatalf("waitHealthy = true on a closed port, want false: %s", detail)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("waitHealthy took %v, want < 5s (bounded by healthzTimeout)", elapsed)
	}
}
