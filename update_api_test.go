package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// updateHarness saves and restores every seam the endpoint touches and
// records the restart — the same discipline as restartHarness in
// update_restart_test.go: a unit test must NEVER run systemctl against the
// host it runs on, and the install path must swap a fake binary in a temp
// dir, never the cached test binary.
//
// container selects the Docker-image path (isContainerInstall); the fake
// on-disk binary lives at exePath and starts as "old binary".
type updateHarness struct {
	detectBus  string
	restarted  []string
	restartErr error
	exePath    string
}

func setupUpdateHarness(t *testing.T, container bool) *updateHarness {
	t.Helper()
	h := &updateHarness{}
	dir := t.TempDir()
	h.exePath = filepath.Join(dir, "pulsemon")
	if err := os.WriteFile(h.exePath, []byte("old binary"), 0755); err != nil {
		t.Fatal(err)
	}

	oldContainer := isContainerInstall
	oldExe := runningExecutable
	oldDetect := detectRestart
	oldPerform := performRestart
	t.Cleanup(func() {
		isContainerInstall = oldContainer
		runningExecutable = oldExe
		detectRestart = oldDetect
		performRestart = oldPerform
	})
	isContainerInstall = func() bool { return container }
	runningExecutable = func() (string, error) { return h.exePath, nil }
	detectRestart = func() string { return h.detectBus }
	performRestart = func(bus string) error {
		h.restarted = append(h.restarted, bus)
		return h.restartErr
	}
	return h
}

// updateServer builds a Server with authentication ENABLED (one account):
// the required shape for the update endpoint (it is 403 while auth is
// disabled — TestUpdateRefusedWhenAuthDisabled).
func updateServer(t *testing.T) *Server {
	t.Helper()
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	if err := srv.auth.AddUser("admin", "update-test-password-1"); err != nil {
		t.Fatal(err)
	}
	return srv
}

func postUpdate(t *testing.T, srv *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest("POST", "/api/update", nil)
	} else {
		req = httptest.NewRequest("POST", "/api/update", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	srv.handleUpdate(rec, req)
	return rec
}

func decodeUpdate(t *testing.T, rec *httptest.ResponseRecorder) updateResponse {
	t.Helper()
	var res updateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("response is not updateResponse JSON: %v: %s", err, rec.Body.String())
	}
	return res
}

// TestUpdateContainerMode pins the Docker contract: the endpoint never
// downloads or installs in a container — it answers with the operator
// command (generic default, PULSEMON_UPDATE_CMD override).
func TestUpdateContainerMode(t *testing.T) {
	srv := updateServer(t)

	t.Run("default command", func(t *testing.T) {
		_ = setupUpdateHarness(t, true)
		rec := postUpdate(t, srv, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d, want 200: %s", rec.Code, rec.Body.String())
		}
		res := decodeUpdate(t, rec)
		if res.Status != "container" || res.Command != containerUpdateCommand {
			t.Fatalf("res = %+v, want container + %q", res, containerUpdateCommand)
		}
	})
	t.Run("env override", func(t *testing.T) {
		_ = setupUpdateHarness(t, true)
		t.Setenv("PULSEMON_UPDATE_CMD", "make update && docker compose up -d")
		rec := postUpdate(t, srv, "")
		res := decodeUpdate(t, rec)
		if res.Status != "container" || res.Command != "make update && docker compose up -d" {
			t.Fatalf("res = %+v, want container + overridden command", res)
		}
	})
}

// TestUpdateUpToDate pins the ordering rule: a release not newer than the
// running version is a no-op (200, nothing installed, no restart).
func TestUpdateUpToDate(t *testing.T) {
	srv := updateServer(t)
	h := setupUpdateHarness(t, false)
	base, _ := serveRelease(t, "v1.0.0", "")
	oldBase, oldVer := releaseBase, Version
	releaseBase, Version = base, "v9.9.9"
	t.Cleanup(func() { releaseBase, Version = oldBase, oldVer })

	rec := postUpdate(t, srv, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if res := decodeUpdate(t, rec); res.Status != "up-to-date" {
		t.Fatalf("res = %+v, want up-to-date", res)
	}
	if got, _ := os.ReadFile(h.exePath); string(got) != "old binary" {
		t.Fatalf("binary was swapped on an up-to-date check: %q", got)
	}
	if len(h.restarted) != 0 {
		t.Fatalf("restarted = %v, want none", h.restarted)
	}
}

// TestUpdateMissingPlatformAsset pins the 409 path: a release without an
// asset for this platform installs nothing.
func TestUpdateMissingPlatformAsset(t *testing.T) {
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"tag_name":"v9.9.9","assets":[{"name":"pulsemon-sunos-amd64","browser_download_url":"http://127.0.0.1:1/bin"}]}`))
	}))
	defer gh.Close()
	oldBase, oldVer := releaseBase, Version
	releaseBase, Version = gh.URL+"/releases", "v0.0.1"
	t.Cleanup(func() { releaseBase, Version = oldBase, oldVer })

	srv := updateServer(t)
	h := setupUpdateHarness(t, false)

	rec := postUpdate(t, srv, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("code = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if got, _ := os.ReadFile(h.exePath); string(got) != "old binary" {
		t.Fatalf("binary was swapped on a missing-asset refusal: %q", got)
	}
}

// TestUpdateHappyPathRestart is the full native path: verified download,
// binary swap, 202 "restarting" with the service restart issued exactly
// once. The 202 must be written BEFORE performRestart (the process dies
// when systemd restarts it), so the recorder must carry the full response.
func TestUpdateHappyPathRestart(t *testing.T) {
	srv := updateServer(t)
	h := setupUpdateHarness(t, false)
	h.detectBus = "user"
	base, _ := serveReleaseVerified(t, "v9.9.9")
	oldBase, oldVer := releaseBase, Version
	releaseBase, Version = base, "v0.0.1"
	t.Cleanup(func() { releaseBase, Version = oldBase, oldVer })

	rec := postUpdate(t, srv, "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("code = %d, want 202: %s", rec.Code, rec.Body.String())
	}
	res := decodeUpdate(t, rec)
	if res.Status != "restarting" || res.Target != "v9.9.9" || res.Bus != "user" {
		t.Fatalf("res = %+v, want restarting/v9.9.9/user", res)
	}
	if len(h.restarted) != 1 || h.restarted[0] != "user" {
		t.Fatalf("restarted = %v, want [user]", h.restarted)
	}
	got, err := os.ReadFile(h.exePath)
	if err != nil || !bytes.Contains(got, []byte("fake pulsemon binary payload")) {
		t.Fatalf("binary not swapped: %v %q", err, got)
	}
}

// TestUpdateInstalledNoService pins the CLI parity rule: with no live
// systemd service the binary is installed but the endpoint must NOT
// auto-restart — it reports "installed" with a manual hint.
func TestUpdateInstalledNoService(t *testing.T) {
	srv := updateServer(t)
	h := setupUpdateHarness(t, false) // detectBus = ""
	base, _ := serveReleaseVerified(t, "v9.9.9")
	oldBase, oldVer := releaseBase, Version
	releaseBase, Version = base, "v0.0.1"
	t.Cleanup(func() { releaseBase, Version = oldBase, oldVer })

	rec := postUpdate(t, srv, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	res := decodeUpdate(t, rec)
	if res.Status != "installed" || res.Hint == "" {
		t.Fatalf("res = %+v, want installed + hint", res)
	}
	if len(h.restarted) != 0 {
		t.Fatalf("restarted = %v, want none (no live service detected)", h.restarted)
	}
	got, _ := os.ReadFile(h.exePath)
	if !bytes.Contains(got, []byte("fake pulsemon binary payload")) {
		t.Fatalf("binary not swapped: %q", got)
	}
}

// TestUpdateSHARefused is the endpoint twin of TestRunUpdateSHARefusedNoLeak:
// a download that verifies against the wrong SHA-256 is refused (502) and
// nothing is installed or restarted.
func TestUpdateSHARefused(t *testing.T) {
	srv := updateServer(t)
	h := setupUpdateHarness(t, false)
	h.detectBus = "user"
	base, _ := serveRelease(t, "v9.9.9", "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	oldBase, oldVer := releaseBase, Version
	releaseBase, Version = base, "v0.0.1"
	t.Cleanup(func() { releaseBase, Version = oldBase, oldVer })

	rec := postUpdate(t, srv, "")
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502: %s", rec.Code, rec.Body.String())
	}
	if got, _ := os.ReadFile(h.exePath); string(got) != "old binary" {
		t.Fatalf("binary was swapped on a sha refusal: %q", got)
	}
	if len(h.restarted) != 0 {
		t.Fatalf("restarted = %v, want none", h.restarted)
	}
}

// TestUpdateBadVersion pins the pre-validation: a malformed version pin is a
// 400 before any network call (no path traversal into the releases URL).
func TestUpdateBadVersion(t *testing.T) {
	srv := updateServer(t)
	rec := postUpdate(t, srv, `{"version":"../evil"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	rec = postUpdate(t, srv, `{"version":"v bad tag"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

// TestUpdateMethodNotAllowed pins the 405 on non-POST.
func TestUpdateMethodNotAllowed(t *testing.T) {
	srv := updateServer(t)
	rec := httptest.NewRecorder()
	srv.handleUpdate(rec, httptest.NewRequest("GET", "/api/update", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code = %d, want 405", rec.Code)
	}
}

// TestUpdateRefusedWhenAuthDisabled pins the 2026-10-24 review (M1) fix: on
// an install where the operator disabled authentication (bootstrapped, zero
// users), POST /api/update must be 403. The self-update path downloads a
// binary, overwrites the running one, and restarts the service, so it is not
// part of the "auth off = fully open" surface: any LAN host could otherwise
// trigger a restart loop, and a compromised upstream release would
// auto-install on every auth-off box. Setup mode (never bootstrapped) is
// already 403 at the auth gate; the CLI (`pulsemon update`) remains the
// operator path in both states.
func TestUpdateRefusedWhenAuthDisabled(t *testing.T) {
	db := newTestDB(t)
	// Bootstrapped with zero users = "auth disabled by the operator"
	// (distinct from fresh-install setup mode, which the gate blocks).
	if err := db.SetSetting("auth_bootstrapped", "1"); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(db, NewProbeWorker(db))
	rec := postUpdate(t, srv, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403: %s", rec.Code, rec.Body.String())
	}
}

// TestUpdateAllowedWhenAuthDisabledAndOptIn pins the opt-in that lifts the
// M1 403: on an operator-disabled (auth-off) install, setting
// allow_unauth_update re-opens POST /api/update without an account — for
// trusted-LAN boxes that deliberately run without authentication. The gate
// is passed (the request reaches the version check and answers up-to-date)
// rather than the M1 403, and nothing is installed.
func TestUpdateAllowedWhenAuthDisabledAndOptIn(t *testing.T) {
	db := newTestDB(t)
	if err := db.SetSetting("auth_bootstrapped", "1"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting("allow_unauth_update", "1"); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(db, NewProbeWorker(db))
	h := setupUpdateHarness(t, false) // native install → reaches the auth gate
	base, _ := serveRelease(t, "v1.0.0", "")
	oldBase, oldVer := releaseBase, Version
	releaseBase, Version = base, "v9.9.9"
	t.Cleanup(func() { releaseBase, Version = oldBase, oldVer })

	rec := postUpdate(t, srv, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 (gate passed, up-to-date): %s", rec.Code, rec.Body.String())
	}
	if res := decodeUpdate(t, rec); res.Status != "up-to-date" {
		t.Fatalf("res = %+v, want up-to-date", res)
	}
	if got, _ := os.ReadFile(h.exePath); string(got) != "old binary" {
		t.Fatalf("binary was swapped on an up-to-date check: %q", got)
	}
}
