package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// g3 guard: no handler may answer a 500 with the raw error text (driver SQL,
// filesystem paths). respondInternal logs the detail and returns a generic body.
func TestFix_g3_NoRawErrorTextInInternalErrors(t *testing.T) {
	re := regexp.MustCompile(`StatusInternalServerError,\s*("[^"]*"\s*\+\s*)?err\.Error\(\)`)
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if re.MatchString(line) {
				t.Errorf("%s:%d returns err.Error() in a 500: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// The graph query failing must give the generic body, not sqlite text.
func TestFix_g3_GraphQueryErrorIsGeneric(t *testing.T) {
	d := newTestDB(t)
	mux := NewServer(d, NewProbeWorker(d)).Mux()
	if _, err := d.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('g', 'g', '10.0.0.1', 60, 1000, 25, 3, 3, 'paused', 'up', 'x')`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`DROP TABLE probes`); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/sensors/g/graph?range=1h", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500 (%s)", rr.Code, rr.Body.String())
	}
	if strings.Contains(strings.ToLower(rr.Body.String()), "no such table") || !strings.Contains(rr.Body.String(), "internal error") {
		t.Fatalf("body leaks driver text or is not generic: %s", rr.Body.String())
	}
}

// m9: the system locations beat $PATH, so a PATH entry cannot shadow systemctl.
// (resolveSystemctl, not the stubbable systemctlPath var.)
func TestFix_m9_SystemctlPathPrefersSystemLocations(t *testing.T) {
	fake := t.TempDir()
	if err := os.WriteFile(filepath.Join(fake, "systemctl"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fake+string(os.PathListSeparator)+os.Getenv("PATH"))
	got := resolveSystemctl()
	for _, p := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			if got != p {
				t.Fatalf("systemctlPath() = %q, want the system binary %q even with a shadowing PATH entry", got, p)
			}
			return
		}
	}
	t.Skip("no systemctl in the fixed system locations on this host")
}

// A Docker install only ever gets the "run docker compose" hint: nothing is
// fetched or swapped, so it is returned whether or not auth is enabled.
func TestFix_UpdateContainerHintWorksWithAuthOff(t *testing.T) {
	d := newTestDB(t)
	srv := NewServer(d, NewProbeWorker(d)) // no users: auth disabled
	hits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer ts.Close()
	origBase, origC := releaseBase, isContainerInstall
	releaseBase, isContainerInstall = ts.URL, func() bool { return true }
	defer func() { releaseBase, isContainerInstall = origBase, origC }()

	rr := httptest.NewRecorder()
	srv.handleUpdate(rr, httptest.NewRequest(http.MethodPost, "/api/update", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"status":"container"`) || !strings.Contains(rr.Body.String(), "docker compose") {
		t.Fatalf("container install, auth off => %d %s, want 200 container hint", rr.Code, rr.Body.String())
	}
	if hits != 0 {
		t.Errorf("container hint made %d network call(s), want 0", hits)
	}
}
