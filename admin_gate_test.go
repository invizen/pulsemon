package main

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
)

// requestStatus issues a (optionally JSON) request and returns the status
// code — the shared helper for the admin-gate route table below.
func requestStatus(t *testing.T, client *http.Client, method, url, body string) int {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestNonAdminCannotReachAdminSurface is the repro for the 2026-10-23
// external review: IsAdmin was checked only on the user-management
// handlers (add/remove user, disable auth), so a regular (non-admin)
// session could still do every other mutating admin operation —
// self-update (binary swap + restart), swap the TLS cert/key, repoint
// webhooks / set SMTP credentials, fire test alerts, and wipe all
// history. Every route on the mutating admin surface must be a 403 for
// a non-admin session, and the same routes must reach the handler for
// an admin.
func TestNonAdminCannotReachAdminSurface(t *testing.T) {
	db, httpSrv := adminFlagServer(t)

	jar, _ := cookiejar.New(nil)
	admin := &http.Client{Jar: jar}
	bootstrapAdmin(t, admin, httpSrv.URL)
	if code := postJSONStatus(t, admin, httpSrv.URL+"/api/auth/login",
		`{"username":"admin","password":"secretpw"}`); code != 200 {
		t.Fatalf("admin login: %d", code)
	}
	if code := postJSONStatus(t, admin, httpSrv.URL+"/api/auth/users",
		`{"username":"helper","password":"helperpw1"}`); code != 200 {
		t.Fatalf("admin add helper: %d", code)
	}

	// The attacker: a legitimately logged-in regular account.
	hjar, _ := cookiejar.New(nil)
	helper := &http.Client{Jar: hjar}
	if code := postJSONStatus(t, helper, httpSrv.URL+"/api/auth/login",
		`{"username":"helper","password":"helperpw1"}`); code != 200 {
		t.Fatalf("helper login: %d", code)
	}

	// The mutating admin surface: every one of these is a 403 for the
	// non-admin session (and must NOT reach the handler — the update
	// attempt in particular must not acquire the update lock).
	cases := []struct {
		method, path, body string
	}{
		{http.MethodPost, "/api/update", ""},
		{http.MethodPut, "/api/settings", "{}"},
		{http.MethodPost, "/api/settings/test", `{"kind":"discord"}`},
		{http.MethodPost, "/api/settings/tls", `{}`},
		{http.MethodDelete, "/api/settings/tls", ""},
		{http.MethodDelete, "/api/history", ""},
	}
	for _, c := range cases {
		code := requestStatus(t, helper, c.method, httpSrv.URL+c.path, c.body)
		if code != http.StatusForbidden {
			t.Errorf("%s %s (non-admin): got %d, want 403", c.method, c.path, code)
		}
	}

	// Admin positive controls: the same routes reach the handler.
	// PUT settings and DELETE history are hermetic 200s; the update
	// endpoint is pinned to the container path (no download, no
	// install); the TLS pair is an empty body (400, missing cert/key);
	// the TLS delete has no dashboard cert to remove (409).
	if code := requestStatus(t, admin, http.MethodPut, httpSrv.URL+"/api/settings", "{}"); code != http.StatusOK {
		t.Errorf("PUT /api/settings (admin): got %d, want 200", code)
	}
	if code := requestStatus(t, admin, http.MethodDelete, httpSrv.URL+"/api/history", ""); code != http.StatusOK {
		t.Errorf("DELETE /api/history (admin): got %d, want 200", code)
	}
	_ = setupUpdateHarness(t, true)
	if code := requestStatus(t, admin, http.MethodPost, httpSrv.URL+"/api/update", ""); code != http.StatusOK {
		t.Errorf("POST /api/update (admin): got %d, want 200 (container)", code)
	}
	if code := requestStatus(t, admin, http.MethodPost, httpSrv.URL+"/api/settings/tls", `{}`); code != http.StatusBadRequest {
		t.Errorf("POST /api/settings/tls (admin): got %d, want 400 (missing cert/key)", code)
	}
	if code := requestStatus(t, admin, http.MethodDelete, httpSrv.URL+"/api/settings/tls", ""); code != http.StatusConflict {
		t.Errorf("DELETE /api/settings/tls (admin): got %d, want 409 (no dashboard cert)", code)
	}

	// State must be exactly as before the non-admin attempts: both
	// accounts exist, auth still enabled.
	if _, ok := userByName(t, db, "admin"); !ok {
		t.Error("admin account missing after non-admin admin-surface attempts")
	}
	if _, ok := userByName(t, db, "helper"); !ok {
		t.Error("helper account missing after non-admin admin-surface attempts")
	}
	bare := &http.Client{}
	resp, err := bare.Get(httpSrv.URL + "/api/auth/status")
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Enabled bool `json:"enabled"`
	}
	json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if !st.Enabled {
		t.Error("auth was disabled by a non-admin")
	}
}
