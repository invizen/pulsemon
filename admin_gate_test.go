package main

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

	// The mutating admin surface — plus the settings READ, whose
	// payload carries operator PII and infrastructure metadata
	// (review 2026-10-30): every one of these is a 403 for the
	// non-admin session (and must NOT reach the handler — the update
	// attempt in particular must not acquire the update lock).
	cases := []struct {
		method, path, body string
	}{
		{http.MethodPost, "/api/update", ""},
		{http.MethodGet, "/api/settings", ""},
		{http.MethodPut, "/api/settings", "{}"},
		{http.MethodPost, "/api/settings/test", `{"kind":"discord"}`},
		{http.MethodPost, "/api/settings/tls", `{}`},
		{http.MethodDelete, "/api/settings/tls", ""},
		{http.MethodDelete, "/api/history", ""},
		{http.MethodDelete, "/api/events", ""},
	}
	for _, c := range cases {
		code := requestStatus(t, helper, c.method, httpSrv.URL+c.path, c.body)
		if code != http.StatusForbidden {
			t.Errorf("%s %s (non-admin): got %d, want 403", c.method, c.path, code)
		}
	}

	// Pin the intentional INVERSE of the table above: GET
	// /api/update-check stays open to EVERY session (re-adjudicated
	// 2026-10-30 — see DECISIONS.md → update-check-refresh-throttle).
	// Read-only, non-secret (the versions are rendered in the header
	// pill for every user), fixed upstream URL (no SSRF), and
	// ?refresh=1 is throttled to one outbound fetch per 60s globally.
	// The admin gate belongs on POST /api/update (code execution +
	// restart), which the table covers. This assertion fails if a
	// future change wraps the route in requireAdmin. Hermetic: fake
	// GitHub + reset cache globals.
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"tag_name":"v9.9.9","html_url":"https://github.com/invizen/pulsemon/releases/tag/v9.9.9"}`))
	}))
	defer gh.Close()
	oldBase := releaseBase
	releaseBase = gh.URL + "/releases"
	oldUCache, oldUAt, oldUAttempt, oldUFailed := updateCheckCached, updateCheckAt, updateCheckAttemptAt, updateCheckFailed
	t.Cleanup(func() {
		releaseBase = oldBase
		updateCheckCached, updateCheckAt, updateCheckAttemptAt, updateCheckFailed = oldUCache, oldUAt, oldUAttempt, oldUFailed
	})
	updateCheckCached, updateCheckFailed = nil, false
	updateCheckAt, updateCheckAttemptAt = time.Time{}, time.Time{}
	if code := requestStatus(t, helper, http.MethodGet, httpSrv.URL+"/api/update-check", ""); code != http.StatusOK {
		t.Errorf("GET /api/update-check (non-admin): got %d, want 200 (intentionally open — DECISIONS.md → update-check-refresh-throttle)", code)
	}

	// Admin positive controls: the same routes reach the handler.
	// GET+PUT settings and DELETE history are hermetic 200s; the
	// update endpoint is pinned to the container path (no download,
	// no install); the TLS pair is an empty body (400, missing
	// cert/key); the TLS delete has no dashboard cert to remove (409).
	if code := requestStatus(t, admin, http.MethodGet, httpSrv.URL+"/api/settings", ""); code != http.StatusOK {
		t.Errorf("GET /api/settings (admin): got %d, want 200", code)
	}
	if code := requestStatus(t, admin, http.MethodPut, httpSrv.URL+"/api/settings", "{}"); code != http.StatusOK {
		t.Errorf("PUT /api/settings (admin): got %d, want 200", code)
	}
	if code := requestStatus(t, admin, http.MethodDelete, httpSrv.URL+"/api/history", ""); code != http.StatusOK {
		t.Errorf("DELETE /api/history (admin): got %d, want 200", code)
	}
	if code := requestStatus(t, admin, http.MethodDelete, httpSrv.URL+"/api/events", ""); code != http.StatusOK {
		t.Errorf("DELETE /api/events (admin): got %d, want 200", code)
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
	jsonDecode(t, resp, &st)
	resp.Body.Close()
	if !st.Enabled {
		t.Error("auth was disabled by a non-admin")
	}
}

// TestNonAdminCannotMutateSensors is the repro for the 2026-10-28
// external review: the per-sensor mutation routes (create, edit,
// delete, clone, per-sensor history wipe) were gated by requireAuth
// only, so a regular (lower-trust) account could create/edit/delete
// sensors and wipe per-sensor events rows — the same audit log the
// requireAdmin-gated DELETE /api/events exists to protect. Non-admins
// are viewers + manual-pulse operators: reads and Pulse Now stay open
// to every session, and every mutation is a 403 that never reaches
// the handler.
func TestNonAdminCannotMutateSensors(t *testing.T) {
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

	// Hermetic ping: the Pulse Now positive control must not depend on
	// real ICMP in the test environment (the probeTarget stub idiom
	// from ping_now_test.go).
	origProbe := probeTarget
	probeTarget = func(ctx context.Context, probeType, target string, timeout time.Duration) probeOutcome {
		return probeOutcome{rttMs: 1, ip: "127.0.0.1"}
	}
	defer func() { probeTarget = origProbe }()

	// Admin creates the sensor the non-admin surface below targets.
	req, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/api/sensors",
		strings.NewReader(`{"name":"gate-sensor","target":"192.0.2.10"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := admin.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var created map[string]interface{}
	jsonDecode(t, resp, &created)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("admin POST /api/sensors: %d, want 201", resp.StatusCode)
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatal("no sensor id in create response")
	}

	// Non-admin mutations: every one is a 403 and must NOT reach the
	// handler (no create, no edit — including pause/resume and target
	// repoint — no delete, no clone, no history wipe).
	cases := []struct {
		method, path, body string
	}{
		{http.MethodPost, "/api/sensors", `{"name":"sneaky","target":"192.0.2.99"}`},
		{http.MethodPatch, "/api/sensors/" + id, `{"name":"hijacked"}`},
		{http.MethodPatch, "/api/sensors/" + id, `{"state":"paused"}`},
		{http.MethodPatch, "/api/sensors/" + id, `{"target":"10.0.0.5"}`},
		{http.MethodDelete, "/api/sensors/" + id, ""},
		{http.MethodPost, "/api/sensors/" + id + "/clone", ""},
		{http.MethodDelete, "/api/sensors/" + id + "/history", ""},
	}
	for _, c := range cases {
		code := requestStatus(t, helper, c.method, httpSrv.URL+c.path, c.body)
		if code != http.StatusForbidden {
			t.Errorf("%s %s (non-admin): got %d, want 403", c.method, c.path, code)
		}
	}

	// Non-admin reads + Pulse Now stay open to every session.
	if code := requestStatus(t, helper, http.MethodGet, httpSrv.URL+"/api/sensors", ""); code != http.StatusOK {
		t.Errorf("GET /api/sensors (non-admin): got %d, want 200", code)
	}
	if code := requestStatus(t, helper, http.MethodGet, httpSrv.URL+"/api/sensors/"+id, ""); code != http.StatusOK {
		t.Errorf("GET /api/sensors/{id} (non-admin): got %d, want 200", code)
	}
	if code := requestStatus(t, helper, http.MethodGet, httpSrv.URL+"/api/sensors/"+id+"/history", ""); code != http.StatusOK {
		t.Errorf("GET /api/sensors/{id}/history (non-admin): got %d, want 200", code)
	}
	if code := requestStatus(t, helper, http.MethodPost, httpSrv.URL+"/api/sensors/"+id+"/ping", ""); code != http.StatusOK {
		t.Errorf("POST /api/sensors/{id}/ping (non-admin): got %d, want 200 (open probe)", code)
	}

	// State must be exactly as before the non-admin attempts: the
	// sensor still exists, is unedited (name intact, original target,
	// and still in its created-paused state — new sensors start
	// paused, api.go), and no "sneaky" or clone rows were created.
	var name, state, target string
	if err := db.QueryRow(`SELECT name, state, target FROM sensors WHERE id = ?`, id).Scan(&name, &state, &target); err != nil {
		t.Fatalf("sensor gone after non-admin attempts: %v", err)
	}
	if name != "gate-sensor" || state != "paused" || target != "192.0.2.10" {
		t.Errorf("sensor mutated by non-admin: name=%q state=%q target=%q", name, state, target)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensors`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("sensor count = %d, want 1 (create/clone leaked)", n)
	}

	// Admin positive controls: the same routes reach the handler.
	if code := requestStatus(t, admin, http.MethodPatch, httpSrv.URL+"/api/sensors/"+id, `{"spike_mult": 6}`); code != http.StatusOK {
		t.Errorf("PATCH /api/sensors/{id} (admin): got %d, want 200", code)
	}
	if code := requestStatus(t, admin, http.MethodPost, httpSrv.URL+"/api/sensors/"+id+"/clone", ""); code != http.StatusCreated {
		t.Errorf("POST /api/sensors/{id}/clone (admin): got %d, want 201", code)
	}
	if code := requestStatus(t, admin, http.MethodDelete, httpSrv.URL+"/api/sensors/"+id+"/history", ""); code != http.StatusOK {
		t.Errorf("DELETE /api/sensors/{id}/history (admin): got %d, want 200", code)
	}
}
