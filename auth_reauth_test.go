package main

// L1 pins (external review, 2026-11-23): destructive account operations
// (add user, delete user, disable auth) require the SESSION'S OWN current
// password — a stolen session cookie must not win account-level
// decisions. Each pin here sabotages the fix in the way the review found:
// drop the reauth call (or the client's current_password field) and the
// matching pin fails.
//
// The happy paths (correct current → 200) are also pinned here, once per
// endpoint, so the gate can never drift into "always reject".

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"pulsemon/internal/store"
)

// reauthAdminServer bootstraps a fresh install (setup mode — no session
// exists, so no current_password is sent) and logs the admin in. Returns
// the session client and the test server.
func reauthAdminServer(t *testing.T) (*http.Client, *httptest.Server) {
	t.Helper()
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	t.Cleanup(httpSrv.Close)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	post := func(path, body string) (int, string) {
		t.Helper()
		resp, err := client.Post(httpSrv.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := post("/api/auth/users", `{"username":"admin","password": "secretpw"}`); code != 200 {
		t.Fatalf("bootstrap: got %d (%s), want 200", code, body)
	}
	if code, body := post("/api/auth/login", `{"username":"admin","password": "secretpw"}`); code != 200 {
		t.Fatalf("login: got %d (%s), want 200", code, body)
	}
	return client, httpSrv
}

func reauthUsernames(t *testing.T, client *http.Client, httpSrv *httptest.Server) []string {
	t.Helper()
	resp, err := client.Get(httpSrv.URL + "/api/auth/users")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var users []store.AuthUser
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		t.Fatalf("decode users: %v", err)
	}
	names := make([]string, 0, len(users))
	for _, u := range users {
		names = append(names, u.Username)
	}
	return names
}

// TestReauthMissingCurrentPassword: an empty/missing current_password is a
// 400 on every destructive endpoint (no KDF ran — the uncharged category).
func TestReauthMissingCurrentPassword(t *testing.T) {
	client, httpSrv := reauthAdminServer(t)

	// add user
	resp, err := client.Post(httpSrv.URL+"/api/auth/users", "application/json",
		strings.NewReader(`{"username":"h1","password": "helperpw1"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("add without current: got %d, want 400", resp.StatusCode)
	}

	// delete user
	req, _ := http.NewRequest(http.MethodDelete, httpSrv.URL+"/api/auth/users/ghost",
		strings.NewReader(`{}`))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("delete without current: got %d, want 400", resp.StatusCode)
	}

	// disable auth
	resp, err = client.Post(httpSrv.URL+"/api/auth/disable", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("disable without current: got %d, want 400", resp.StatusCode)
	}
}

// TestReauthWrongCurrentPassword: a wrong current_password is a 403 and
// MUST NOT mutate state — this is the stolen-cookie case the review found
// (a valid session, wrong password: the endpoint has to stand down).
func TestReauthWrongCurrentPassword(t *testing.T) {
	client, httpSrv := reauthAdminServer(t)

	// add: h1 must NOT be created
	resp, err := client.Post(httpSrv.URL+"/api/auth/users", "application/json",
		strings.NewReader(`{"username":"h1","password": "helperpw1","current_password": "wrongpass9"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(b), "current password incorrect") {
		t.Fatalf("add with wrong current: got %d (%s), want 403 'current password incorrect'", resp.StatusCode, b)
	}

	// a real second user so the delete pins have a non-last target
	resp, err = client.Post(httpSrv.URL+"/api/auth/users", "application/json",
		strings.NewReader(`{"username":"h1","password": "helperpw1","current_password": "secretpw"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("add h1 with correct current: got %d, want 200", resp.StatusCode)
	}

	// delete: h1 must survive
	req, _ := http.NewRequest(http.MethodDelete, httpSrv.URL+"/api/auth/users/h1",
		strings.NewReader(`{"current_password": "wrongpass9"}`))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("delete with wrong current: got %d (%s), want 403", resp.StatusCode, b)
	}

	// disable: auth must stay enabled
	resp, err = client.Post(httpSrv.URL+"/api/auth/disable", "application/json",
		strings.NewReader(`{"current_password": "wrongpass9"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("disable with wrong current: got %d (%s), want 403", resp.StatusCode, b)
	}

	// State unchanged: both users present, auth enabled.
	for _, want := range []string{"admin", "h1"} {
		found := false
		for _, n := range reauthUsernames(t, client, httpSrv) {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("state mutated by a rejected reauth: %s missing from roster", want)
		}
	}
	stResp, err := client.Get(httpSrv.URL + "/api/auth/status")
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(stResp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	stResp.Body.Close()
	if !st.Enabled {
		t.Fatal("auth disabled by a rejected reauth, want still enabled")
	}
}

// TestReauthLastUserGuardOrdering: with a single user, a self-delete with
// the CORRECT current password passes the reauth and then hits the
// last-user guard — 400, not 403. Pins the ordering (reauth → guard), so
// the guard can never be masked by (or mask) the credential check.
func TestReauthLastUserGuardOrdering(t *testing.T) {
	client, httpSrv := reauthAdminServer(t)
	req, _ := http.NewRequest(http.MethodDelete, httpSrv.URL+"/api/auth/users/admin",
		strings.NewReader(`{"current_password": "secretpw"}`))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), "cannot remove the last user") {
		t.Fatalf("self-delete last user: got %d (%s), want 400 last-user guard", resp.StatusCode, b)
	}
}

// TestReauthThrottle: spraying a wrong current_password from one IP burns
// the SHARED per-IP login budget — loginFailMax failures then 429, exactly
// like a login spray (the gate and login must stay in one bucket, or a
// session holder gets an unlimited reauth-guessing channel).
func TestReauthThrottle(t *testing.T) {
	client, httpSrv := reauthAdminServer(t)
	// One real second user so every attempt targets the delete endpoint.
	resp, err := client.Post(httpSrv.URL+"/api/auth/users", "application/json",
		strings.NewReader(`{"username":"h1","password": "helperpw1","current_password": "secretpw"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("add h1: got %d, want 200", resp.StatusCode)
	}

	var last int
	var lastBody string
	for i := 0; i < loginFailMax; i++ {
		req, _ := http.NewRequest(http.MethodDelete, httpSrv.URL+"/api/auth/users/h1",
			strings.NewReader(`{"current_password": "wrongpass9"}`))
		resp, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		last, lastBody = resp.StatusCode, string(b)
		if last != http.StatusForbidden {
			t.Fatalf("attempt %d: got %d (%s), want 403", i+1, last, lastBody)
		}
	}
	// The next attempt is locked out (per-IP, shared with login).
	req, _ := http.NewRequest(http.MethodDelete, httpSrv.URL+"/api/auth/users/h1",
		strings.NewReader(`{"current_password": "wrongpass9"}`))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("attempt %d: got %d (%s), want 429 after %d failures",
			loginFailMax+1, resp.StatusCode, b, loginFailMax)
	}
	// h1 survived the whole spray.
	for _, n := range reauthUsernames(t, client, httpSrv) {
		if n == "h1" {
			return
		}
	}
	t.Fatal("h1 deleted by a throttle spray, want it to survive")
}

// TestReauthBootstrapUnaffected: the fresh-install bootstrap has no
// session by definition, so it must NOT require current_password — the
// gate must stay open for the first account (a regression here bricks
// first-time setup), while the very NEXT add (now authenticated) must
// require it.
func TestReauthBootstrapUnaffected(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	t.Cleanup(httpSrv.Close)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// Bootstrap WITHOUT current_password: 200.
	resp, err := client.Post(httpSrv.URL+"/api/auth/users", "application/json",
		strings.NewReader(`{"username":"admin","password": "secretpw"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("bootstrap without current: got %d, want 200 (setup mode has no session)", resp.StatusCode)
	}

	// Login, then the NEXT add without current_password: 400.
	resp, err = client.Post(httpSrv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password": "secretpw"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("login: got %d, want 200", resp.StatusCode)
	}
	resp, err = client.Post(httpSrv.URL+"/api/auth/users", "application/json",
		strings.NewReader(`{"username":"h1","password": "helperpw1"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("authenticated add without current: got %d, want 400", resp.StatusCode)
	}
}
