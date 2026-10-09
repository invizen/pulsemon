package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// lastTestDBPath records the most recent newTestDB path so sibling-handle
// tests (out-of-band writes, like the host CLI) can reopen the same store.
var lastTestDBPath string

func newTestDB(t *testing.T) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.db")
	lastTestDBPath = path
	db, err := NewDB(path)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return db
}

// TestAuthUserValidation pins the account rules: username shape, minimum
// password length, case-insensitive uniqueness, and the "first user
// enables auth" transition.
func TestAuthUserValidation(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	if a.Enabled() {
		t.Fatal("fresh DB must have auth disabled")
	}
	cases := []struct {
		user, pass string
		ok         bool
	}{
		{"", "secretpw", false},
		{"9bad", "secretpw", false},                  // must start with a letter
		{"bad name", "secretpw", false},              // no spaces
		{"bad/name", "secretpw", false},              // no slashes
		{strings.Repeat("x", 33), "secretpw", false}, // over 32
		{"ok", "short", false},                       // under 8 chars
		{"operator", "secretpw", true},
	}
	for i, c := range cases {
		err := a.AddUser(c.user, c.pass)
		if c.ok && err != nil {
			t.Fatalf("case %d (%q): AddUser: %v", i, c.user, err)
		}
		if !c.ok && err == nil {
			t.Fatalf("case %d (%q): expected rejection", i, c.user)
		}
	}
	if !a.Enabled() {
		t.Fatal("auth must be enabled after the first user is added")
	}
	// Case-insensitive uniqueness: OPERATOR and operator are one account.
	if err := a.AddUser("OPERATOR", "secretpw"); err == nil {
		t.Fatal("duplicate user (case variant) must be rejected")
	}
	n, err := db.UserCount()
	if err != nil || n != 1 {
		t.Fatalf("UserCount = %d, %v; want 1", n, err)
	}
}

// TestAuthStateVerifyRoundTrip exercises add → verify (right + wrong
// password + unknown user) against a real DB row, proving the bcrypt hash
// stored is what VerifyUser checks.
func TestAuthStateVerifyRoundTrip(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	if err := a.AddUser("admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
	if u, ok := a.VerifyUser("Admin", "secretpw"); !ok || u != "admin" {
		t.Fatalf("VerifyUser = %q, %v; want admin (case-insensitive)", u, ok)
	}
	if _, ok := a.VerifyUser("admin", "wrongpw123"); ok {
		t.Fatal("VerifyUser accepted a wrong password")
	}
	if _, ok := a.VerifyUser("nobody", "secretpw"); ok {
		t.Fatal("VerifyUser accepted an unknown user")
	}
	// The stored value must be a bcrypt hash, never the plaintext.
	h, err := db.UserHash("admin")
	if err != nil {
		t.Fatal(err)
	}
	if h == "secretpw" || !strings.HasPrefix(h, "$2") {
		t.Fatalf("stored hash %q is not a bcrypt hash", h)
	}
}

// TestAuthRemoveLastUserProtected: the last remaining account cannot be
// removed through RemoveUser — only through Disable (the explicit
// auth-off action).
func TestAuthRemoveLastUserProtected(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	if err := a.AddUser("only", "secretpw"); err != nil {
		t.Fatal(err)
	}
	if err := a.RemoveUser("only"); err == nil {
		t.Fatal("removing the last user must fail")
	}
	if n, _ := db.UserCount(); n != 1 {
		t.Fatalf("UserCount = %d, want 1", n)
	}
	if err := a.AddUser("second", "secretpw"); err != nil {
		t.Fatal(err)
	}
	if err := a.RemoveUser("only"); err != nil {
		t.Fatalf("RemoveUser with two users: %v", err)
	}
	if err := a.Disable(); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if a.Enabled() {
		t.Fatal("auth still enabled after Disable")
	}
	if n, _ := db.UserCount(); n != 0 {
		t.Fatalf("UserCount after Disable = %d, want 0", n)
	}
	if _, ok := a.VerifyUser("second", "secretpw"); ok {
		t.Fatal("VerifyUser must fail after Disable")
	}
}

// TestAuthSessions: create → valid → drop, plus SessionUser ownership and
// rejection of bogus tokens.
func TestAuthSessions(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	if err := a.AddUser("admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.CreateSession("admin", "wrongpw123"); ok {
		t.Fatal("CreateSession must reject a bad password")
	}
	sess, ok := a.CreateSession("admin", "secretpw")
	if !ok || sess == "" {
		t.Fatal("CreateSession failed for valid credentials")
	}
	if !a.ValidSession(sess) {
		t.Fatal("fresh session must be valid")
	}
	if u, ok := a.SessionUser(sess); !ok || u != "admin" {
		t.Fatalf("SessionUser = %q, %v; want admin", u, ok)
	}
	if a.ValidSession("bogussessiontoken") {
		t.Fatal("unknown session must be invalid")
	}
	if a.ValidSession("") {
		t.Fatal("empty session must be invalid")
	}
	a.DropSession(sess)
	if a.ValidSession(sess) {
		t.Fatal("dropped session must be invalid")
	}
}

// TestExpiredSessionRejected: the 30-day sliding expiry must be enforced,
// not cosmetic. Backdates a live session's stored expiry directly (no
// waiting) and asserts both layers: ValidSession rejects + deletes the
// entry, and the auth gate 401s a request carrying the stale cookie.
// None of the other auth tests can catch this — they all run against
// fresh sessions.
func TestExpiredSessionRejected(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// backdate backdates the session token's stored expiry in place.
	backdate := func(tok string) {
		t.Helper()
		srv.auth.mu.Lock()
		defer srv.auth.mu.Unlock()
		s, ok := srv.auth.sessions[tok]
		if !ok {
			t.Fatalf("session %q not found in map", tok)
		}
		s.expiry = time.Now().Add(-time.Minute)
		srv.auth.sessions[tok] = s
	}
	// cookieTok reads the session cookie the jar holds.
	cookieTok := func() string {
		t.Helper()
		su, _ := url.Parse(httpSrv.URL)
		for _, c := range jar.Cookies(su) {
			if c.Name == authSessionName {
				return c.Value
			}
		}
		t.Fatal("no session cookie in jar")
		return ""
	}
	post := func(path, body string) *http.Response {
		t.Helper()
		resp, err := client.Post(httpSrv.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// --- unit level: expired token is invalid and deleted on check ---
	if err := srv.auth.AddUser("admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
	sess, ok := srv.auth.CreateSession("admin", "secretpw")
	if !ok {
		t.Fatal("CreateSession failed")
	}
	backdate(sess)
	if srv.auth.ValidSession(sess) {
		t.Fatal("ValidSession accepted an EXPIRED session token")
	}
	srv.auth.mu.Lock()
	_, stillThere := srv.auth.sessions[sess]
	srv.auth.mu.Unlock()
	if stillThere {
		t.Fatal("expired session entry must be deleted on rejection")
	}

	// A live session still slides: a hit moves expiry back to now+TTL.
	// Backdate it an hour first so the slide is measurable.
	sess2, ok := srv.auth.CreateSession("admin", "secretpw")
	if !ok {
		t.Fatal("CreateSession failed")
	}
	srv.auth.mu.Lock()
	s2 := srv.auth.sessions[sess2]
	s2.expiry = time.Now().Add(authSessionTTL - time.Hour)
	srv.auth.sessions[sess2] = s2
	srv.auth.mu.Unlock()
	if !srv.auth.ValidSession(sess2) {
		t.Fatal("ValidSession rejected a live session")
	}
	srv.auth.mu.Lock()
	after := srv.auth.sessions[sess2].expiry
	srv.auth.mu.Unlock()
	want := time.Now().Add(authSessionTTL)
	if after.Before(want.Add(-2*time.Second)) || after.After(want.Add(2*time.Second)) {
		t.Fatalf("live hit did not slide expiry to now+TTL: got %v, want ≈ %v", after, want)
	}

	// --- gate level: a stale cookie on the wire must 401 ---
	resp := post("/api/auth/login", `{"username":"admin","password":"secretpw"}`)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("login: got %d", resp.StatusCode)
	}
	backdate(cookieTok())
	resp, err := client.Get(httpSrv.URL + "/api/sensors")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("gate admitted an EXPIRED session cookie: got %d, want 401", resp.StatusCode)
	}
}

// TestAuthEnabledCacheServesFromCache proves the core claim: Enabled() stops
// issuing the per-request COUNT(*). userCountFn is a per-instance seam that
// counts how many times the underlying count source is actually read. Once
// the cache is primed, further reads within the TTL must come from memory.
func TestAuthEnabledCacheServesFromCache(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	reads := 0
	a.userCountFn = func() (int, error) {
		reads++
		return 0, nil // no users
	}

	// Prime: cold cache -> exactly one read.
	if a.Enabled() {
		t.Fatal("Enabled() true with zero users")
	}
	if reads != 1 {
		t.Fatalf("prime Enabled() read the count %d times, want 1", reads)
	}
	// Many more reads within the TTL: all served from cache, zero new reads.
	// Without the cache this would be +50.
	for i := 0; i < 50; i++ {
		_ = a.Enabled()
	}
	if reads != 1 {
		t.Fatalf("Enabled() within TTL re-read the count: total %d, want 1", reads)
	}

	// After the TTL expires, the next read must refresh (read again).
	time.Sleep(enabledTTL + 50*time.Millisecond)
	_ = a.Enabled()
	if reads != 2 {
		t.Fatalf("Enabled() after TTL did not refresh: total reads %d, want 2", reads)
	}
}

// TestAuthInAppMutationIsInstant confirms the dashboard's own user mutations
// are never stale: an in-app AddUser/Disable flips Enabled() immediately,
// with no TTL wait. The cache is primed "disabled" first and the test runs in
// milliseconds (well under the 2s TTL), so Enabled() can only be correct right
// after the mutation if the mutation refreshes the cache eagerly. Sabotaging
// refreshEnabledNow (removing it from AddUser/Disable) makes this fail.
func TestAuthInAppMutationIsInstant(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	if a.Enabled() {
		t.Fatal("Enabled() true on a fresh DB")
	}
	// Prime the cache with "disabled" so any subsequent "enabled" reading can
	// only come from the mutation's eager refresh, not a natural TTL expiry.
	_ = a.Enabled()

	start := time.Now()
	if err := a.AddUser("operator", "secretpw"); err != nil {
		t.Fatal(err)
	}
	if !a.Enabled() {
		t.Fatal("Enabled() not true immediately after in-app AddUser (eager refresh missing)")
	}
	if elapsed := time.Since(start); elapsed > enabledTTL {
		t.Fatalf("mutation+read took %v (> TTL %v); the instant-read assertion is no longer meaningful", elapsed, enabledTTL)
	}

	if err := a.Disable(); err != nil {
		t.Fatal(err)
	}
	if a.Enabled() {
		t.Fatal("Enabled() still true immediately after in-app Disable (eager refresh missing)")
	}
}

// TestAuthStateRefreshSeesExternalWrite simulates `pulsemon auth-user add`
// running OUTSIDE the server process: a second DB handle inserts a user and
// the live AuthState picks it up on its next check without a restart. With
// the Enabled() cache, out-of-band writes are honored within enabledTTL
// (in-app mutations are instant via refreshEnabledNow).
func TestAuthStateRefreshSeesExternalWrite(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	if a.Enabled() {
		t.Fatal("Enabled before any user exists")
	}
	// A sibling process (host CLI) writes through its own DB handle.
	sibling, err := NewDB(lastTestDBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer sibling.Close()
	if err := sibling.InitSchema(); err != nil {
		t.Fatal(err)
	}
	if err := (NewAuthState(sibling)).AddUser("cliuser", "secretpw"); err != nil {
		t.Fatal(err)
	}
	// Within the TTL the live state MAY still be cached (disabled) — that's
	// the documented ≤2s out-of-band staleness. Wait it out, then it MUST be
	// current.
	time.Sleep(enabledTTL + 50*time.Millisecond)
	if !a.Enabled() {
		t.Fatal("live AuthState did not pick up the external user write after the TTL")
	}
	if u, ok := a.VerifyUser("cliuser", "secretpw"); !ok || u != "cliuser" {
		t.Fatalf("VerifyUser after external write = %q, %v", u, ok)
	}
	// And back again: auth-user remove from the host clears it live.
	if err := sibling.RemoveAllUsers(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(enabledTTL + 50*time.Millisecond)
	if a.Enabled() {
		t.Fatal("live AuthState still enabled after external disable (post-TTL)")
	}
}

// TestAuthGateEndToEnd drives the real HTTP server with the auth gate:
// open dashboard → add user → 401s everywhere except healthz/auth-login →
// login sets a session cookie → API open → user management → logout →
// 401 again.
func TestAuthGateEndToEnd(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	post := func(path, body string) *http.Response {
		t.Helper()
		resp, err := client.Post(httpSrv.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	get := func(path string) *http.Response {
		t.Helper()
		resp, err := client.Get(httpSrv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	t.Run("open dashboard before auth", func(t *testing.T) {
		resp := get("/api/sensors")
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("sensors open: got %d", resp.StatusCode)
		}
	})

	// Auth is off, so the (session-gated) user endpoint is reachable:
	// creating the first account is what flips the gate on.
	t.Run("first user enables auth", func(t *testing.T) {
		resp := post("/api/auth/users", `{"username":"admin","password":"secretpw"}`)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("add first user: got %d", resp.StatusCode)
		}
	})

	t.Run("locked out after enable", func(t *testing.T) {
		for _, path := range []string{"/api/sensors", "/api/settings", "/api/events"} {
			resp := get(path)
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("%s: got %d, want 401", path, resp.StatusCode)
			}
		}
		// healthz stays open.
		resp := get("/api/healthz")
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("healthz: got %d, want 200", resp.StatusCode)
		}
		// The document still loads (the UI gate handles it).
		resp = get("/")
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("document: got %d, want 200", resp.StatusCode)
		}
	})

	t.Run("login requires valid credentials", func(t *testing.T) {
		resp := post("/api/auth/login", `{"username":"admin","password":"wrongpw123"}`)
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("bad password: got %d, want 401", resp.StatusCode)
		}
		resp = post("/api/auth/login", `{"username":"nobody","password":"secretpw"}`)
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("unknown user: got %d, want 401", resp.StatusCode)
		}
		resp = post("/api/auth/login", `{"username":"admin"}`)
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatalf("missing password: got %d, want 400", resp.StatusCode)
		}
	})

	t.Run("login sets session cookie", func(t *testing.T) {
		resp := post("/api/auth/login", `{"username":"Admin","password":"secretpw"}`)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("login: got %d, want 200", resp.StatusCode)
		}
		su, _ := url.Parse(httpSrv.URL)
		cookies := jar.Cookies(su)
		if len(cookies) != 1 || cookies[0].Name != authSessionName {
			t.Fatalf("session cookie not set: %v", cookies)
		}
		// The HttpOnly flag is asserted on the wire (the Set-Cookie
		// header), which is what browsers honor. net/http/cookiejar does
		// not preserve HttpOnly/SameSite on the cookies it returns.
		resp2 := post("/api/auth/login", `{"username":"Admin","password":"secretpw"}`)
		resp2.Body.Close()
		var found *http.Cookie
		for _, c := range resp2.Cookies() {
			if c.Name == authSessionName {
				found = c
			}
		}
		if found == nil {
			t.Fatalf("session cookie not on the wire: %v", resp2.Cookies())
		}
		if !found.HttpOnly {
			t.Fatal("session cookie must be HttpOnly on the wire")
		}
		if found.SameSite != http.SameSiteStrictMode {
			t.Fatalf("session cookie SameSite = %v, want Strict", found.SameSite)
		}
		if found.Path != "/" {
			t.Fatalf("session cookie Path = %q, want /", found.Path)
		}
		if !found.Expires.After(time.Now()) {
			t.Fatal("session cookie must have a future expiry")
		}
		// API is open with the session.
		resp = get("/api/sensors")
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("sensors with session: got %d", resp.StatusCode)
		}
	})

	t.Run("user management", func(t *testing.T) {
		// List: just admin.
		resp := get("/api/auth/users")
		var users []struct{ Username string }
		jsonDecode(t, resp, &users)
		resp.Body.Close()
		if len(users) != 1 || users[0].Username != "admin" {
			t.Fatalf("user list = %v, want [admin]", users)
		}
		// Add a second account.
		resp = post("/api/auth/users", `{"username":"bob","password":"bobpass1"}`)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("add bob: got %d", resp.StatusCode)
		}
		// Duplicate (case variant) is rejected.
		resp = post("/api/auth/users", `{"username":"BOB","password":"bobpass1"}`)
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatalf("duplicate user: got %d, want 400", resp.StatusCode)
		}
		// Change my own password.
		resp = post("/api/auth/users/admin/password", `{"password":"newpass9"}`)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("change own password: got %d", resp.StatusCode)
		}
		// ... but not someone else's.
		resp = post("/api/auth/users/bob/password", `{"password":"newpass9"}`)
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatalf("change other's password: got %d, want 404", resp.StatusCode)
		}
		// Old password is dead, new one works (fresh client, no cookie).
		bare := &http.Client{}
		req, _ := http.NewRequest("POST", httpSrv.URL+"/api/auth/login",
			strings.NewReader(`{"username":"admin","password":"secretpw"}`))
		req.Header.Set("Content-Type", "application/json")
		r2, err := bare.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r2.Body.Close()
		if r2.StatusCode != 401 {
			t.Fatalf("old password: got %d, want 401", r2.StatusCode)
		}
		req, _ = http.NewRequest("POST", httpSrv.URL+"/api/auth/login",
			strings.NewReader(`{"username":"admin","password":"newpass9"}`))
		req.Header.Set("Content-Type", "application/json")
		r3, err := bare.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r3.Body.Close()
		if r3.StatusCode != 200 {
			t.Fatalf("new password: got %d, want 200", r3.StatusCode)
		}
		// Remove bob (a non-last user).
		req, _ = http.NewRequest("DELETE", httpSrv.URL+"/api/auth/users/bob", nil)
		r4, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r4.Body.Close()
		if r4.StatusCode != 200 {
			t.Fatalf("remove bob: got %d", r4.StatusCode)
		}
		// Remove the last user is refused (400).
		req, _ = http.NewRequest("DELETE", httpSrv.URL+"/api/auth/users/admin", nil)
		r5, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r5.Body.Close()
		if r5.StatusCode != 400 {
			t.Fatalf("remove last user: got %d, want 400", r5.StatusCode)
		}
	})

	t.Run("user management requires a session", func(t *testing.T) {
		bare := &http.Client{}
		resp, err := bare.Get(httpSrv.URL + "/api/auth/users")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("user list without session: got %d, want 401", resp.StatusCode)
		}
	})

	t.Run("logout locks out again", func(t *testing.T) {
		resp := post("/api/auth/logout", "{}")
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("logout: got %d", resp.StatusCode)
		}
		resp = get("/api/sensors")
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("after logout: got %d, want 401", resp.StatusCode)
		}
	})
}

// TestAuthDisableViaAPI turns auth off through the endpoint and proves the
// dashboard is open again without a restart.
func TestAuthDisableViaAPI(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	resp, err := client.Post(httpSrv.URL+"/api/auth/users", "application/json",
		strings.NewReader(`{"username":"admin","password":"secretpw"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = client.Post(httpSrv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"secretpw"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	resp, err = client.Post(httpSrv.URL+"/api/auth/disable", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("disable: %d", resp.StatusCode)
	}
	// Fresh client (no cookie): the dashboard is open again.
	bare := &http.Client{}
	resp, err = bare.Get(httpSrv.URL + "/api/sensors")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("after disable: got %d, want 200", resp.StatusCode)
	}
}

// TestAuthLegacyTokenMigration: a DB created by the old single-token build
// (settings row `auth_token` holding a bcrypt hash) must boot into the new
// user model with an `admin` account whose password is the old token, and
// the legacy row must be cleared so the migration only ever runs once.
func TestAuthLegacyTokenMigration(t *testing.T) {
	db := newTestDB(t)
	const tok = "pm_abcdefGhijklMNopqr2345"
	hash, err := bcrypt.GenerateFromPassword([]byte(tok), bcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting("auth_token", string(hash)); err != nil {
		t.Fatal(err)
	}
	// Re-init the schema: this is what a server boot does on the old DB.
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema on legacy DB: %v", err)
	}
	if n, _ := db.UserCount(); n != 1 {
		t.Fatalf("UserCount after migration = %d, want 1", n)
	}
	a := NewAuthState(db)
	if u, ok := a.VerifyUser("admin", tok); !ok || u != "admin" {
		t.Fatalf("VerifyUser(admin, old token) = %q, %v; want ok", u, ok)
	}
	if got := db.GetSetting("auth_token"); got != "" {
		t.Fatalf("legacy auth_token row not cleared: %q", got)
	}
	// Idempotent: a second InitSchema must not fail or add a user.
	if err := db.InitSchema(); err != nil {
		t.Fatalf("second InitSchema: %v", err)
	}
	if n, _ := db.UserCount(); n != 1 {
		t.Fatalf("UserCount after re-migration = %d, want 1", n)
	}
}

// loginPost is a helper that POSTs a login body with an optional
// X-Forwarded-For override (to simulate distinct client IPs through the
// same test server).
func loginPost(t *testing.T, base, body, xff string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", base+"/api/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestLoginThrottleLockout drives the real server: loginFailMax failed
// attempts from one IP lock it out (subsequent attempts — even with the
// CORRECT password — return 429 + Retry-After, and never run the bcrypt
// KDF), while a DIFFERENT IP is unaffected. A successful login from an
// IP that has some failures clears its counter.
func TestLoginThrottleLockout(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	// Trust the loopback peer so the X-Forwarded-For values below are honored
	// as distinct client IPs (models a reverse-proxied install). Without this,
	// the new default ignores XFF and every request would key to the peer.
	srv.auth.trustedProxies = parseTrustedProxies("127.0.0.0/8")
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	if err := srv.auth.AddUser("admin", "secretpw"); err != nil {
		t.Fatal(err)
	}

	// Fill the failure window from a single simulated IP.
	const attackerIP = "203.0.113.7"
	for i := 0; i < loginFailMax; i++ {
		resp := loginPost(t, httpSrv.URL, `{"username":"admin","password":"wrongpw"}`, attackerIP)
		resp.Body.Close()
		if i < loginFailMax-1 {
			if resp.StatusCode != 401 {
				t.Fatalf("attempt %d: got %d, want 401 (before lockout)", i, resp.StatusCode)
			}
		} else {
			// The Nth failure trips the lockout; it is still a 401 this time
			// (the attempt ran), but the NEXT one is throttled.
			if resp.StatusCode != 401 {
				t.Fatalf("attempt %d: got %d, want 401", i, resp.StatusCode)
			}
		}
	}

	// Now locked out: even the CORRECT password is refused with 429.
	resp := loginPost(t, httpSrv.URL, `{"username":"admin","password":"secretpw"}`, attackerIP)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("locked-out correct login: got %d, want 429 (body %s)", resp.StatusCode, body)
	}
	if ra := resp.Header.Get("Retry-After"); ra == "" {
		t.Fatal("429 must carry a Retry-After header")
	}

	// A DIFFERENT client IP is unaffected by the attacker's lockout.
	resp = loginPost(t, httpSrv.URL, `{"username":"admin","password":"secretpw"}`, "198.51.100.1")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("unaffected IP: got %d, want 200", resp.StatusCode)
	}

	// A direct-IP path (no XFF) also works — the lockout is per-IP.
	resp = loginPost(t, httpSrv.URL, `{"username":"admin","password":"secretpw"}`, "")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("direct-IP login: got %d, want 200", resp.StatusCode)
	}
}

// TestLoginSuccessClearsThrottle: a few failures, then a SUCCESS, must reset
// the counter so the operator is not carrying forward stale failures.
func TestLoginSuccessClearsThrottle(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	// Trust the loopback peer so the X-Forwarded-For value below is honored
	// as the client IP (models a reverse-proxied install).
	srv.auth.trustedProxies = parseTrustedProxies("127.0.0.0/8")
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()
	if err := srv.auth.AddUser("admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
	const ip = "203.0.113.9"
	// loginFailMax-1 failures (one short of lockout), then a success.
	for i := 0; i < loginFailMax-1; i++ {
		resp := loginPost(t, httpSrv.URL, `{"username":"admin","password":"wrong"}`, ip)
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("pre-success failure %d: got %d, want 401", i, resp.StatusCode)
		}
	}
	resp := loginPost(t, httpSrv.URL, `{"username":"admin","password":"secretpw"}`, ip)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("success after failures: got %d, want 200", resp.StatusCode)
	}
	// The success cleared the counter: the NEXT loginFailMax failures should
	// all be plain 401s (not a 429), proving the counter restarted.
	for i := 0; i < loginFailMax-1; i++ {
		r2 := loginPost(t, httpSrv.URL, `{"username":"admin","password":"wrong"}`, ip)
		r2.Body.Close()
		if r2.StatusCode != 401 {
			t.Fatalf("post-reset failure %d: got %d, want 401", i, r2.StatusCode)
		}
	}
}

// TestRejectedLoginIsSlowed: every rejected login must take at least the
// constant-time delay (loginSlowDown). This is what equalizes the
// unknown-user / wrong-password response times (closing the timing oracle)
// and caps online-cracking speed. Measured end-to-end over HTTP.
func TestRejectedLoginIsSlowed(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()
	if err := srv.auth.AddUser("admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
	// Warm up (first bcrypt call may include some one-time init).
	_ = loginPost(t, httpSrv.URL, `{"username":"admin","password":"wrong"}`, "203.0.113.20")
	start := time.Now()
	resp := loginPost(t, httpSrv.URL, `{"username":"admin","password":"wrong"}`, "203.0.113.20")
	resp.Body.Close()
	elapsed := time.Since(start)
	if resp.StatusCode != 401 {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
	if elapsed < loginSlowDown {
		t.Fatalf("rejected login took %v, want >= %v (constant-time delay)", elapsed, loginSlowDown)
	}
}

// TestClientIP pins the IP-extraction rules the throttle keys on:
//   - default: the direct TCP peer; X-Forwarded-For from an untrusted peer is
//     IGNORED (so it cannot be rotated to dodge the lockout).
//   - trusted peer (in PULSEMON_TRUSTED_PROXIES): the first X-Forwarded-For
//     entry wins, attributing the attempt to the real client.
//   - malformed XFF always falls back to the peer.
func TestClientIP(t *testing.T) {
	newReq := func(remote, xff string) *http.Request {
		r := httptest.NewRequest("POST", "/api/auth/login", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	// default: no trusted proxies — XFF must be ignored.
	def := NewAuthState(nil)
	// trusted: loopback peer is trusted, so XFF is honored.
	proxied := NewAuthState(nil)
	proxied.trustedProxies = parseTrustedProxies("127.0.0.0/8")

	if got := def.ClientIP(newReq("10.0.0.5:1234", "")); got != "10.0.0.5" {
		t.Errorf("direct peer (default) = %q, want 10.0.0.5", got)
	}
	// The fix: an untrusted peer's XFF is ignored, even a well-formed one.
	if got := def.ClientIP(newReq("10.0.0.5:1234", "203.0.113.7, 10.0.0.1")); got != "10.0.0.5" {
		t.Errorf("untrusted-peer XFF = %q, want peer 10.0.0.5 (XFF must be ignored)", got)
	}
	// Trusted peer: first XFF entry is used.
	if got := proxied.ClientIP(newReq("127.0.0.1:999", "203.0.113.7, 10.0.0.1")); got != "203.0.113.7" {
		t.Errorf("trusted-peer XFF = %q, want 203.0.113.7", got)
	}
	// Trusted peer but no XFF: falls back to the peer.
	if got := proxied.ClientIP(newReq("127.0.0.1:999", "")); got != "127.0.0.1" {
		t.Errorf("trusted peer, no XFF = %q, want 127.0.0.1", got)
	}
	// Malformed XFF (even from a trusted peer): fall back to the peer.
	if got := proxied.ClientIP(newReq("127.0.0.1:999", "garbage, 10.0.0.1")); got != "127.0.0.1" {
		t.Errorf("malformed trusted XFF = %q, want peer 127.0.0.1", got)
	}
	// Bare-IP trust entry (no /32) still matches.
	bare := NewAuthState(nil)
	bare.trustedProxies = parseTrustedProxies("10.99.99.50")
	if got := bare.ClientIP(newReq("10.99.99.50:443", "9.9.9.9")); got != "9.9.9.9" {
		t.Errorf("bare-IP trusted peer XFF = %q, want 9.9.9.9", got)
	}
}

// TestClientIPRotationIgnored is the security proof for the X-Forwarded-For
// spoofing fix: an attacker who rotates the XFF header on every request must
// still be keyed to the SAME IP (the real TCP peer), so the per-IP throttle
// cannot be dodged. With the old "trust XFF unconditionally" code each
// rotated value produced a fresh throttle key and the lockout never tripped.
func TestClientIPRotationIgnored(t *testing.T) {
	a := NewAuthState(nil) // no trusted proxies — the default, safest config.
	const peer = "203.0.113.7:55555"
	saw := map[string]bool{}
	for i := 0; i < 50; i++ {
		r := httptest.NewRequest("POST", "/api/auth/login", nil)
		r.RemoteAddr = peer
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("1.1.1.%d", i)) // rotate every call
		saw[a.ClientIP(r)] = true
	}
	if len(saw) != 1 {
		t.Fatalf("rotating XFF produced %d distinct throttle keys %v; want exactly 1 (the peer)", len(saw), saw)
	}
	if _, ok := saw["203.0.113.7"]; !ok {
		t.Fatalf("throttle key = %v; want the peer 203.0.113.7", saw)
	}
}

// TestLoginThrottleIgnoresUntrustedXFF drives the REAL server over HTTP with
// NO trusted proxies (the default). An attacker rotates X-Forwarded-For on
// every attempt, hoping each request looks like a new IP. Because the XFF is
// ignored, every attempt is keyed to the same loopback peer, so after
// loginFailMax failures the peer is locked out — the 429 fires regardless of
// how many fake IPs the attacker cycled. This test FAILS on the old code
// (where each rotated XFF was a fresh key and no lockout ever tripped).
func TestLoginThrottleIgnoresUntrustedXFF(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	// Default: no trusted proxies (NewAuthState reads PULSEMON_TRUSTED_PROXIES,
	// which is unset here). Be explicit so a stray env var can't change it.
	srv.auth.trustedProxies = nil
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	if err := srv.auth.AddUser("admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
	// loginFailMax attempts, each with a DIFFERENT spoofed XFF. If XFF were
	// trusted these would be loginFailMax distinct IPs (no lockout); since it
	// isn't, they're all the same peer and the lockout trips.
	for i := 0; i < loginFailMax; i++ {
		resp := loginPost(t, httpSrv.URL, `{"username":"admin","password":"wrongpw"}`, fmt.Sprintf("10.99.%d.%d", i/256, i%256))
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("attempt %d: got %d, want 401 (still below lockout)", i, resp.StatusCode)
		}
	}
	// Next attempt (yet another spoofed IP) must now be 429 — the peer is
	// locked out, rotation didn't help.
	resp := loginPost(t, httpSrv.URL, `{"username":"admin","password":"secretpw"}`, "10.99.255.255")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("post-rotation: got %d, want 429 (body %s) — XFF rotation must not dodge the lockout", resp.StatusCode, body)
	}
}

// jsonDecode decodes a JSON response body into v.
func jsonDecode(t *testing.T, resp *http.Response, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}
