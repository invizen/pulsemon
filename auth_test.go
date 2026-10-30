package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
	"pulsemon/internal/store"
)

// lastTestDBPath records the most recent newTestDB path so sibling-handle
// tests (out-of-band writes, like the host CLI) can reopen the same store.
var lastTestDBPath string

func newTestDB(t *testing.T) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.db")
	lastTestDBPath = path
	db, err := store.NewStore(path)
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
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
	if _, ok := a.CreateSession("admin", "wrongpw123", false); ok {
		t.Fatal("CreateSession must reject a bad password")
	}
	sess, ok := a.CreateSession("admin", "secretpw", false)
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
	sess, ok := srv.auth.CreateSession("admin", "secretpw", false)
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
	sess2, ok := srv.auth.CreateSession("admin", "secretpw", false)
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

// TestSessionAbsoluteMaxAge: the 30-day sliding expiry must NOT let a
// session live forever. authSessionMaxAge caps the total lifetime from LOGIN
// time (s.created), independent of activity — so a continuously-active
// session (an open dashboard tab polling every few seconds, or a stolen
// cookie used periodically, whose sliding expiry ValidSession/SessionUser
// keep pushing out) is rejected and deleted once authSessionMaxAge elapses
// from login, even though its sliding expiry is still far in the future. The
// sliding TTL alone cannot do this; the cap is the absolute bound.
//
// Like TestExpiredSessionRejected this backdates the stored fields directly
// (no 30-day wait): an "active" session is one whose sliding expiry is in the
// future but whose login time (created) is past the cap.
func TestSessionAbsoluteMaxAge(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	if err := a.AddUser("admin", "secretpw"); err != nil {
		t.Fatal(err)
	}

	// activeWithLoginAgo mints a real session, then backdates its LOGIN time
	// by createdAgo while keeping its sliding expiry in the future (now+TTL) —
	// the exact state a continuously-active session reaches createdAgo after
	// login.
	activeWithLoginAgo := func(createdAgo time.Duration) string {
		tok, ok := a.CreateSession("admin", "secretpw", false)
		if !ok {
			t.Fatal("CreateSession failed")
		}
		a.mu.Lock()
		s := a.sessions[tok]
		s.created = time.Now().Add(-createdAgo)
		s.expiry = time.Now().Add(authSessionTTL) // actively slid: far in the future
		a.sessions[tok] = s
		a.mu.Unlock()
		return tok
	}

	// 1. Within the cap: an active session still validates (and slides).
	within := activeWithLoginAgo(29 * 24 * time.Hour)
	if !a.ValidSession(within) {
		t.Fatal("a session within the max-age cap must stay valid")
	}

	// 2. Past the cap: an ACTIVE session (future sliding expiry) is rejected
	//    AND deleted once authSessionMaxAge elapses from login.
	past := activeWithLoginAgo(31 * 24 * time.Hour)
	if a.ValidSession(past) {
		t.Fatal("ValidSession accepted a session past its absolute max-age")
	}
	a.mu.Lock()
	_, stillValid := a.sessions[past]
	a.mu.Unlock()
	if stillValid {
		t.Fatal("a past-max-age session entry must be deleted on rejection")
	}

	// 3. The cap must hold on SessionUser too (the gate-exempt
	//    /api/auth/status path) — not just ValidSession — otherwise a
	//    status-poll-only client would slide its session forever.
	past2 := activeWithLoginAgo(31 * 24 * time.Hour)
	if _, ok := a.SessionUser(past2); ok {
		t.Fatal("SessionUser accepted a session past its absolute max-age")
	}
	a.mu.Lock()
	_, stillValid2 := a.sessions[past2]
	a.mu.Unlock()
	if stillValid2 {
		t.Fatal("SessionUser must delete a past-max-age session on rejection")
	}

	// 4. A just-logged-in session is unaffected by the cap.
	fresh, ok := a.CreateSession("admin", "secretpw", false)
	if !ok {
		t.Fatal("CreateSession failed")
	}
	if !a.ValidSession(fresh) {
		t.Fatal("a just-logged-in session must be valid")
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
	sibling, err := store.NewStore(lastTestDBPath)
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

	t.Run("setup mode: bootstrap surface only", func(t *testing.T) {
		// Fresh install (no account has ever existed): non-bootstrap
		// endpoints are 403 — no unauthenticated sensor access before the
		// first account. healthz stays open.
		resp := get("/api/sensors")
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("sensors in setup mode: got %d, want 403", resp.StatusCode)
		}
		resp = get("/api/healthz")
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("healthz in setup mode: got %d, want 200", resp.StatusCode)
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
		// Max-Age is relative to the client's receipt time (RFC 6265
		// §5.3 gives it precedence over Expires), so a client clock
		// skewed ahead of the server can't treat the expiry as already
		// past and drop the cookie (2026-10-20 external review).
		if found.MaxAge != int(authSessionTTL.Seconds()) {
			t.Fatalf("session cookie MaxAge = %d, want %d", found.MaxAge, int(authSessionTTL.Seconds()))
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
		// Change my own password (current password required since the
		// 2026-10-23 external-review fix).
		resp = post("/api/auth/users/admin/password", `{"current_password":"secretpw","password":"newpass9"}`)
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
		// The deletion cookie must carry Max-Age=0 ("delete now" per
		// RFC 6265) — a negative MaxAge would OMIT the attribute and
		// leave only the clock-absolute 1970 Expires (2026-10-20
		// external review).
		var del *http.Cookie
		for _, c := range resp.Cookies() {
			if c.Name == authSessionName {
				del = c
			}
		}
		if del == nil {
			t.Fatalf("logout did not send a deletion cookie: %v", resp.Cookies())
		}
		if del.MaxAge != 0 {
			t.Fatalf("deletion cookie MaxAge = %d, want 0", del.MaxAge)
		}
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
//   - trusted peer (in PULSEMON_TRUSTED_PROXIES): the rightmost XFF entry
//     that is not itself a trusted proxy wins (2026-10-19 review M3a —
//     entries left of it are client-supplied and rotatable).
//   - unparseable XFF entries are skipped; if none parse, the peer is used.
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
	// Trusted peer: the rightmost untrusted XFF entry is used — 10.0.0.1 is
	// the hop our proxy appended; 203.0.113.7 is client-supplied.
	if got := proxied.ClientIP(newReq("127.0.0.1:999", "203.0.113.7, 10.0.0.1")); got != "10.0.0.1" {
		t.Errorf("trusted-peer XFF = %q, want 10.0.0.1 (rightmost untrusted)", got)
	}
	// Trusted peer but no XFF: falls back to the peer.
	if got := proxied.ClientIP(newReq("127.0.0.1:999", "")); got != "127.0.0.1" {
		t.Errorf("trusted peer, no XFF = %q, want 127.0.0.1", got)
	}
	// Malformed XFF entries are skipped (even from a trusted peer).
	if got := proxied.ClientIP(newReq("127.0.0.1:999", "10.0.0.1, garbage")); got != "10.0.0.1" {
		t.Errorf("malformed trusted XFF = %q, want 10.0.0.1", got)
	}
	// Entirely unparseable XFF: fall back to the peer.
	if got := proxied.ClientIP(newReq("127.0.0.1:999", "garbage, nonsense")); got != "127.0.0.1" {
		t.Errorf("unparseable trusted XFF = %q, want peer 127.0.0.1", got)
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

// TestSweepThrottleDropsStaleEntries locks the m4 fix: the opportunistic GC
// drops throttle entries that can no longer affect a decision (no recent
// failures AND no active lockout), while keeping entries with a recent
// failure or an unexpired lockout. This bounds memory under a multi-IP spray.
func TestSweepThrottleDropsStaleEntries(t *testing.T) {
	a := NewAuthState(newTestDB(t))
	a.ensureThrottleMaps()
	now := time.Now()

	// stale: failures older than the window, no lockout → dropped.
	a.loginThrottle.fails["stale"] = []time.Time{now.Add(-2 * loginFailWindow)}
	// recent: a failure within the window → kept.
	a.loginThrottle.fails["recent"] = []time.Time{now.Add(-time.Second)}
	// locked: stale failures but an active (unexpired) lockout → kept.
	a.loginThrottle.fails["locked"] = []time.Time{now.Add(-2 * loginFailWindow)}
	a.loginThrottle.lockout["locked"] = now.Add(loginLockout)

	a.sweepThrottle(now)

	if _, ok := a.loginThrottle.fails["stale"]; ok {
		t.Error("stale entry not swept")
	}
	if _, ok := a.loginThrottle.fails["recent"]; !ok {
		t.Error("recent entry swept (should be kept)")
	}
	if _, ok := a.loginThrottle.fails["locked"]; !ok {
		t.Error("locked entry swept (should be kept while lockout is active)")
	}
	if _, ok := a.loginThrottle.lockout["locked"]; !ok {
		t.Error("active lockout removed (should be kept)")
	}
}

// TestSweepExpiredSessionsEvictsAbandoned locks the opportunistic session
// GC: when CreateSession runs past the sweep threshold, expired sessions
// are evicted from the map while live sessions survive. Without the sweep,
// an abandoned session (cookie discarded, never presented again) pins its
// map entry for the process's entire uptime — ValidSession/SessionUser only
// delete the specific token they are asked about.
func TestSweepExpiredSessionsEvictsAbandoned(t *testing.T) {
	a := NewAuthState(newTestDB(t))
	if err := a.AddUser("admin", "secretpw"); err != nil {
		t.Fatal(err)
	}

	// Fill the map past the sweep threshold (64).
	const n = 70
	toks := make([]string, 0, n)
	for i := 0; i < n; i++ {
		tok, ok := a.CreateSession("admin", "secretpw", false)
		if !ok {
			t.Fatal("create session")
		}
		toks = append(toks, tok)
	}

	// Age every session EXCEPT the last five past its expiry: the five
	// survivors must outlive the sweep, the rest must not.
	a.mu.Lock()
	for i, tok := range toks {
		if i < n-5 {
			s := a.sessions[tok]
			s.expiry = time.Now().Add(-time.Minute)
			a.sessions[tok] = s
		}
	}
	a.mu.Unlock()

	// The next CreateSession crosses the threshold and must sweep. The
	// sweep is rate-limited now (review nit 2026-10-24: a full walk on
	// every past-threshold create was O(n^2)); the fill loop above already
	// consumed this window's sweep, so open it again to observe eviction.
	a.mu.Lock()
	a.nextSweepSessions = time.Time{}
	a.mu.Unlock()
	fresh, ok := a.CreateSession("admin", "secretpw", false)
	if !ok {
		t.Fatal("create session after sweep")
	}

	a.mu.Lock()
	got := len(a.sessions)
	_, freshAlive := a.sessions[fresh]
	a.mu.Unlock()
	if !freshAlive {
		t.Fatal("new session missing from map")
	}
	if want := 6; got != want { // 5 live survivors + the new session
		t.Fatalf("map size after sweep = %d, want %d (expired entries evicted, live ones kept)", got, want)
	}
	// The aged tokens must be gone — not merely expired, evicted.
	a.mu.Lock()
	for i, tok := range toks[:n-5] {
		if _, ok := a.sessions[tok]; ok {
			t.Fatalf("expired token %d (age %s) still in map after sweep", i, tok[:8])
		}
	}
	a.mu.Unlock()
	for i, tok := range toks[n-5:] {
		if !a.ValidSession(tok) {
			t.Fatalf("live token %d rejected after sweep", i)
		}
	}
}

// TestFix_m6_SecureCookieBehindTrustedProxy pins the m6 fix: behind a
// TLS-terminating reverse proxy (plain HTTP at the socket, trusted peer,
// X-Forwarded-Proto: https) the session cookie must carry Secure — the old
// code set Secure only when r.TLS != nil, so a proxied install handed the
// session token to a plaintext hop. A spoofed X-Forwarded-Proto from a
// peer that is NOT in the trusted list must not gain Secure.
func TestFix_m6_SecureCookieBehindTrustedProxy(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	// Trust the loopback peer (the httptest client) so its
	// X-Forwarded-Proto is honored — models a reverse-proxied install.
	srv.auth.trustedProxies = parseTrustedProxies("127.0.0.0/8")
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	if err := srv.auth.AddUser("admin", "secretpw"); err != nil {
		t.Fatal(err)
	}

	login := func(xfp string) *http.Cookie {
		t.Helper()
		req, _ := http.NewRequest("POST", httpSrv.URL+"/api/auth/login", strings.NewReader(`{"username":"admin","password":"secretpw"}`))
		req.Header.Set("Content-Type", "application/json")
		if xfp != "" {
			req.Header.Set("X-Forwarded-Proto", xfp)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login: got %d, want 200", resp.StatusCode)
		}
		var c *http.Cookie
		for _, cc := range resp.Cookies() {
			if cc.Name == authSessionName {
				c = cc
				break
			}
		}
		if c == nil {
			t.Fatalf("no session cookie in response")
		}
		return c
	}

	t.Run("trusted proxy + XFP https => Secure", func(t *testing.T) {
		if c := login("https"); !c.Secure {
			t.Error("cookie not Secure behind a trusted proxy reporting https")
		}
	})
	t.Run("trusted proxy + XFP http => not Secure", func(t *testing.T) {
		if c := login("http"); c.Secure {
			t.Error("cookie Secure behind a trusted proxy reporting http")
		}
	})
	t.Run("no XFP header => not Secure", func(t *testing.T) {
		if c := login(""); c.Secure {
			t.Error("cookie Secure on plain HTTP without X-Forwarded-Proto")
		}
	})
}

// TestClientIPRightmostUntrusted pins the 2026-10-19 review M3a fix: behind
// a trusted proxy, the client controls everything LEFT of the hop the proxy
// appended, so rotating the leftmost XFF entry must not change the throttle
// key. Nested trusted proxies are skipped right-to-left; if every entry is
// trusted, the leftmost is used.
func TestClientIPRightmostUntrusted(t *testing.T) {
	a := NewAuthState(nil)
	a.trustedProxies = parseTrustedProxies("127.0.0.0/8, 10.99.99.0/24")
	req := func(xff string) *http.Request {
		r := httptest.NewRequest("POST", "/api/auth/login", nil)
		r.RemoteAddr = "127.0.0.1:443"
		r.Header.Set("X-Forwarded-For", xff)
		return r
	}
	saw := map[string]bool{}
	for i := 0; i < 20; i++ {
		saw[a.ClientIP(req(fmt.Sprintf("1.1.1.%d, 203.0.113.7", i)))] = true
	}
	if len(saw) != 1 || !saw["203.0.113.7"] {
		t.Fatalf("rotating leftmost XFF produced keys %v; want only 203.0.113.7", saw)
	}
	// Nested trusted hop (10.99.99.2) on the right is skipped.
	if got := a.ClientIP(req("1.1.1.1, 203.0.113.7, 10.99.99.2")); got != "203.0.113.7" {
		t.Errorf("nested trusted hop: got %q, want 203.0.113.7", got)
	}
	// Every entry trusted: leftmost wins.
	if got := a.ClientIP(req("10.99.99.3, 10.99.99.2")); got != "10.99.99.3" {
		t.Errorf("all-trusted XFF: got %q, want leftmost 10.99.99.3", got)
	}
}

// TestThrottleKey pins the 2026-10-19 review M3b bucketing as refined by
// external review #7: private/loopback IPv4 per host (/32), other IPv4
// shares a /24, IPv6 shares a /64, unparseable strings pass through.
func TestThrottleKey(t *testing.T) {
	cases := map[string]string{
		// private + loopback IPv4: per-host
		"10.99.99.7":        "10.99.99.7",
		"10.99.99.250":      "10.99.99.250",
		"192.168.1.5":       "192.168.1.5",
		"172.16.0.1":        "172.16.0.1",
		"127.0.0.1":         "127.0.0.1",
		"::ffff:10.99.99.7": "10.99.99.7",
		// public IPv4: /24 (rotation within the /24 stays in one bucket)
		"93.184.216.34": "93.184.216.0",
		"93.184.216.99": "93.184.216.0",
		// IPv6: /64
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::",
		"2001:db8:1:2:ffff::9": "2001:db8:1:2::",
		"2001:db8:1:3::1":      "2001:db8:1:3::",
		"not-an-ip":            "not-an-ip",
	}
	for in, want := range cases {
		if got := throttleKey(in); got != want {
			t.Errorf("throttleKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestLoginThrottleIPv6Slash64 drives the real server: failures spread
// across addresses in ONE /64 share a single budget, so the lockout trips
// for the whole /64 (2026-10-19 review M3b).
func TestLoginThrottleIPv6Slash64(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	srv.auth.trustedProxies = parseTrustedProxies("127.0.0.0/8")
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()
	if err := srv.auth.AddUser("admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < loginFailMax; i++ {
		resp := loginPost(t, httpSrv.URL, `{"username":"admin","password":"wrongpw"}`, fmt.Sprintf("2001:db8:1:2::%x", i+1))
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("attempt %d: got %d, want 401", i, resp.StatusCode)
		}
	}
	resp := loginPost(t, httpSrv.URL, `{"username":"admin","password":"secretpw"}`, "2001:db8:1:2::ffff")
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("fresh address in locked /64: got %d, want 429", resp.StatusCode)
	}
	// A different /64 is unaffected.
	resp = loginPost(t, httpSrv.URL, `{"username":"admin","password":"secretpw"}`, "2001:db8:1:3::1")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("other /64: got %d, want 200", resp.StatusCode)
	}
}

// TestLoginThrottleLANPerHost is the 2026-10-19 external review #7
// regression: private IPv4 is bucketed per host (/32), NOT per /24 — one
// misbehaving LAN client (stale saved password, an old polling script)
// must not lock out every other device on the homelab subnet. The
// "other LAN host still logs in" assertion is what the /24-era code
// fails: it answered 429 there.
func TestLoginThrottleLANPerHost(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	srv.auth.trustedProxies = parseTrustedProxies("127.0.0.0/8")
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()
	if err := srv.auth.AddUser("admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < loginFailMax; i++ {
		resp := loginPost(t, httpSrv.URL, `{"username":"admin","password":"wrongpw"}`, "192.168.1.7")
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("attempt %d: got %d, want 401", i, resp.StatusCode)
		}
	}
	// The locked host stays locked...
	resp := loginPost(t, httpSrv.URL, `{"username":"admin","password":"secretpw"}`, "192.168.1.7")
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("locked host: got %d, want 429", resp.StatusCode)
	}
	// ...while a DIFFERENT host on the same /24 is unaffected.
	resp = loginPost(t, httpSrv.URL, `{"username":"admin","password":"secretpw"}`, "192.168.1.8")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("other LAN host: got %d, want 200", resp.StatusCode)
	}
}

// TestRemoveUserConcurrentNeverZero is the 2026-10-19 review M4 regression:
// two concurrent RemoveUser calls on the last two accounts must never both
// succeed (the old COUNT-then-DELETE did, leaving zero users = auth off).
func TestRemoveUserConcurrentNeverZero(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	for round := 0; round < 100; round++ {
		if err := db.RemoveAllUsers(); err != nil {
			t.Fatal(err)
		}
		// Bypass bcrypt (cost is irrelevant here) — insert rows directly
		// (the DB-level AddUser helper was removed: the non-atomic
		// COUNT-then-INSERT duplicated the first-admin invariant that
		// AuthState.AddUserMode owns atomically, with no production
		// callers — 2026-10-22 external review).
		for _, u := range []string{"alice", "bob"} {
			if _, err := db.Exec(`INSERT INTO users (username, password_hash, created_at, is_admin) VALUES (?, 'x', ?, 0)`, u, store.Now()); err != nil {
				t.Fatal(err)
			}
		}
		var wg sync.WaitGroup
		for _, u := range []string{"alice", "bob"} {
			wg.Add(1)
			go func(u string) {
				defer wg.Done()
				_ = a.RemoveUser(u)
			}(u)
		}
		wg.Wait()
		if n, err := db.UserCount(); err != nil || n == 0 {
			t.Fatalf("round %d: user count = %d (err %v), want >= 1", round, n, err)
		}
	}
	// Direct DB call on the last user is refused too.
	if n, _ := db.UserCount(); n == 1 {
		users, _ := db.ListUsers()
		if err := db.RemoveUser(users[0].Username); err == nil {
			t.Fatal("db.RemoveUser of the last user succeeded, want error")
		}
	}
}

// TestPasswordOver72Bytes pins the 2026-10-19 review m2 fix: a >72-byte
// password is a 400 with our message on create (was a 500) and a clean
// errPasswordTooLong on change (was raw bcrypt text).
func TestPasswordOver72Bytes(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	long := strings.Repeat("a", 73)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/users",
		strings.NewReader(`{"username":"admin","password":"`+long+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.authGate().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "exceeds 72 bytes") {
		t.Fatalf("create with 73-byte password: %d %s, want 400 'exceeds 72 bytes'", rr.Code, rr.Body.String())
	}
	if err := srv.auth.AddUser("admin", strings.Repeat("a", 72)); err != nil {
		t.Fatalf("72-byte password must be accepted: %v", err)
	}
	if err := srv.auth.SetUserPassword("admin", long, ""); !errors.Is(err, errPasswordTooLong) {
		t.Fatalf("SetUserPassword 73 bytes: err %v, want errPasswordTooLong", err)
	}
}

// ---------- admin-flag tests (2026-10-19 external review fix) ----------

func adminFlagServer(t *testing.T) (*store.Store, *httptest.Server) {
	t.Helper()
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	t.Cleanup(httpSrv.Close)
	return db, httpSrv
}

func userByName(t *testing.T, db *store.Store, name string) (store.AuthUser, bool) {
	t.Helper()
	users, err := db.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	for _, u := range users {
		if u.Username == name {
			return u, true
		}
	}
	return store.AuthUser{}, false
}

// TestSetupBootstrapUserIsAdmin pins the admin-flag invariant: the first
// account created through the setup gate is the admin, and later accounts
// (added by the admin) are regular users.
func TestSetupBootstrapUserIsAdmin(t *testing.T) {
	db, httpSrv := adminFlagServer(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// Setup mode: unauthenticated first account.
	if code := postJSONStatus(t, client, httpSrv.URL+"/api/auth/users",
		`{"username":"admin","password":"secretpw"}`); code != 200 {
		t.Fatalf("bootstrap: %d", code)
	}
	// Log in as admin, add a helper.
	if code := postJSONStatus(t, client, httpSrv.URL+"/api/auth/login",
		`{"username":"admin","password":"secretpw"}`); code != 200 {
		t.Fatalf("login: %d", code)
	}
	if code := postJSONStatus(t, client, httpSrv.URL+"/api/auth/users",
		`{"username":"helper","password":"helperpw1"}`); code != 200 {
		t.Fatalf("admin add helper: %d", code)
	}

	admin, ok := userByName(t, db, "admin")
	if !ok || !admin.IsAdmin {
		t.Fatalf("bootstrap user must be admin: %+v (ok=%v)", admin, ok)
	}
	helper, ok := userByName(t, db, "helper")
	if !ok || helper.IsAdmin {
		t.Fatalf("admin-added user must NOT be admin: %+v (ok=%v)", helper, ok)
	}
}

// TestNonAdminCannotManageUsers is the horizontal-privilege-escalation repro
// from the 2026-10-19 external review: a regular (non-admin) session must
// NOT be able to remove users (anyone's, including its own), add users, or
// disable auth. Each attempt is a 403 AND the state must be unchanged.
func TestNonAdminCannotManageUsers(t *testing.T) {
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

	if code := deleteStatus(t, helper, httpSrv.URL+"/api/auth/users/admin"); code != http.StatusForbidden {
		t.Errorf("helper delete admin: got %d, want 403", code)
	}
	if code := deleteStatus(t, helper, httpSrv.URL+"/api/auth/users/helper"); code != http.StatusForbidden {
		t.Errorf("helper delete self: got %d, want 403", code)
	}
	if code := postJSONStatus(t, helper, httpSrv.URL+"/api/auth/users",
		`{"username":"evil","password":"evilevpw1"}`); code != http.StatusForbidden {
		t.Errorf("helper add user: got %d, want 403", code)
	}
	if code := postJSONStatus(t, helper, httpSrv.URL+"/api/auth/disable", "{}"); code != http.StatusForbidden {
		t.Errorf("helper disable auth: got %d, want 403", code)
	}

	// State must be exactly as before: both accounts exist, no "evil",
	// auth still enabled.
	if _, ok := userByName(t, db, "admin"); !ok {
		t.Error("admin account missing after helper attacks")
	}
	if _, ok := userByName(t, db, "helper"); !ok {
		t.Error("helper account missing after self-delete attempt")
	}
	if _, ok := userByName(t, db, "evil"); ok {
		t.Error("'evil' account was created by a non-admin")
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

// TestAdminRemovalAndPromotion: an admin CAN remove a regular user; when
// the LAST ADMIN is removed, the oldest remaining user is promoted in the
// same transaction (the install is never left without an admin); and the
// last user still cannot be removed at all.
func TestAdminRemovalAndPromotion(t *testing.T) {
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

	// Admin removes the regular user: allowed, no promotion needed.
	if code := deleteStatus(t, admin, httpSrv.URL+"/api/auth/users/helper"); code != http.StatusOK {
		t.Fatalf("admin remove helper: got %d, want 200", code)
	}
	if _, ok := userByName(t, db, "helper"); ok {
		t.Fatal("helper still exists after admin removal")
	}
	if a, _ := userByName(t, db, "admin"); !a.IsAdmin {
		t.Fatal("admin must keep the flag after removing a regular user")
	}

	// Admin re-adds helper, then removes SELF — the last admin. Allowed:
	// the oldest remaining user (helper) is promoted atomically.
	if code := postJSONStatus(t, admin, httpSrv.URL+"/api/auth/users",
		`{"username":"helper","password":"helperpw1"}`); code != 200 {
		t.Fatalf("admin re-add helper: %d", code)
	}
	if code := deleteStatus(t, admin, httpSrv.URL+"/api/auth/users/admin"); code != http.StatusOK {
		t.Fatalf("admin self-remove (last admin): got %d, want 200", code)
	}
	if _, ok := userByName(t, db, "admin"); ok {
		t.Fatal("admin account must be gone after self-removal")
	}
	helper, ok := userByName(t, db, "helper")
	if !ok {
		t.Fatal("helper missing after admin self-removal")
	}
	if !helper.IsAdmin {
		t.Fatal("oldest remaining user must be promoted to admin")
	}

	// The promoted helper is now the ONLY user: removal refused.
	hjar, _ := cookiejar.New(nil)
	hclient := &http.Client{Jar: hjar}
	if code := postJSONStatus(t, hclient, httpSrv.URL+"/api/auth/login",
		`{"username":"helper","password":"helperpw1"}`); code != 200 {
		t.Fatalf("helper login: %d", code)
	}
	req, _ := http.NewRequest(http.MethodDelete, httpSrv.URL+"/api/auth/users/helper", nil)
	resp, err := hclient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "last user") {
		t.Fatalf("last-user self-remove: got %d %s, want 400 'last user'", resp.StatusCode, body)
	}
	if n, _ := db.UserCount(); n != 1 {
		t.Fatalf("UserCount = %d, want 1 (last user must be protected)", n)
	}
}

// TestLegacyTokenMigrationUserIsAdmin: a pre-user-model install (single
// auth_token) migrates to the 'admin' account, which must carry the admin
// flag — otherwise a long-running legacy install would boot with zero
// admins and every account-management endpoint locked.
func TestLegacyTokenMigrationUserIsAdmin(t *testing.T) {
	db := newTestDB(t)
	const tok = "pm_abcdefGhijklMNopqr4567"
	hash, err := bcrypt.GenerateFromPassword([]byte(tok), bcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting("auth_token", string(hash)); err != nil {
		t.Fatal(err)
	}
	// Re-init the schema: this is what a server boot does on the old DB.
	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}
	admin, ok := userByName(t, db, "admin")
	if !ok {
		t.Fatal("legacy 'admin' account missing after migration")
	}
	if !admin.IsAdmin {
		t.Fatal("legacy-migrated 'admin' account must be the admin")
	}
}

// TestAdminColumnMigration: a DB created before the is_admin column existed
// (old users schema, two accounts) boots through InitSchema and comes out
// with the column added and the OLDEST user promoted — an existing install
// must never boot with zero admins.
func TestAdminColumnMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := store.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	// Build the PRE-migration schema by hand (no is_admin column).
	if _, err := db.Exec(`CREATE TABLE users (
		username TEXT PRIMARY KEY,
		password_hash TEXT NOT NULL,
		created_at TEXT
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users VALUES ('oldest', 'x', '2020-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users VALUES ('newer', 'y', '2021-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}

	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema on old-schema DB: %v", err)
	}

	oldest, ok := userByName(t, db, "oldest")
	if !ok || !oldest.IsAdmin {
		t.Fatalf("oldest user must be promoted to admin: %+v (ok=%v)", oldest, ok)
	}
	newer, ok := userByName(t, db, "newer")
	if !ok || newer.IsAdmin {
		t.Fatalf("newer user must stay a regular user: %+v (ok=%v)", newer, ok)
	}

	// Idempotent: a second boot must not change anything.
	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}
	newer, _ = userByName(t, db, "newer")
	if newer.IsAdmin {
		t.Fatal("second InitSchema must not promote a second admin")
	}
}

func deleteStatus(t *testing.T, client *http.Client, url string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// TestSetupBootstrapGate pins the 2026-10-20 external review fix:
// setup mode (unauthenticated first-account creation) is keyed off a
// VALID session, not raw cookie presence, and is a FRESH-INSTALL
// surface only.
//
//   - Fresh install + a dead pulsemon_session cookie (30-day TTL, or a
//     replayed one): bootstrap proceeds (200). The old cookie-presence
//     check made setup=false here and 403'd "Create First Account".
//   - Operator-disabled install (accounts wiped, auth_bootstrapped
//     set): unauthenticated account creation is refused (403) — the
//     one open-mode operation with a lockout consequence (the new
//     account is admin and re-enables auth server-wide). /api/auth/
//     status reports bootstrapped so the UI swaps the bootstrap button
//     for the CLI hint.
//   - The CLI path (AddUser, setupMode=false) stays the operator's
//     re-enable route in the disabled state.
func TestSetupBootstrapGate(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	// (1) Fresh install with a STALE cookie: present but dead (no such
	// session), so setup mode must still apply.
	req, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/api/auth/users",
		strings.NewReader(`{"username":"admin","password":"secretpw"}`))
	req.AddCookie(&http.Cookie{Name: authSessionName, Value: "stale-token-from-an-old-install"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fresh install + stale cookie: got %d, want 200 (bootstrap)", resp.StatusCode)
	}

	// Log in, then disable auth (wipes the account, keeps the
	// auth_bootstrapped flag).
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp, err = client.Post(httpSrv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"secretpw"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = client.Post(httpSrv.URL+"/api/auth/disable", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disable: %d", resp.StatusCode)
	}

	// status must report the disabled (bootstrapped) state so the UI
	// can swap the bootstrap button for the CLI hint.
	stResp, err := http.Get(httpSrv.URL + "/api/auth/status")
	if err != nil {
		t.Fatal(err)
	}
	stBody, _ := io.ReadAll(stResp.Body)
	stResp.Body.Close()
	var st struct {
		Enabled      bool `json:"enabled"`
		Bootstrapped bool `json:"bootstrapped"`
	}
	if err := json.Unmarshal(stBody, &st); err != nil {
		t.Fatalf("status unmarshal: %v", err)
	}
	if st.Enabled {
		t.Fatal("status.enabled = true after disable, want false")
	}
	if !st.Bootstrapped {
		t.Fatal("status.bootstrapped = false after disable, want true")
	}

	// (2) Disabled install: unauthenticated account creation is
	// refused — no LAN client can mint the admin account and re-enable
	// auth. With AND without the (now dead) session cookie.
	bare := &http.Client{}
	for _, stale := range []bool{false, true} {
		req, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/api/auth/users",
			strings.NewReader(`{"username":"intruder","password":"intrapass1"}`))
		if stale {
			req.AddCookie(&http.Cookie{Name: authSessionName, Value: "stale-token-from-an-old-install"})
		}
		r2, err := bare.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r2.Body.Close()
		label := "no cookie"
		if stale {
			label = "stale cookie"
		}
		if r2.StatusCode != http.StatusForbidden {
			t.Fatalf("disabled install, %s: got %d, want 403", label, r2.StatusCode)
		}
	}
	if n, _ := db.UserCount(); n != 0 {
		t.Fatalf("user count after refused creates = %d, want 0", n)
	}

	// (3) CLI re-enable (direct AddUser, setupMode=false) keeps working
	// in the disabled state.
	if err := srv.auth.AddUser("admin", "secretpw"); err != nil {
		t.Fatalf("CLI re-enable (AddUser) in disabled state: %v", err)
	}
	if !srv.auth.Enabled() {
		t.Fatal("auth not re-enabled after CLI AddUser")
	}
}

// TestCSRFCrossPortGate pins both arms of the cross-port CSRF gate
// (authGate): state-changing requests are refused on a non-same-origin
// Sec-Fetch-Site (the modern-browser signal — "same-site" included, i.e.
// a page on another PORT of the same IP) or a foreign Origin, and pass
// for same-origin browsers and for Origin-less non-browser clients
// (curl, server-to-server, the test suite), which cannot be a browser
// CSRF. (2026-10-20 external review — SFS arm; the Origin arm dates to
// 2026-10-13.)
func TestCSRFCrossPortGate(t *testing.T) {
	db := newTestDB(t)
	// Operator-disabled state: zero users + bootstrapped flag → the
	// documented "auth off = fully open" mode, so a POST that passes the
	// CSRF gate reaches the handler and 201s — a clean pass/fail signal.
	if err := db.SetSetting("auth_bootstrapped", "1"); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	postWith := func(name, sfs, origin string) int {
		body := `{"name":"` + name + `","target":"127.0.0.1","type":"icmp","tags":[],"interval_s":60,"timeout_ms":1000,"loss_warn":25,"down_after":2,"spike_mult":5}`
		req, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/api/sensors", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if sfs != "" {
			req.Header.Set("Sec-Fetch-Site", sfs)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// Pass: non-browser client (no SFS, no Origin) — the documented
	// curl / server-to-server path must keep working.
	if code := postWith("csrf-curl", "", ""); code != http.StatusCreated {
		t.Fatalf("no SFS, no Origin (curl): got %d, want 201", code)
	}
	// Pass: same-origin browser (the dashboard UI itself), with and
	// without a matching Origin.
	if code := postWith("csrf-same-origin", "same-origin", ""); code != http.StatusCreated {
		t.Fatalf("SFS same-origin: got %d, want 201", code)
	}
	if code := postWith("csrf-same-origin-orig", "same-origin", httpSrv.URL); code != http.StatusCreated {
		t.Fatalf("SFS same-origin + matching Origin: got %d, want 201", code)
	}
	// Block: the cross-port vector — a page on another port of the same
	// IP is same-site, and modern browsers report exactly that.
	if code := postWith("csrf-same-site", "same-site", ""); code != http.StatusForbidden {
		t.Fatalf("SFS same-site: got %d, want 403", code)
	}
	// Block: cross-site (includes the DNS-rebinding page).
	if code := postWith("csrf-cross-site", "cross-site", ""); code != http.StatusForbidden {
		t.Fatalf("SFS cross-site: got %d, want 403", code)
	}
	// Block: foreign Origin (the pre-existing arm, 2026-10-13).
	if code := postWith("csrf-foreign-origin", "", "http://192.168.1.10:8080"); code != http.StatusForbidden {
		t.Fatalf("foreign Origin: got %d, want 403", code)
	}
	// GETs are exempt from the gate — reads stay open.
	req, _ := http.NewRequest(http.MethodGet, httpSrv.URL+"/api/sensors", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET with SFS cross-site: got %d, want 200 (reads exempt)", resp.StatusCode)
	}
}

// TestLoginOversizedBodyIs413 drives the real server: a valid login body that
// exceeds the 1 MiB gate limit must be refused with 413 "request body too
// large" — like every other JSON handler — not a 400 that hides the size
// limit. Pre-fix, handleAuthLogin mapped every decode error to 400, so this
// test fails on the unfixed build.
func TestLoginOversizedBodyIs413(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()
	// Bootstrapped install (zero users, auth disabled): endpoints are open.
	db.SetSetting("auth_bootstrapped", "1")

	// Valid JSON, ~2 MiB: a 1 MiB password field of padding.
	pad := strings.Repeat("x", 1<<20)
	body := `{"username":"alice","password":"` + pad + `"}`
	resp, err := http.Post(httpSrv.URL+"/api/auth/login", "application/json",
		strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized login body: got %d, want 413", resp.StatusCode)
	}

	// A missing field is still a plain 400 with the credential message, and
	// a malformed (undersized) body is still a 400.
	resp, err = http.Post(httpSrv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"alice"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing password: got %d, want 400", resp.StatusCode)
	}
	resp, err = http.Post(httpSrv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`not json`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed body: got %d, want 400", resp.StatusCode)
	}
}

// TestIsAdminCachedWithinTTL (2026-10-30 review #4): the admin-flag answer
// is cached per username for userOKTTL — a flag flip in the DB is served
// stale inside the window and honored once the TTL expires. Pre-fix
// IsAdmin hit SQLite on every call; its sibling checks (Enabled,
// userExistsCached) were already TTL-cached.
func TestIsAdminCachedWithinTTL(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	if _, err := db.Exec("INSERT INTO users (username, password_hash, created_at, is_admin) VALUES ('alice', 'x', '2026-01-01T00:00:00Z', 1)"); err != nil {
		t.Fatalf("seed alice: %v", err)
	}
	if !a.IsAdmin("alice") {
		t.Fatal("IsAdmin = false for a seeded admin (want true; also primes the cache)")
	}
	// Flip the flag directly in the DB: the cached answer must be served
	// within the TTL window (no re-query).
	if _, err := db.Exec("UPDATE users SET is_admin = 0 WHERE username = 'alice'"); err != nil {
		t.Fatalf("flip flag: %v", err)
	}
	if !a.IsAdmin("alice") {
		t.Fatal("IsAdmin = false within the TTL of the flip — the stale cached answer (true) is expected here")
	}
	time.Sleep(userOKTTL + 100*time.Millisecond)
	if a.IsAdmin("alice") {
		t.Fatal("IsAdmin = true after the TTL expired — the flipped flag (0) must be honored")
	}
}

// TestIsAdminFailsClosedOnDBError (2026-10-30 review #4): with the users
// table gone and no cached answer, IsAdmin must return false — a read
// error must never grant admin (the deliberate opposite of userExists,
// which fails OPEN so a DB hiccup cannot log the operator out).
func TestIsAdminFailsClosedOnDBError(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	if _, err := db.Exec("DROP TABLE users"); err != nil {
		t.Fatalf("drop users: %v", err)
	}
	if a.IsAdmin("ghost") {
		t.Fatal("IsAdmin = true on a read error — must fail closed")
	}
}

// TestIsAdminInvalidatedOnPromotion (2026-10-30 review #4): RemoveUser's
// last-admin promotion must clear the admin cache — the promoted user's
// cached "non-admin" (primed below) must not 403 their next admin request
// for up to userOKTTL. Pins the invalidation the cache fix introduced
// (refreshEnabledNow clears adminCache at the mutation sites).
func TestIsAdminInvalidatedOnPromotion(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	if _, err := db.Exec(`INSERT INTO users (username, password_hash, created_at, is_admin)
		VALUES ('alice', 'x', '2026-01-01T00:00:00Z', 1),
		       ('bob',   'x', '2026-01-02T00:00:00Z', 0)`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if !a.IsAdmin("alice") {
		t.Fatal("seed: alice must be admin")
	}
	if a.IsAdmin("bob") {
		t.Fatal("seed: bob must not be admin (this call primes bob's cached false)")
	}
	if err := a.RemoveUser("alice"); err != nil {
		t.Fatalf("remove last admin: %v", err)
	}
	if !a.IsAdmin("bob") {
		t.Fatal("bob is not admin immediately after the last admin's removal — the promotion must clear his cached non-admin")
	}
}
