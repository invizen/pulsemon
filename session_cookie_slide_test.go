package main

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestFix_SessionCookieSlides pins the sliding-cookie fix: the session
// cookie was issued once at login with a fixed Max-Age=30d, and
// ValidSession slid only the IN-MEMORY expiry — so the browser deleted
// the cookie exactly 30 days after login even for a daily user, defeating
// the sliding-session design (server expiry = last-use+30d is always >=
// cookie expiry = login+30d, so the cookie always died first). The gate
// now re-issues the SAME token once the cookie ages past half the TTL
// (CookieRenewalDue), and SessionUser (the gate-exempt /api/auth/status
// path) slides like ValidSession. Fails pre-fix (no Set-Cookie on an
// aged session; SessionUser leaves the backdated expiry alone).
func TestFix_SessionCookieSlides(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	if err := srv.auth.AddUser("admin", "secretpw"); err != nil {
		t.Fatal(err)
	}

	// Login: cookie issued, cookieIssued = now.
	resp, err := client.Post(httpSrv.URL+"/api/auth/login", "application/json", strings.NewReader(`{"username":"admin","password":"secretpw"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", resp.StatusCode)
	}

	// A fresh (young) session must NOT re-issue: no Set-Cookie on a
	// normal authenticated request (no per-poll header churn).
	resp, err = client.Get(httpSrv.URL + "/api/sensors")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sensors: %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == authSessionName {
			t.Fatalf("young session re-issued a cookie on a plain request: %v (at most one per half-TTL of activity)", c)
		}
	}

	// Age the cookie past half the TTL (16d) — as a daily user's cookie
	// would be on day 16. The next authenticated request must re-issue
	// the SAME token with a fresh 30-day Max-Age.
	su, _ := url.Parse(httpSrv.URL)
	var tok string
	for _, c := range jar.Cookies(su) {
		if c.Name == authSessionName {
			tok = c.Value
		}
	}
	if tok == "" {
		t.Fatal("no session cookie in jar")
	}
	srv.auth.mu.Lock()
	s := srv.auth.sessions[tok]
	s.cookieIssued = time.Now().Add(-16 * 24 * time.Hour)
	srv.auth.sessions[tok] = s
	srv.auth.mu.Unlock()

	resp, err = client.Get(httpSrv.URL + "/api/sensors")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sensors after aged cookie: %d", resp.StatusCode)
	}
	var reissued *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == authSessionName {
			reissued = c
		}
	}
	if reissued == nil {
		t.Fatal("aged session (cookie 16d old): no Set-Cookie re-issue — the browser would delete the cookie at day 30 and log the active user out (the sliding design is defeated)")
	}
	if reissued.Value != tok {
		t.Errorf("re-issued cookie value = %q, want the SAME token %q (refresh, not rotate)", reissued.Value, tok)
	}
	if reissued.MaxAge != int(authSessionTTL.Seconds()) {
		t.Errorf("re-issued cookie MaxAge = %d, want %d (full TTL from now)", reissued.MaxAge, int(authSessionTTL.Seconds()))
	}

	// A second request right after: no immediate re-issue (the stamp
	// was refreshed by the re-issue).
	resp, err = client.Get(httpSrv.URL + "/api/sensors")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == authSessionName {
			t.Fatalf("cookie re-issued again immediately (the stamp must reset after a re-issue): %v", c)
		}
	}

	// SessionUser (the gate-exempt /api/auth/status path) must slide like
	// ValidSession: backdate the expiry an hour, call SessionUser, and the
	// expiry must be back at now+TTL.
	srv.auth.mu.Lock()
	s = srv.auth.sessions[tok]
	s.expiry = time.Now().Add(authSessionTTL - time.Hour)
	srv.auth.sessions[tok] = s
	srv.auth.mu.Unlock()
	if _, ok := srv.auth.SessionUser(tok); !ok {
		t.Fatal("SessionUser rejected a live session")
	}
	srv.auth.mu.Lock()
	after := srv.auth.sessions[tok].expiry
	srv.auth.mu.Unlock()
	want := time.Now().Add(authSessionTTL)
	if after.Before(want.Add(-2*time.Second)) || after.After(want.Add(2*time.Second)) {
		t.Errorf("SessionUser did not slide expiry to now+TTL: got %v, want ~ %v", after, want)
	}
}
