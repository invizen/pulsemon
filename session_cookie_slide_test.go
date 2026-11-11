package main

import (
	"context"

	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestFix_SessionCookieSlides pins the sliding-cookie fix: the session
// cookie was issued once at login with a fixed Max-Age=7d, and
// ValidSession slid only the IN-MEMORY expiry — so the browser deleted
// the cookie exactly 7 days after login even for a daily user, defeating
// the sliding-session design (server expiry = last-use+7d is always >=
// cookie expiry = login+7d, so the cookie always died first). The gate
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
	if err := srv.auth.AddUser(context.Background(), "admin", "secretpw"); err != nil {
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

	// Age the cookie past half the TTL (5d) — as a daily user's cookie
	// would be on day 5. The next authenticated request must re-issue
	// the SAME token with a fresh 7-day Max-Age.
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
	s.cookieIssued = time.Now().Add(-5 * 24 * time.Hour)
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
		t.Fatal("aged session (cookie 5d old): no Set-Cookie re-issue — the browser would delete the cookie at day 7 and log the active user out (the sliding design is defeated)")
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

// TestFix_RenewalCookieCappedByMaxAge (review 2026-11-11 #8): the re-issue
// lifetime is min(authSessionTTL, created + authSessionMaxAge − now).
// Uncapped, a renewal on day 29.x handed the browser a fresh Max-Age=7d
// cookie for a session the server rejects within a day — the browser kept
// sending a cookie it believed was a week young while every request 401d
// at the absolute cap. Capped, the browser drops the cookie when the
// session actually dies; a session at/past the cap gets no renewal at all.
//
// Method-level: CookieRenewalDue's third return is the capped lifetime
// (full TTL for a young session, ≈1d at day 29, 0/due=false at the cap).
// Gate-level: the Set-Cookie on a day-29 renewal carries Max-Age ≈ 1d —
// NOT the full 7d — and the value is the same token.
func TestFix_RenewalCookieCappedByMaxAge(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()
	if err := srv.auth.AddUser(context.Background(), "admin", "secretpw"); err != nil {
		t.Fatal(err)
	}

	age := func(tok string, created time.Time, issued time.Time) {
		srv.auth.mu.Lock()
		s := srv.auth.sessions[tok]
		s.created = created
		s.cookieIssued = issued
		// Keep the sliding expiry comfortably alive: the renewal question
		// is the ABSOLUTE cap, not the idle window.
		s.expiry = time.Now().Add(authSessionTTL)
		srv.auth.sessions[tok] = s
		srv.auth.mu.Unlock()
	}

	// Method level: young session → full TTL on renewal.
	tok, ok := srv.auth.CreateSession(context.Background(), "admin", "secretpw", false)
	if !ok {
		t.Fatal("CreateSession failed")
	}
	age(tok, time.Now().Add(-10*24*time.Hour), time.Now().Add(-authSessionTTL/2))
	if due, _, maxAge := srv.auth.CookieRenewalDue(tok); !due || maxAge != authSessionTTL {
		t.Fatalf("day-10 renewal: due=%v maxAge=%v, want due + full %v", due, maxAge, authSessionTTL)
	}
	// Day 29 + 1h (→ ~23h remaining): renewal due, lifetime capped to the
	// remaining absolute lifetime, not the full TTL.
	age(tok, time.Now().Add(-29*24*time.Hour-time.Hour), time.Now().Add(-authSessionTTL/2))
	if due, _, maxAge := srv.auth.CookieRenewalDue(tok); !due || maxAge > 24*time.Hour || maxAge < 22*time.Hour {
		t.Fatalf("day-29 renewal: due=%v maxAge=%v, want due + ~23h cap (not the full %v)", due, maxAge, authSessionTTL)
	}
	// At/past the cap: no renewal (the session is dead to validation
	// anyway; advertising any cookie life would be a lie).
	age(tok, time.Now().Add(-30*24*time.Hour-time.Hour), time.Now().Add(-authSessionTTL/2))
	if due, _, maxAge := srv.auth.CookieRenewalDue(tok); due || maxAge != 0 {
		t.Fatalf("past-cap renewal: due=%v maxAge=%v, want no renewal", due, maxAge)
	}

	// Gate level: real login, age to day 29 (+1d → ~1d remaining), one
	// authenticated request must re-issue with Max-Age ≈ 1d.
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp, err := client.Post(httpSrv.URL+"/api/auth/login", "application/json", strings.NewReader(`{"username":"admin","password":"secretpw"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	u, _ := url.Parse(httpSrv.URL)
	var tok2 string
	for _, c := range jar.Cookies(u) {
		if c.Name == authSessionName {
			tok2 = c.Value
		}
	}
	if tok2 == "" {
		t.Fatal("no session cookie in jar")
	}
	age(tok2, time.Now().Add(-29*24*time.Hour), time.Now().Add(-authSessionTTL/2))
	resp, err = client.Get(httpSrv.URL + "/api/sensors")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sensors at day 29: %d", resp.StatusCode)
	}
	var reissued *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == authSessionName {
			reissued = c
		}
	}
	if reissued == nil {
		t.Fatal("day-29 aged cookie got no re-issue")
	}
	if reissued.Value != tok2 {
		t.Errorf("re-issue rotated the token: %q", reissued.Value)
	}
	wantMax := int((24 * time.Hour).Seconds())
	if reissued.MaxAge <= 0 || reissued.MaxAge > wantMax {
		t.Errorf("re-issue Max-Age = %d, want ≈ %d (capped to the remaining absolute lifetime, NOT the full %d)", reissued.MaxAge, wantMax, int(authSessionTTL.Seconds()))
	}
}
