package main

// NIT-27 pins: the gate's sliding-cookie renewal must not ride responses
// that end the session (logout, disable), and a self-delete must clear the
// renewed dead cookie. History: docs/DECISIONS.md → cookie-renewal-session-end.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ageSessionCookie ages the session's cookie past half-TTL so the gate's
// sliding renewal is due on the next authenticated request.
func ageSessionCookie(t *testing.T, srv *Server, tok string) {
	t.Helper()
	srv.auth.mu.Lock()
	sess := srv.auth.sessions[tok]
	sess.cookieIssued = time.Now().Add(-authSessionTTL)
	srv.auth.sessions[tok] = sess
	srv.auth.mu.Unlock()
}

// mustAddUser adds a dashboard user (first is admin).
func mustAddUser(t *testing.T, srv *Server, user, pw string) {
	t.Helper()
	if err := srv.auth.AddUser(context.Background(), user, pw); err != nil {
		t.Fatal(err)
	}
}

// mustSession mints a live session for user.
func mustSession(t *testing.T, srv *Server, user, pw string) string {
	t.Helper()
	tok, ok, _ := srv.auth.CreateSession(context.Background(), user, pw, false)
	if !ok {
		t.Fatalf("CreateSession(%s)", user)
	}
	return tok
}

// setCookies parses the response's Set-Cookie headers for the session
// cookie (empty value = the clearing form).
func setCookies(t *testing.T, rr *httptest.ResponseRecorder) []string {
	t.Helper()
	var out []string
	for _, raw := range rr.Result().Header.Values("Set-Cookie") {
		c, err := http.ParseSetCookie(raw)
		if err != nil {
			t.Fatalf("unparseable Set-Cookie %q: %v", raw, err)
		}
		if c.Name == authSessionName {
			out = append(out, c.Value)
		}
	}
	return out
}

// TestLogoutSkipsSlidingRenewal: an aged session logging out must get
// exactly ONE Set-Cookie — the clear. Pre-fix the gate re-issued the token
// (renewal) ahead of the handler's clear: two Set-Cookies for one name, and
// a re-issued token for a session about to die.
func TestLogoutSkipsSlidingRenewal(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	mustAddUser(t, srv, "admin", "secretpw")
	tok := mustSession(t, srv, "admin", "secretpw")
	ageSessionCookie(t, srv, tok)

	req := httptest.NewRequest("POST", "/api/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: authSessionName, Value: tok})
	rr := httptest.NewRecorder()
	srv.authGate().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("logout: %d", rr.Code)
	}
	cookies := setCookies(t, rr)
	if len(cookies) != 1 {
		t.Fatalf("logout Set-Cookie count = %d (%v); want 1 (the clear, no renewal)", len(cookies), cookies)
	}
	if cookies[0] != "" {
		t.Fatalf("logout cookie value = %q; want empty (clear)", cookies[0])
	}
}

// TestDisableSkipsSlidingRenewal: same contract on /api/auth/disable — the
// last authenticated response must carry only the clearing cookie.
func TestDisableSkipsSlidingRenewal(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	mustAddUser(t, srv, "admin", "secretpw")
	mustAddUser(t, srv, "viewer", "viewerpw")
	tok := mustSession(t, srv, "admin", "secretpw")
	ageSessionCookie(t, srv, tok)

	req := httptest.NewRequest("POST", "/api/auth/disable", strings.NewReader(`{"current_password":"secretpw"}`))
	req.AddCookie(&http.Cookie{Name: authSessionName, Value: tok})
	rr := httptest.NewRecorder()
	srv.authGate().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", rr.Code, rr.Body.String())
	}
	cookies := setCookies(t, rr)
	if len(cookies) != 1 {
		t.Fatalf("disable Set-Cookie count = %d (%v); want 1 (the clear, no renewal)", len(cookies), cookies)
	}
	if cookies[0] != "" {
		t.Fatalf("disable cookie value = %q; want empty (clear)", cookies[0])
	}
}

// TestSelfDeleteClearsRenewedCookie: an admin deleting their own account
// with an aged session must get the clearing cookie — pre-fix the gate
// renewed the token moments before the delete and the response carried no
// Set-Cookie at all, so the browser kept presenting the dead renewed token.
func TestSelfDeleteClearsRenewedCookie(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	mustAddUser(t, srv, "admin", "secretpw")
	mustAddUser(t, srv, "viewer", "viewerpw")
	tok := mustSession(t, srv, "admin", "secretpw")
	ageSessionCookie(t, srv, tok)

	req := httptest.NewRequest("DELETE", "/api/auth/users/admin", strings.NewReader(`{"current_password":"secretpw"}`))
	req.AddCookie(&http.Cookie{Name: authSessionName, Value: tok})
	rr := httptest.NewRecorder()
	srv.authGate().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("self-delete: %d %s", rr.Code, rr.Body.String())
	}
	cookies := setCookies(t, rr)
	if len(cookies) != 1 || cookies[0] != "" {
		t.Fatalf("self-delete Set-Cookie = %v; want exactly [\"\"] (the clear)", cookies)
	}
}

// TestSelfDeleteOtherUserNoCookie: deleting someone else's account must NOT
// clear the caller's (live) cookie — the clear is self-delete-only.
func TestSelfDeleteOtherUserNoCookie(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	mustAddUser(t, srv, "admin", "secretpw")
	mustAddUser(t, srv, "viewer", "viewerpw")
	mustAddUser(t, srv, "third", "thirdpw1")
	tok := mustSession(t, srv, "admin", "secretpw")

	req := httptest.NewRequest("DELETE", "/api/auth/users/viewer", strings.NewReader(`{"current_password":"secretpw"}`))
	req.AddCookie(&http.Cookie{Name: authSessionName, Value: tok})
	rr := httptest.NewRecorder()
	srv.authGate().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete other: %d %s", rr.Code, rr.Body.String())
	}
	if cookies := setCookies(t, rr); len(cookies) != 0 {
		t.Fatalf("delete-other Set-Cookie = %v; want none (caller session is live)", cookies)
	}
}

// TestRenewalStillIssuesOnNormalTraffic: positive control — an aged session
// on an ordinary authenticated read MUST still get the renewal (the skip is
// logout/disable-only, not a global renewal kill).
func TestRenewalStillIssuesOnNormalTraffic(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	mustAddUser(t, srv, "admin", "secretpw")
	tok := mustSession(t, srv, "admin", "secretpw")
	ageSessionCookie(t, srv, tok)

	req := httptest.NewRequest("GET", "/api/sensors", nil)
	req.AddCookie(&http.Cookie{Name: authSessionName, Value: tok})
	rr := httptest.NewRecorder()
	srv.authGate().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("sensors: %d", rr.Code)
	}
	cookies := setCookies(t, rr)
	if len(cookies) != 1 || cookies[0] != tok {
		t.Fatalf("normal-traffic Set-Cookie = %v; want [%s] (the renewal)", cookies, tok)
	}
}
