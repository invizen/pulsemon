package main

// Cookie-shadowing regression tests (2026-11-25 external review MINOR-17).
//
// RFC 6265 does not isolate cookies by port: every app on the same
// homelab IP shares one cookie jar per domain, and browsers sort
// same-name cookies by PATH length (longest first) when sending them.
// A sibling app that sets pulsemon_session=x; Path=/api (or a sibling
// subdomain setting the same name) therefore sends its cookie AHEAD of
// Pulsemon's Path=/ cookie on every /api/* request. r.Cookie() returns
// only the FIRST same-name cookie, so the stranger's value won the
// session lookup: a browser holding a perfectly valid session got 401
// on every gated route (the login→401 loop), /api/auth/status reported
// unauthenticated, healthz hid the version, and logout dropped the
// stranger's value while the operator's session survived.
//
// The fix: every read site iterates ALL same-name cookies and accepts
// through the session store (sessionCookieValues / sessionCookieFrom) —
// store acceptance is the only discriminator cookie order cannot spoof.
// History: docs/DECISIONS.md → session-cookie-shadowing.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// shadowCookieRequest builds a request whose Cookie header carries two
// same-name cookies in the exact order a browser sends them when the
// shadowing app's longer-Path cookie sorts ahead of Pulsemon's: the
// stranger's value FIRST, the operator's valid token second.
func shadowCookieRequest(t *testing.T, method, path, shadow, valid string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Cookie", authSessionName+"="+shadow+"; "+authSessionName+"="+valid)
	return req
}

// newShadowServer builds a server with one admin account and a live
// session, returning the server and the session token.
func newShadowServer(t *testing.T) (*Server, string) {
	t.Helper()
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	if err := srv.auth.AddUser(context.Background(), "admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
	tok, ok, _ := srv.auth.CreateSession(context.Background(), "admin", "secretpw", false)
	if !ok {
		t.Fatal("CreateSession failed")
	}
	return srv, tok
}

const shadowValue = "shadow-value-from-sibling-app"

// TestSessionCookieValues pins the iterator contract: every same-name
// value in client send order, other cookie names ignored, empty when
// none.
func TestSessionCookieValues(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/sensors", nil)
	req.Header.Set("Cookie", "other=1; "+authSessionName+"=v1; x=2; "+authSessionName+"=v2")
	got := sessionCookieValues(req)
	if len(got) != 2 || got[0] != "v1" || got[1] != "v2" {
		t.Fatalf("sessionCookieValues: %v, want [v1 v2]", got)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Cookie", "other=1")
	if got := sessionCookieValues(req2); len(got) != 0 {
		t.Fatalf("no session cookies: %v, want empty", got)
	}

	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := sessionCookieValues(req3); got != nil {
		t.Fatalf("no Cookie header: %v, want nil", got)
	}
}

// TestShadowedSessionCookieGate is the DoS pin: the browser's send order
// (shadowing cookie FIRST, valid token second) must authenticate.
// Pre-fix the gate, /api/auth/status, and healthz all read only the
// first cookie, so a valid session read as absent on every /api/*
// request — the login→401 loop.
func TestShadowedSessionCookieGate(t *testing.T) {
	srv, tok := newShadowServer(t)

	// 1. A gated route: the valid cookie behind the shadow must win.
	rr := httptest.NewRecorder()
	srv.authGate().ServeHTTP(rr, shadowCookieRequest(t, http.MethodGet, "/api/sensors", shadowValue, tok))
	if rr.Code != http.StatusOK {
		t.Fatalf("shadowed /api/sensors: %d, want 200 (valid cookie must beat the shadow)", rr.Code)
	}

	// 2. /api/auth/status (gate-exempt): the sessionFrom cookie
	// fallback is the ONLY check here — dispatch through the mux so
	// the gate's context stash can't mask it (admin_gate_test.go
	// convention). The operator reads as authenticated.
	rr = httptest.NewRecorder()
	srv.Mux().ServeHTTP(rr, shadowCookieRequest(t, http.MethodGet, "/api/auth/status", shadowValue, tok))
	var st authStatusPayload
	if err := json.NewDecoder(rr.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if rr.Code != http.StatusOK || !st.Authed || st.User != "admin" {
		t.Fatalf("shadowed /api/auth/status: %d authed=%v user=%q, want 200/authed/admin", rr.Code, st.Authed, st.User)
	}

	// 3. healthz version reveal: the live session must be seen.
	rr = httptest.NewRecorder()
	srv.authGate().ServeHTTP(rr, shadowCookieRequest(t, http.MethodGet, "/api/healthz", shadowValue, tok))
	var hz map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&hz); err != nil {
		t.Fatal(err)
	}
	if rr.Code != http.StatusOK || hz["version"] != Version {
		t.Fatalf("shadowed /api/healthz: %d version=%v, want 200/%q (a live session reveals it)", rr.Code, hz["version"], Version)
	}

	// 4. Negative control: a shadow with NO valid cookie behind it is
	// still a 401 — acceptance is by store lookup, not cookie count.
	rr = httptest.NewRecorder()
	srv.authGate().ServeHTTP(rr, shadowCookieRequest(t, http.MethodGet, "/api/sensors", shadowValue, "another-bogus"))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("bogus-only cookies: %d, want 401", rr.Code)
	}
}

// TestShadowedLogoutDropsValidSession pins the logout arm: a shadowed
// logout must drop the operator's REAL session. Pre-fix only the first
// cookie's value (the stranger's) was dropped, so the operator's
// session survived a logout.
func TestShadowedLogoutDropsValidSession(t *testing.T) {
	srv, tok := newShadowServer(t)

	// No Origin header: a non-browser client, which the CSRF gate
	// allows (csrf_test.go pins that arm).
	rr := httptest.NewRecorder()
	srv.authGate().ServeHTTP(rr, shadowCookieRequest(t, http.MethodPost, "/api/auth/logout", shadowValue, tok))
	if rr.Code != http.StatusOK {
		t.Fatalf("shadowed logout: %d, want 200", rr.Code)
	}

	// The operator's session must be GONE now.
	req := httptest.NewRequest(http.MethodGet, "/api/sensors", nil)
	req.AddCookie(&http.Cookie{Name: authSessionName, Value: tok})
	rr = httptest.NewRecorder()
	srv.authGate().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("after shadowed logout: %d, want 401 (the real session must be dropped)", rr.Code)
	}
}
