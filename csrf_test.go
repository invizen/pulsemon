package main

// Cross-port CSRF regression tests (2026-10-13 external review, finding 13).
//
// The session cookie is SameSite=Strict, but per RFC 6265bis "same-site" is
// scheme+host — the PORT is not part of the site. In a homelab, every other
// web app on the same IP is same-SITE to pulsemon, so a page on
// 192.168.1.10:8080 can fire a simple credentials-including POST at
// 192.168.1.10:9299 (empty body, no custom headers → no CORS preflight)
// and the browser WILL attach the session cookie. authGate therefore
// rejects any non-GET/HEAD request whose Origin host does not match the
// request Host; requests without an Origin (curl, server-to-server) pass.

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

func postJSONStatus(t *testing.T, client *http.Client, url, body string) int {
	t.Helper()
	resp, err := client.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// bootstrapAdmin creates the first account so the server leaves setup mode
// (auth enabled) — newTestDB starts with zero users, and in setup mode the
// allowlist 403s everything except the bootstrap surface, which would make
// the origin-gate expectations below ambiguous.
func bootstrapAdmin(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	if code := postJSONStatus(t, client, baseURL+"/api/auth/users",
		`{"username":"admin","password":"secretpw"}`); code != 200 {
		t.Fatalf("bootstrap: %d", code)
	}
}

// TestOriginGateBlocksCrossPortSameIP covers the gate on a no-session
// endpoint (logout is in the authGate allowlist): a same-IP page on
// another port is refused, a same-origin page and a no-Origin client
// (curl) pass.
func TestOriginGateBlocksCrossPortSameIP(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()
	host := strings.TrimPrefix(httpSrv.URL, "http://")
	originHost := strings.SplitN(host, ":", 2)[0]

	client := &http.Client{}
	bootstrapAdmin(t, client, httpSrv.URL)

	// 1. Cross-port same-IP Origin (the CSRF vector) → 403.
	req, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/api/auth/logout", strings.NewReader(""))
	req.Header.Set("Origin", "http://"+originHost+":8080")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-port Origin: got %d, want 403", resp.StatusCode)
	}

	// 2. Same-origin Origin → allowed.
	req, _ = http.NewRequest(http.MethodPost, httpSrv.URL+"/api/auth/logout", strings.NewReader(""))
	req.Header.Set("Origin", httpSrv.URL)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("same-origin Origin: got %d, want 200", resp.StatusCode)
	}

	// 3. No Origin (curl / server-to-server) → allowed.
	resp, err = client.Post(httpSrv.URL+"/api/auth/logout", "", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("no Origin: got %d, want 200", resp.StatusCode)
	}
}

// TestOriginGateBlocksCSRFWithSession is the true attack shape: the victim
// has a valid session (the browser attaches the SameSite=Strict cookie to a
// same-site cross-port request), and a page on another port of the same IP
// fires POST /api/auth/disable — the destructive endpoint that wipes every
// dashboard account. The gate must refuse it AND the disable must not
// have happened.
func TestOriginGateBlocksCSRFWithSession(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()
	host := strings.TrimPrefix(httpSrv.URL, "http://")
	originHost := strings.SplitN(host, ":", 2)[0]

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// Bootstrap an account and log in (session cookie now in the jar).
	bootstrapAdmin(t, client, httpSrv.URL)
	if code := postJSONStatus(t, client, httpSrv.URL+"/api/auth/login",
		`{"username":"admin","password":"secretpw"}`); code != 200 {
		t.Fatalf("login: %d", code)
	}

	// THE ATTACK: cross-port same-IP page, victim's cookie attached.
	req, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/api/auth/disable", strings.NewReader(""))
	req.Header.Set("Origin", "http://"+originHost+":8080")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("CSRF disable: got %d, want 403", resp.StatusCode)
	}

	// Auth must still be enabled — the disable did NOT execute.
	resp, err = client.Get(httpSrv.URL + "/api/auth/status")
	if err != nil {
		t.Fatal(err)
	}
	var st authStatusPayload
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !st.Enabled {
		t.Fatal("auth was disabled by the blocked CSRF request")
	}

	// Control: the same request from the dashboard's own origin passes.
	if code := postJSONStatus(t, client, httpSrv.URL+"/api/auth/disable",
		`{}`); code != 200 {
		t.Fatalf("same-origin disable: got %d, want 200", code)
	}
}

// TestOriginGateAllowsCrossOriginGET pins that the gate only polices
// state-changing methods — a cross-origin read (link, image, fetch
// without credentials) is unaffected.
func TestOriginGateAllowsCrossOriginGET(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()
	host := strings.TrimPrefix(httpSrv.URL, "http://")
	originHost := strings.SplitN(host, ":", 2)[0]

	bootstrapAdmin(t, &http.Client{}, httpSrv.URL)

	req, _ := http.NewRequest(http.MethodGet, httpSrv.URL+"/api/sensors", nil)
	req.Header.Set("Origin", "http://"+originHost+":8080")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// Auth-enabled API read without a session: 401 — NOT 403, which the
	// origin gate (or setup mode) would return.
	if resp.StatusCode == http.StatusForbidden {
		t.Fatal("cross-origin GET was refused by the origin gate")
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cross-origin GET: got %d, want 401", resp.StatusCode)
	}
}

// TestOriginGateNullOriginRefused pins that the "null" origin (sandboxed
// iframes) can never match a request host.
func TestOriginGateNullOriginRefused(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	req, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/api/auth/logout", strings.NewReader(""))
	req.Header.Set("Origin", "null")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("null Origin: got %d, want 403", resp.StatusCode)
	}
}

// TestOriginGateProxyPreservedHost pins the reverse-proxy path: Caddy
// (pulsemon.invizen.com → pulsemon:9299) forwards the ORIGINAL Host header,
// so the browser's Origin host and r.Host agree and legitimate saves keep
// working through TLS termination.
func TestOriginGateProxyPreservedHost(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	bootstrapAdmin(t, &http.Client{}, httpSrv.URL)

	req, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/api/auth/logout", strings.NewReader(""))
	req.Host = "pulsemon.example.com" // what a Host-preserving proxy forwards
	req.Header.Set("Origin", "https://pulsemon.example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy-preserved Host: got %d, want 200", resp.StatusCode)
	}
}
