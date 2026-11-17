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
	"bufio"
	"encoding/json"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	neturl "net/url"
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

// TestOriginGateNullOriginEmptyHostRefused (2026-11-17 external review #7)
// pins the degenerate corner of the Origin arm: Origin: null parses with an
// EMPTY host, and an HTTP/1.0 request with no Host header (legal
// pre-HTTP/1.1 — the Go server leaves r.Host == "") made
// EqualFold("", "") read as a MATCH. The gate must fail closed there. No
// browser sends Host-less HTTP/1.0, and a non-browser client needs no
// Origin to pass (the arm is skipped when Origin is absent), so this is
// pure fail-closed hygiene: the Origin arm must never treat "no origin
// host" as equal to "no request host".
func TestOriginGateNullOriginEmptyHostRefused(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	// Leave setup mode: with zero users the setup allowlist 403s
	// everything except the bootstrap surface, which would make the
	// origin-gate expectations below ambiguous (bootstrapAdmin uses the
	// stdlib client — a Host-bearing, Origin-less POST — so it passes the
	// gate and creates the first account).
	bootstrapAdmin(t, &http.Client{}, httpSrv.URL)

	// 1. The degenerate case: raw HTTP/1.0, NO Host header, Origin: null
	//    → 403. (The stdlib client always sends a Host header, so this
	//    shape is only reachable over a raw connection.)
	if code := rawHTTP10Post(t, httpSrv.URL+"/api/auth/logout", map[string]string{"Origin": "null"}); code != http.StatusForbidden {
		t.Fatalf("Origin: null + empty Host: got %d, want 403", code)
	}
	// 2. Control: the same request WITHOUT an Origin header passes the
	//    gate (the arm is skipped for non-browser clients) — proves the
	//    403 above comes from the Origin arm, not from the missing Host.
	if code := rawHTTP10Post(t, httpSrv.URL+"/api/auth/logout", nil); code != http.StatusOK {
		t.Fatalf("Origin-less HTTP/1.0 request: got %d, want 200 (Origin arm skipped)", code)
	}
}

// rawHTTP10Post sends a raw HTTP/1.0 POST over a bare TCP connection and
// returns the response status code. headers may be nil.
func rawHTTP10Post(t *testing.T, url string, headers map[string]string) int {
	t.Helper()
	u, err := neturl.Parse(url)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var b strings.Builder
	b.WriteString("POST " + u.Path + " HTTP/1.0\r\n")
	for k, v := range headers {
		b.WriteString(k + ": " + v + "\r\n")
	}
	b.WriteString("Content-Length: 0\r\n")
	b.WriteString("Connection: close\r\n\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
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
