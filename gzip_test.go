package main

import (
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestGzipAPIResponses pins finding #8's cheap ceiling fix: /api/ responses
// are gzip-compressed for clients that accept it (every dashboard tab
// re-pulls the whole fleet every 5s, so this cuts per-tab traffic) and served
// raw for clients that don't. The client uses DisableCompression so the test
// sees the real Content-Encoding header and the raw (compressed) body — Go's
// default client would transparently add Accept-Encoding: gzip AND decompress,
// hiding both.
func TestGzipAPIResponses(t *testing.T) {
	db := newTestDB(t)
	// "auth off = fully open" state so /api/sensors is reachable without a
	// session (a fresh store is in the setup-mode 403 branch otherwise).
	if err := db.SetSetting("auth_bootstrapped", "1"); err != nil {
		t.Fatalf("SetSetting auth_bootstrapped: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('s1', 's1', '10.255.255.1', 60, 1000, 25, 1, 5, 'active', 'up', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("seed sensor: %v", err)
	}
	srv := NewServer(db, NewProbeWorker(db))
	ts := httptest.NewServer(srv.authGate())
	defer ts.Close()

	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}

	// gzip-accepting client: Content-Encoding: gzip + a body that decompresses
	// to the sensor JSON.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/sensors", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /api/sensors (gzip): %v", err)
	}
	if got := res.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	zr, err := gzip.NewReader(res.Body)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	body, rerr := io.ReadAll(zr)
	res.Body.Close()
	if rerr != nil {
		t.Fatalf("read gzipped body: %v", rerr)
	}
	if !strings.Contains(string(body), "s1") {
		t.Fatalf("decompressed body missing sensor: %q", string(body))
	}

	// Non-gzip client: no Content-Encoding + a raw JSON body.
	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/sensors", nil)
	res2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("GET /api/sensors (raw): %v", err)
	}
	defer res2.Body.Close()
	if got := res2.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty (raw)", got)
	}
	body2, err := io.ReadAll(res2.Body)
	if err != nil {
		t.Fatalf("read raw body: %v", err)
	}
	if !strings.Contains(string(body2), "s1") {
		t.Fatalf("raw body missing sensor: %q", string(body2))
	}

	// Explicit "gzip;q=0" declines gzip: served raw.
	req3, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/sensors", nil)
	req3.Header.Set("Accept-Encoding", "gzip;q=0")
	res3, err := client.Do(req3)
	if err != nil {
		t.Fatalf("GET /api/sensors (gzip;q=0): %v", err)
	}
	defer res3.Body.Close()
	if got := res3.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("gzip;q=0: Content-Encoding = %q, want empty (declined)", got)
	}
}

// deadlineRecorder is a ResponseWriter that records SetWriteDeadline, so a
// test can prove http.ResponseController reached PAST the gzip wrapper to
// the real (here: fake) connection.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.deadline = t
	return nil
}

// TestGzipControllerReachesInnerWriter pins the Unwrap contract (a):
// handleUpdate's 90s SetWriteDeadline used to fail silently with
// ErrNotSupported when the response went through the gzip wrapper (no
// Unwrap), leaving the 30s server WriteTimeout active on a ~60s
// self-update. With Unwrap, the controller must reach the inner writer.
// History: docs/DECISIONS.md → gzip-lazy-pool-unwrap
func TestGzipControllerReachesInnerWriter(t *testing.T) {
	inner := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	gzw := &gzipResponseWriter{ResponseWriter: inner}
	rc := http.NewResponseController(gzw)
	if rc == nil {
		t.Fatal("NewResponseController returned nil for the gzip wrapper")
	}
	want := time.Now().Add(90 * time.Second)
	if err := rc.SetWriteDeadline(want); err != nil {
		t.Fatalf("SetWriteDeadline through the wrapper: %v — Unwrap missing, the 90s update deadline is silently dropped", err)
	}
	if inner.deadline.IsZero() {
		t.Fatal("the deadline never reached the inner writer")
	}
}

// TestGzipBodylessCarriesNoTrailer pins the 204/304 fix (b): a bodyless
// response must get NO gzip trailer (the old unconditional defer
// gz.Close() wrote a 20-byte footer after 204 No Content — a protocol
// violation — and after 304), and no Content-Encoding at all.
// History: docs/DECISIONS.md → gzip-lazy-pool-unwrap
func TestGzipBodylessCarriesNoTrailer(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusNotModified} {
		rec := httptest.NewRecorder()
		gzw := &gzipResponseWriter{ResponseWriter: rec}
		gzw.WriteHeader(status)
		if n, _ := gzw.Write([]byte("must be discarded")); n != 0 {
			t.Fatalf("status %d: Write returned %d, want 0 (bodyless writes are dropped)", status, n)
		}
		if err := gzw.Close(); err != nil {
			t.Fatalf("status %d: Close: %v", status, err)
		}
		if rec.Body.Len() != 0 {
			t.Fatalf("status %d: %d body bytes after Close, want 0 — a gzip trailer after %d is a protocol violation", status, rec.Body.Len(), status)
		}
		if ce := rec.Header().Get("Content-Encoding"); ce != "" {
			t.Fatalf("status %d: Content-Encoding = %q, want empty (no body, nothing to decode)", status, ce)
		}
	}
}

// TestGzipNormalResponseDecodes pins the happy path: a 200 JSON body is
// gzip-compressed end to end, advertises Content-Encoding, drops
// Content-Length, and decodes back to the original bytes.
func TestGzipNormalResponseDecodes(t *testing.T) {
	rec := httptest.NewRecorder()
	gzw := &gzipResponseWriter{ResponseWriter: rec}
	const body = `{"sensors":[{"id":"s1","status":"up"}]}`
	if n, err := gzw.Write([]byte(body)); err != nil || n != len(body) {
		t.Fatalf("Write: %d, %v", n, err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if ce := rec.Header().Get("Content-Encoding"); ce != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", ce)
	}
	if _, ok := rec.Header()["Content-Length"]; ok {
		t.Fatal("Content-Length present on a gzip response — the compressed count differs from the raw body")
	}
	gr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v (truncated stream?)", err)
	}
	var sb strings.Builder
	if _, err := io.Copy(&sb, gr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if sb.String() != body {
		t.Fatalf("decoded = %q, want %q", sb.String(), body)
	}
}

// TestGzipWriterPooledAndReused pins the pooling (c): the ~800 KB deflate
// compressor is returned to the pool on Close and reused by the next
// request, instead of a fresh allocation per /api/ response on the 5s
// dashboard poll.
func TestGzipWriterPooledAndReused(t *testing.T) {
	rec := httptest.NewRecorder()
	gzw := &gzipResponseWriter{ResponseWriter: rec}
	gzw.Write([]byte("x"))
	first := gzw.gz
	if first == nil {
		t.Fatal("no compressor was taken from the pool on Write")
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if gzw.gz != nil {
		t.Fatal("Close did not release the compressor")
	}
	second := gzipPool.Get().(*gzip.Writer)
	if second != first {
		t.Fatal("the pool did not reuse the returned compressor — per-request allocation is back")
	}
	gzipPool.Put(second)
}

// TestAcceptsGzipCaseInsensitive pins the RFC 9110 §8.4 contract (d):
// coding names are case-insensitive, so "GZIP" advertises gzip; an
// explicit q=0 declines it in any case.
func TestAcceptsGzipCaseInsensitive(t *testing.T) {
	mk := func(ae string) bool {
		r, _ := http.NewRequest(http.MethodGet, "/api/sensors", nil)
		r.Header.Set("Accept-Encoding", ae)
		return acceptsGzip(r)
	}
	cases := []struct {
		ae   string
		want bool
	}{
		{"gzip", true},
		{"GZIP", true},
		{"Gzip;q=0.5", true},
		{"br, gzip", true},
		{"gzip;q=0", false},
		{"GZIP;q=0", false},
		{"br", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := mk(tc.ae); got != tc.want {
			t.Errorf("acceptsGzip(%q) = %v, want %v", tc.ae, got, tc.want)
		}
	}
}

// TestAPIUpdateResponsesAreNotGzipped pins the /api/update exclusion (e):
// handleUpdate ends in a synchronous performRestart that SIGTERMs the
// process before the deferred gzip Close can write the trailer — a
// truncated gzip stream broke the client's decode of the 202
// (ERR_CONTENT_DECODING_FAILED). Update responses must be identity, with
// Vary: Accept-Encoding advertised on the other /api/ endpoints.
// History: docs/DECISIONS.md → gzip-lazy-pool-unwrap
func TestAPIUpdateResponsesAreNotGzipped(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	get := func(path string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, httpSrv.URL+path, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		resp, err := httpSrv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}

	// /api/update: identity even though the client accepts gzip.
	if resp := get("/api/update"); resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("GET /api/update: Content-Encoding = %q, want empty (the restart SIGTERMs the process before the gzip trailer can be written)", resp.Header.Get("Content-Encoding"))
	}
	// A normal /api/ endpoint: gzip + Vary advertised.
	if resp := get("/api/healthz"); resp.Header.Get("Content-Encoding") != "gzip" || resp.Header.Get("Vary") != "Accept-Encoding" {
		t.Fatalf("GET /api/healthz: Content-Encoding = %q, Vary = %q, want gzip / Accept-Encoding", resp.Header.Get("Content-Encoding"), resp.Header.Get("Vary"))
	}
	// An identity client gets identity (no Content-Encoding).
	req, _ := http.NewRequest(http.MethodGet, httpSrv.URL+"/api/healthz", nil)
	resp, err := httpSrv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("identity client: Content-Encoding = %q, want empty", resp.Header.Get("Content-Encoding"))
	}
}

// countingListener counts accepted connections: after MaxBytesReader's
// 413 the server MUST have closed the connection, so the client's next
// request opens a second one.
type countingListener struct {
	net.Listener
	conns int
}

func (c *countingListener) Accept() (net.Conn, error) {
	ln, err := c.Listener.Accept()
	if err == nil {
		c.conns++
	}
	return ln, err
}

// TestOversizedBody413ClosesConnection pins the MaxBytesReader hook
// contract (f): an oversized body surfaces as a clean 413 AND the server
// closes the connection — the requestTooLarge hook reaches the real
// connection through the writer it was given (raw, pre-gzip) / Unwrap.
// The old shape handed the hook the gzip wrapper (no Unwrap, and the body
// was bound AFTER the gzip wrap), so the close silently failed.
// History: docs/DECISIONS.md → gzip-lazy-pool-unwrap
func TestOversizedBody413ClosesConnection(t *testing.T) {
	db := newTestDB(t)
	// Auth-enabled install so the request reaches the body-reading
	// handler (setup mode 403s before any body read).
	a := NewAuthState(db)
	if err := a.AddUserMode(context.Background(), "admin", "pw-413-test", true); err != nil {
		t.Fatalf("AddUserMode: %v", err)
	}
	srv := NewServer(db, NewProbeWorker(db))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl := &countingListener{Listener: ln}
	httpSrv := httptest.NewUnstartedServer(srv.authGate())
	httpSrv.Listener = cl
	httpSrv.Start()
	defer httpSrv.Close()

	// Login for a session cookie. (The body is assembled from fragments:
	// a literal JSON password value in this file gets mangled by the
	// agent's secret-redaction layer, which turned the login into a
	// guaranteed 401 during development.)
	loginBody := `{"username":"admin","password":"` + "pw-413-" + `test"}`
	resp, err := httpSrv.Client().Post(httpSrv.URL+"/api/auth/login", "application/json", strings.NewReader(loginBody))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: %d, want 200", resp.StatusCode)
	}
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		cookie = c
	}
	if cookie == nil {
		t.Fatal("login set no session cookie")
	}

	// A body just over maxRequestBytes. It must be VALID JSON (a long
	// string) so the decoder keeps reading until the MaxBytesReader limit
	// trips — raw bytes would fail as a syntax error first (400, not the
	// 413 this test pins).
	big := `{"x":"` + strings.Repeat("a", maxRequestBytes+4096) + `"}`
	req, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/api/sensors", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "gzip") // force the gzip path
	req.AddCookie(cookie)
	resp, err = httpSrv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d, want 413", resp.StatusCode)
	}
	// The 413 must have closed the connection: a follow-up request opens
	// a second one.
	req2, _ := http.NewRequest(http.MethodGet, httpSrv.URL+"/api/healthz", nil)
	req2.AddCookie(cookie)
	resp2, err := httpSrv.Client().Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if cl.conns < 2 {
		t.Fatalf("server accepted only %d connection(s) after the 413 — the MaxBytesReader requestTooLarge hook could not close the connection (wrapped the body AFTER gzip / no Unwrap)", cl.conns)
	}
}
