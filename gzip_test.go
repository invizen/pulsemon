package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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
	// Reuse is asserted through the pool's New count, NOT pointer
	// identity: under -race, sync.Pool.Put intentionally drops the item
	// at random (~25%, "Randomly drop x on floor") to stress callers
	// that don't rely on retention, so an identity assertion across
	// Put/Get flakes (2026-11-19 CI failure on a 2-core runner). A
	// broken Close (no Put) calls New on every Get; a healthy pool
	// returns a pooled writer within a few Put/Get cycles even with
	// drops (P(32 straight drops) ≈ 3e-19).
	var newCount atomic.Int64
	orig := gzipPool
	gzipPool = &sync.Pool{New: func() any {
		newCount.Add(1)
		return gzip.NewWriter(io.Discard)
	}}
	defer func() { gzipPool = orig }()

	rec := httptest.NewRecorder()
	gzw := &gzipResponseWriter{ResponseWriter: rec}
	gzw.Write([]byte("x"))
	first := gzw.gz
	if first == nil {
		t.Fatal("no compressor was taken from the pool on Write")
	}
	if n := newCount.Load(); n != 1 {
		t.Fatalf("New called %d times for the first write on an empty pool, want 1", n)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if gzw.gz != nil {
		t.Fatal("Close did not release the compressor")
	}
	reused := 0
	for i := 0; i < 20; i++ {
		rec := httptest.NewRecorder()
		gzw := &gzipResponseWriter{ResponseWriter: rec}
		gzw.Write([]byte("x"))
		if gzw.gz == nil {
			t.Fatal("no compressor was taken from the pool on Write")
		}
		if err := gzw.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if gzw.gz != nil {
			t.Fatal("Close did not release the compressor")
		}
		// One Get per cycle, and the taken writer is NOT put back: the
		// pool stays drained, so a broken Close (no Put) can never
		// manufacture a New-free Get.
		before := newCount.Load()
		gz := gzipPool.Get().(*gzip.Writer)
		if newCount.Load() == before {
			reused++ // Close's Put survived — the pooled writer came back
		}
		_ = gz
	}
	if reused == 0 {
		t.Fatalf("20 Write/Close/Get cycles, zero pooled reuses (New on every Get) — per-request allocation is back")
	}
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

// TestGzipHeadResponse pins the HEAD path: a HEAD request must COMPLETE
// (a body-less response must not leave any writer blocked waiting to
// flush a body). MINOR-23(c) added the wrap exclusion — HEAD skips the
// gzip wrapper entirely, so the response (405 here: the route's real
// HEAD answer) must NOT declare Content-Encoding: gzip (a body the
// client never receives) and the per-request ErrBodyNotAllowed log line
// is gone with it. 204/304 are covered by
// TestGzipBodylessCarriesNoTrailer.
// History: docs/DECISIONS.md → testing-benchmark-gaps,
// gzip-head-and-bodyless-fixes
func TestGzipHeadResponse(t *testing.T) {
	db := newTestDB(t)
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

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableCompression: true}}
	req, _ := http.NewRequest(http.MethodHead, ts.URL+"/api/sensors", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	type headResult struct {
		resp *http.Response
		err  error
	}
	done := make(chan headResult, 1)
	go func() {
		resp, err := client.Do(req)
		done <- headResult{resp: resp, err: err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("HEAD /api/sensors: %v (it must complete, not hang)", r.err)
		}
		defer r.resp.Body.Close()
		// 405 is the route's real HEAD answer (the handler only serves
		// GET/POST) — the pin is about the gzip contract, not routing.
		if r.resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("HEAD /api/sensors: %d, want 405", r.resp.StatusCode)
		}
		if ce := r.resp.Header.Get("Content-Encoding"); ce != "" {
			t.Fatalf("HEAD: Content-Encoding = %q, want empty (HEAD skips the gzip wrap — a body the client never gets must not be declared gzip)", ce)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("HEAD /api/sensors hung (a body-less response blocked the writer)")
	}
}

// headlessWriter mimics net/http's HEAD ResponseWriter: the header calls
// succeed, Write refuses the body with http.ErrBodyNotAllowed.
type headlessWriter struct{}

func (headlessWriter) Header() http.Header       { return http.Header{} }
func (headlessWriter) WriteHeader(int)           {}
func (headlessWriter) Write([]byte) (int, error) { return 0, http.ErrBodyNotAllowed }

// TestRespondWithJSONIgnoresBodyNotAllowed pins the log-noise half of
// MINOR-23(c): a writer that refuses the body (net/http's HEAD outcome)
// must produce NO log line — pre-fix every HEAD /api/* request logged
// "respondWithJSON: encode: http: response with ...". A genuine marshal
// failure must STILL be logged.
func TestRespondWithJSONIgnoresBodyNotAllowed(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	respondWithJSON(headlessWriter{}, http.StatusOK, map[string]string{"ok": "1"})
	if buf.Len() != 0 {
		t.Fatalf("respondWithJSON logged for the expected HEAD outcome: %q", buf.String())
	}

	// A real marshal failure (top-level func: fails before any Write) must
	// still surface in the log.
	buf.Reset()
	respondWithJSON(headlessWriter{}, http.StatusOK, func() {})
	if !strings.Contains(buf.String(), "respondWithJSON: encode") {
		t.Fatalf("genuine marshal failure was not logged: %q", buf.String())
	}
}

// serverishWriter models the real net/http server's response semantics
// (which httptest.ResponseRecorder can't represent — it keeps a 1xx as
// the effective status): a 1xx is recorded and sent immediately, a final
// status SNAPSHOTs the header map (Go 1.24+: later sets are lost), a
// second final status is ignored, and a lone 1xx + body upgrades to 200.
type serverishWriter struct {
	header   http.Header
	snapshot http.Header // the map as of the last final WriteHeader
	status   int
	body     bytes.Buffer
}

func (s *serverishWriter) Header() http.Header {
	if s.header == nil {
		s.header = http.Header{}
	}
	return s.header
}

func (s *serverishWriter) WriteHeader(code int) {
	if code >= 100 && code < 200 {
		s.status = code
		return
	}
	if s.status >= 200 {
		return // superfluous final status: ignored (the server logs it)
	}
	s.status = code
	s.snapshot = s.header.Clone()
}

func (s *serverishWriter) Write(b []byte) (int, error) {
	if s.status < 200 {
		s.status = http.StatusOK
		s.snapshot = s.header.Clone()
	}
	s.body.Write(b)
	return len(b), nil
}

// TestGzipOneShotThenFinalBody pins MINOR-23(a): a 1xx WriteHeader (102
// Processing) used to set bypass permanently, so the final 200 + body
// after it was silently discarded — the client got Content-Encoding: gzip
// and an empty body (ERR_CONTENT_DECODING_FAILED). The final status must
// clear the bypass, and the CE must land in the header SNAPSHOT (set
// before the server's WriteHeader — Go 1.24+ drops later sets).
func TestGzipOneShotThenFinalBody(t *testing.T) {
	inner := &serverishWriter{}
	gzw := &gzipResponseWriter{ResponseWriter: inner}
	gzw.WriteHeader(http.StatusProcessing) // 102
	gzw.WriteHeader(http.StatusOK)
	const body = `{"ok":true}`
	if n, err := gzw.Write([]byte(body)); err != nil || n != len(body) {
		t.Fatalf("Write after 1xx→200: %d, %v — the 1xx bypass was never cleared", n, err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if inner.status != http.StatusOK {
		t.Fatalf("final status = %d, want 200", inner.status)
	}
	if ce := inner.snapshot.Get("Content-Encoding"); ce != "gzip" {
		t.Fatalf("Content-Encoding in the header snapshot = %q, want gzip (a CE set after the server's WriteHeader is dropped)", ce)
	}
	gr, err := gzip.NewReader(&inner.body)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v (the body was discarded?)", err)
	}
	out, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(out) != body {
		t.Fatalf("decoded = %q, want %q", out, body)
	}
}

// TestGzipOneShotEndToEnd pins the same contract through a real net/http
// server (the server writes the 102 immediately, then the final 200):
// the client must receive Content-Encoding: gzip and a body that decodes.
func TestGzipOneShotEndToEnd(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gzw := &gzipResponseWriter{ResponseWriter: w}
		defer gzw.Close()
		w = gzw
		w.WriteHeader(http.StatusProcessing)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer res.Body.Close()
	if ce := res.Header.Get("Content-Encoding"); ce != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", ce)
	}
	gr, err := gzip.NewReader(res.Body)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v (the 1xx left the body bypassed?)", err)
	}
	out, _ := io.ReadAll(gr)
	if string(out) != `{"ok":true}` {
		t.Fatalf("decoded = %q, want %q", out, `{"ok":true}`)
	}
}

// TestGzipBodylessStatusCarriesNoEncoding pins MINOR-23(b): a status-only
// response (WriteHeader, no body) must NOT declare Content-Encoding: gzip
// — pre-fix the header was set at WriteHeader and Close saw g.gz == nil,
// so the client got a 0-byte "gzip" body: an invalid stream
// (ERR_CONTENT_DECODING_FAILED).
func TestGzipBodylessStatusCarriesNoEncoding(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusBadRequest, http.StatusUnauthorized} {
		rec := httptest.NewRecorder()
		gzw := &gzipResponseWriter{ResponseWriter: rec}
		gzw.WriteHeader(status)
		if err := gzw.Close(); err != nil {
			t.Fatalf("status %d: Close: %v", status, err)
		}
		if ce := rec.Header().Get("Content-Encoding"); ce != "" {
			t.Fatalf("status %d: Content-Encoding = %q, want empty (no body was written — a 0-byte gzip stream is invalid)", status, ce)
		}
		if rec.Body.Len() != 0 {
			t.Fatalf("status %d: %d body bytes, want 0", status, rec.Body.Len())
		}
	}
}
