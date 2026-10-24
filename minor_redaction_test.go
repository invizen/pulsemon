package main

// Review 2026-10-24 minor batch — 5xx response bodies on the update path
// echoed raw upstream errors ("fetch release: Get
// "http://127.0.0.1:PORT/...": dial tcp ...", DNS/resolver text, proxy
// config). The g3 contract already covers 500s via respondInternal; 502/503
// were the blind spot. Detail now goes to the log; the body gets a generic
// verdict. The one intentional exception (SHA-mismatch refusal — actionable,
// no upstream detail) carries a redaction-ok: marker enforced by the g3
// static test, which now scans 500+502+503.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// deadUpstream closes connections without replying: the resulting error
// text unavoidably contains the server's 127.0.0.1:PORT address, which is
// exactly the detail that must NOT appear in a response body.
func deadUpstream() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			conn.Close()
		}
	}))
}

func withReleaseBase(t *testing.T, url string) {
	t.Helper()
	orig := releaseBase
	releaseBase = url
	// Drop the process-wide update-check cache too: a warm success from an
	// earlier test in the same binary would otherwise answer 200 before any
	// fetch happens, hiding the body we are trying to assert on.
	cached, failed, at := updateCheckCached, updateCheckFailed, updateCheckAt
	updateCheckMu.Lock()
	updateCheckCached, updateCheckFailed = nil, false
	updateCheckAt = time.Time{}
	updateCheckMu.Unlock()
	t.Cleanup(func() {
		releaseBase = orig
		updateCheckMu.Lock()
		updateCheckCached, updateCheckFailed, updateCheckAt = cached, failed, at
		updateCheckMu.Unlock()
	})
}

func TestUpdateAPIBadGatewayBodiesRedacted(t *testing.T) {
	dead := deadUpstream()
	t.Cleanup(dead.Close)
	withReleaseBase(t, dead.URL)

	// Auth ENABLED: since the 2026-10-24 review (M1) the update endpoint
	// 403s while auth is off, so an auth-off server would never reach the
	// 502 body this test is asserting on. handleUpdate is called directly
	// (like the rest of the update tests) so the mux's session check is
	// not the thing under test here.
	srv := updateServer(t)

	rec := httptest.NewRecorder()
	srv.handleUpdate(rec, httptest.NewRequest("POST", "/api/update", strings.NewReader("")))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("dead upstream: code = %d, want 502 (body %q)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "127.0.0.1") || strings.Contains(body, ":") && strings.Contains(body, dead.URL[7:]) {
		t.Fatalf("502 body leaks upstream address detail: %q", body)
	}
	if !strings.Contains(body, "GitHub") {
		t.Fatalf("502 body lost its actionable verdict: %q", body)
	}
}

func TestUpdateCheckUnavailableBodyRedacted(t *testing.T) {
	dead := deadUpstream()
	t.Cleanup(dead.Close)
	withReleaseBase(t, dead.URL)

	d := newTestDB(t)
	mux := NewServer(d, NewProbeWorker(d)).Mux()

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/update-check", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("dead upstream: code = %d, want 503 (body %q)", rr.Code, rr.Body.String())
	}
	if body := rr.Body.String(); strings.Contains(body, "127.0.0.1") {
		t.Fatalf("503 body leaks upstream address detail: %q", body)
	}
}
