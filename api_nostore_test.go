package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestFix_APINoStore pins the Cache-Control contract (external review
// finding: static assets set no-cache but JSON API responses set no
// Cache-Control at all, leaving sensitive payloads like /api/settings and
// /api/auth/status exposed to intermediate proxies and aggressive browser
// caching). The gate must answer no-store on EVERY /api/ response — 200s
// and error paths alike — while static assets keep their own no-cache
// contract (set later in serveStatic, which this test guards against
// regression).
func TestFix_APINoStore(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	gate := srv.authGate()

	// 1. API 200 path: healthz is reachable in every auth state.
	req := httptest.NewRequest("GET", "/api/healthz", nil)
	rr := httptest.NewRecorder()
	gate.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/healthz = %d, want 200", rr.Code)
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("healthz Cache-Control = %q, want no-store", cc)
	}

	// 2. API error path: fresh install (no users) → /api/sensors is 403
	// setup-required; the no-store header must be set before any branch
	// returns, so error responses carry it too.
	req = httptest.NewRequest("GET", "/api/sensors", nil)
	rr = httptest.NewRecorder()
	gate.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("GET /api/sensors (fresh install) = %d, want 403", rr.Code)
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("403 response Cache-Control = %q, want no-store (error paths included)", cc)
	}

	// 3. Static assets keep the existing no-cache contract (serveStatic
	// sets it after the gate, so the gate must not have clobbered it).
	req = httptest.NewRequest("GET", "/index.html", nil)
	rr = httptest.NewRecorder()
	gate.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /index.html = %d, want 200", rr.Code)
	}
	if cc := rr.Header().Get("Cache-Control"); !strings.Contains(cc, "no-cache") {
		t.Errorf("index.html Cache-Control = %q, want the static no-cache contract", cc)
	}
}
