package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFix_g7_StaticCharsetETag304(t *testing.T) {
	d := newTestDB(t)
	mux := NewServer(d, NewProbeWorker(d)).Mux()

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/index.html", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /index.html = %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
	etag := rr.Header().Get("ETag")
	if len(etag) < 10 || !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) || strings.HasPrefix(etag, "W/") {
		t.Fatalf("ETag = %q, want a quoted strong tag", etag)
	}
	if !strings.Contains(rr.Header().Get("Cache-Control"), "no-cache") {
		t.Errorf("Cache-Control = %q, want no-cache", rr.Header().Get("Cache-Control"))
	}
	if rr.Body.Len() == 0 {
		t.Fatal("200 response had no body")
	}

	// Revalidation with the returned tag: 304, no body, tag still sent.
	req := httptest.NewRequest("GET", "/index.html", nil)
	req.Header.Set("If-None-Match", etag)
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req)
	if rr2.Code != http.StatusNotModified || rr2.Body.Len() != 0 {
		t.Fatalf("If-None-Match => %d with %d body bytes, want 304 and empty", rr2.Code, rr2.Body.Len())
	}
	if rr2.Header().Get("ETag") != etag {
		t.Errorf("304 lost the ETag: %q", rr2.Header().Get("ETag"))
	}

	// A stale tag must NOT 304 (an update is never served stale).
	req = httptest.NewRequest("GET", "/index.html", nil)
	req.Header.Set("If-None-Match", `"stale"`)
	rr3 := httptest.NewRecorder()
	mux.ServeHTTP(rr3, req)
	if rr3.Code != http.StatusOK {
		t.Errorf("stale If-None-Match => %d, want 200", rr3.Code)
	}

	// Other assets get an ETag too; unknown paths are still 404.
	rr4 := httptest.NewRecorder()
	mux.ServeHTTP(rr4, httptest.NewRequest("GET", "/favicon.svg", nil))
	if rr4.Code != http.StatusOK || rr4.Header().Get("ETag") == "" {
		t.Errorf("favicon.svg => %d etag %q", rr4.Code, rr4.Header().Get("ETag"))
	}
	rr5 := httptest.NewRecorder()
	mux.ServeHTTP(rr5, httptest.NewRequest("GET", "/nope-does-not-exist.js", nil))
	if rr5.Code != http.StatusNotFound {
		t.Errorf("unknown asset => %d, want 404", rr5.Code)
	}
}
