package main

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
