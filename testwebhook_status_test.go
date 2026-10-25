package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// TestTestWebhookStatusHandling pins TestWebhook's response handling: a 2xx
// is a success, a redirect (3xx < 400) is refused, and any other 3xx/4xx/5xx
// is a failure with the status in the detail. Each case sends a non-trivial
// body so the capped drain (io.LimitReader — the 2026-10-24 change that makes
// TestWebhook consistent with postJSON) has real bytes to read.
//
// This is a behavior-preserving pin: it passes WITH and WITHOUT the drain
// (the drain's connection-reuse benefit is not externally observable in a
// test, so it is verified by inspection — it is the exact same idiom as
// postJSON, which is proven working). What it locks is the status contract,
// which had no dedicated test: a future edit to the drain or the status
// branches can't silently change what TestWebhook reports.
func TestTestWebhookStatusHandling(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "testwebhook_status.db")
	db, err := NewDB(dbPath)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	withPlainTransport(t, func() {
		cases := []struct {
			name       string
			status     int
			wantOK     bool
			wantSubstr string
		}{
			{"2xx success", http.StatusOK, true, "HTTP OK"},
			{"redirect refused", http.StatusMovedPermanently, false, "redirected"},
			{"server error", http.StatusInternalServerError, false, "HTTP 500"},
		}
		for _, c := range cases {
			c := c
			t.Run(c.name, func(t *testing.T) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(c.status)
					// Non-trivial body so the drain reads real bytes.
					_, _ = w.Write([]byte(strings.Repeat("x", 4096)))
				}))
				defer srv.Close()
				if err := db.SetSetting("google_chat_url", srv.URL); err != nil {
					t.Fatalf("SetSetting: %v", err)
				}
				pw := NewProbeWorker(db)
				ok, detail := pw.TestWebhook(context.Background(), "google_chat")
				if ok != c.wantOK {
					t.Errorf("status %d: ok = %v, want %v (detail %q)", c.status, ok, c.wantOK, detail)
				}
				if !strings.Contains(detail, c.wantSubstr) {
					t.Errorf("status %d: detail %q, want substring %q", c.status, detail, c.wantSubstr)
				}
			})
		}
	})
}
