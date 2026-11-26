package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestWebhookBodyDiag pins the Telegram-style error-envelope extraction
// (MINOR-21): parameters.retry_after plus a truncated description, and
// (0, "") for empty / non-JSON / foreign shapes.
func TestWebhookBodyDiag(t *testing.T) {
	secs, desc := webhookBodyDiag([]byte(`{"ok":false,"error_code":429,"description":"Too Many Requests: retry later","parameters":{"retry_after":35}}`))
	if secs != 35 || desc != "Too Many Requests: retry later" {
		t.Fatalf("webhookBodyDiag = (%d, %q), want (35, %q)", secs, desc, "Too Many Requests: retry later")
	}
	if secs, desc = webhookBodyDiag(nil); secs != 0 || desc != "" {
		t.Fatalf("webhookBodyDiag(nil) = (%d, %q), want (0, %q)", secs, desc, "")
	}
	if secs, desc = webhookBodyDiag([]byte(`not json`)); secs != 0 || desc != "" {
		t.Fatalf("webhookBodyDiag(non-JSON) = (%d, %q), want (0, %q)", secs, desc, "")
	}
	if secs, desc = webhookBodyDiag([]byte(`{"text":"plain"}`)); secs != 0 || desc != "" {
		t.Fatalf("webhookBodyDiag(foreign shape) = (%d, %q), want (0, %q)", secs, desc, "")
	}
	long := strings.Repeat("a", 300)
	if _, desc = webhookBodyDiag([]byte(`{"description":"` + long + `"}`)); len([]rune(desc)) != 201 {
		t.Fatalf("long description = %d runes, want 201 (200 cap + ellipsis)", len([]rune(desc)))
	}
}

// TestPostJSONHonorsBodyRetryAfter is the MINOR-21 flood-wait pin: a 429
// carrying parameters.retry_after ONLY in the JSON body (no Retry-After
// header — Telegram's shape) must delay the in-band retry by that long.
// Pre-fix the body was drained to io.Discard and the header-only parse
// fell back to the fixed schedule (5ms here), re-hitting the provider
// outside its flood window.
func TestPostJSONHonorsBodyRetryAfter(t *testing.T) {
	withPlainTransport(t, func() {
		old := alertRetryDelays
		alertRetryDelays = []time.Duration{5 * time.Millisecond, 5 * time.Millisecond}
		defer func() { alertRetryDelays = old }()
		pw := NewProbeWorker(nil)

		var mu sync.Mutex
		var hits []time.Time
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits = append(hits, time.Now())
			n := len(hits)
			mu.Unlock()
			if n == 1 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"ok":false,"error_code":429,"description":"Too Many Requests: retry later","parameters":{"retry_after":1}}`))
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		if err := pw.postJSON(srv.URL, map[string]any{"text": "x"}); err != nil {
			t.Fatalf("429 (body retry_after) then 200 should succeed: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(hits) != 2 {
			t.Fatalf("hits = %d, want 2", len(hits))
		}
		if gap := hits[1].Sub(hits[0]); gap < 950*time.Millisecond {
			t.Fatalf("retry after 429 came %v later, want >= ~1s (body parameters.retry_after: 1 — pre-fix the body was discarded)", gap)
		}
	})
}

// TestPostJSON429HeaderBeatsBody pins the precedence: when the provider
// sends BOTH a Retry-After header and a body retry_after, the header (the
// standard mechanism) wins — the body is a fallback, not an override.
func TestPostJSON429HeaderBeatsBody(t *testing.T) {
	withPlainTransport(t, func() {
		old := alertRetryDelays
		alertRetryDelays = []time.Duration{5 * time.Millisecond, 5 * time.Millisecond}
		defer func() { alertRetryDelays = old }()
		pw := NewProbeWorker(nil)

		var mu sync.Mutex
		var hits []time.Time
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits = append(hits, time.Now())
			n := len(hits)
			mu.Unlock()
			if n == 1 {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":3}}`))
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		if err := pw.postJSON(srv.URL, map[string]any{"text": "x"}); err != nil {
			t.Fatalf("429 then 200 should succeed: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(hits) != 2 {
			t.Fatalf("hits = %d, want 2", len(hits))
		}
		gap := hits[1].Sub(hits[0])
		if gap < 950*time.Millisecond || gap >= 1900*time.Millisecond {
			t.Fatalf("retry gap = %v, want ~1s (header Retry-After: 1 beats body retry_after: 3)", gap)
		}
	})
}

// TestPostJSON400SurfacesBodyDescription pins the 4xx diagnostics (MINOR-
// 21): a non-retryable 400 must carry the provider's description (a
// misconfigured Telegram chat: "chat not found") in the returned error —
// pre-fix it reported only "endpoint returned 400".
func TestPostJSON400SurfacesBodyDescription(t *testing.T) {
	withPlainTransport(t, func() {
		pw := NewProbeWorker(nil)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`))
		}))
		defer srv.Close()
		err := pw.postJSON(srv.URL, map[string]any{"text": "x"})
		if err == nil {
			t.Fatal("400 must not succeed")
		}
		if !strings.Contains(err.Error(), "endpoint returned 400") || !strings.Contains(err.Error(), "chat not found") {
			t.Fatalf("postJSON 400 error = %q, want it to carry the body description", err)
		}
	})
}

// TestWebhookDetailSurfacesBodyDescription pins the test-button side:
// TestWebhook's failure detail for a 400 must include the provider's
// description, so the operator sees what to fix.
func TestWebhookDetailSurfacesBodyDescription(t *testing.T) {
	withPlainTransport(t, func() {
		db := newTestDB(t)
		pw := NewProbeWorker(db)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`))
		}))
		defer srv.Close()
		if _, err := db.Exec(`INSERT INTO settings (setting_key, value) VALUES ('google_chat_url', ?)`, srv.URL); err != nil {
			t.Fatalf("seed settings: %v", err)
		}
		ok, detail := pw.TestWebhook(context.Background(), "google_chat")
		if ok {
			t.Fatal("400 must report failure")
		}
		if !strings.Contains(detail, "endpoint returned HTTP 400") || !strings.Contains(detail, "chat not found") {
			t.Fatalf("TestWebhook detail = %q, want it to carry the body description", detail)
		}
	})
}

// TestDoWebhookPostBodyOnlyOn400 pins the capture scope: the body is
// kept only on 400+ responses; a 2xx body is drained as before (nil
// returned), so successful responses cost nothing extra.
func TestDoWebhookPostBodyOnlyOn400(t *testing.T) {
	withPlainTransport(t, func() {
		pw := NewProbeWorker(nil)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"ok":true}`))
		}))
		defer srv.Close()
		code, _, body, err := pw.doWebhookPost(context.Background(), srv.URL, []byte(`{}`))
		if err != nil || code != 200 {
			t.Fatalf("doWebhookPost = (%d, %v), want (200, nil)", code, err)
		}
		if body != nil {
			t.Fatalf("2xx body = %q, want nil (only 400+ bodies are captured)", body)
		}
	})
}
