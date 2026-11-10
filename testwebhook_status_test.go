package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"pulsemon/internal/store"
	"strings"
	"sync"
	"sync/atomic"
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
	db, err := store.NewStore(dbPath)
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
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

// TestTestWebhookSurfacesURLReadError (review 2026-11-03): a transient
// settings-read failure on the provider URL must surface as a database error
// to the operator testing their config — not masquerade as "no <provider>
// webhook URL configured". Pre-fix TestWebhook read the URL via the
// swallow-to-"" GetSetting, so a locked DB reported the not-configured path
// for a perfectly-configured provider. resolveDestinations (the delivery
// path) was already hardened to getSettingErr; the test button was the
// straggler.
func TestTestWebhookSurfacesURLReadError(t *testing.T) {
	db := newTestDB(t)
	_ = db.SetSetting("discord_enabled", "1")
	_ = db.SetSetting("discord_url", "http://10.99.99.1/hook")
	pw := NewProbeWorker(db)

	orig := getSettingErr
	getSettingErr = func(db *store.Store, key string) (string, error) {
		if key == "discord_url" {
			return "", errors.New("simulated transient DB lock")
		}
		return orig(db, key)
	}
	defer func() { getSettingErr = orig }()

	ok, msg := pw.TestWebhook(t.Context(), "discord")
	if ok {
		t.Fatalf("TestWebhook ok=true with a failing URL read (msg %q)", msg)
	}
	if msg != "database error reading provider settings" {
		t.Fatalf("TestWebhook msg = %q, want the database error (pre-fix this was the swallow-to-empty 'no URL configured' path)", msg)
	}
}

// TestTestWebhookSurfacesChatIDReadError (review 2026-11-03): a transient
// settings-read failure on telegram_chat_id must surface as a database error
// — not post an empty chat_id to Telegram (HTTP 400). Pre-fix the chat_id was
// read via the swallow-to-"" GetSetting, so a DB lock at test time posted
// {"chat_id": ""}. The test must fail BEFORE any POST.
func TestTestWebhookSurfacesChatIDReadError(t *testing.T) {
	withPlainTransport(t, func() {
		db := newTestDB(t)
		_ = db.SetSetting("telegram_enabled", "1")
		var reqCount int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&reqCount, 1)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		_ = db.SetSetting("telegram_url", srv.URL)
		_ = db.SetSetting("telegram_chat_id", "111222")
		pw := NewProbeWorker(db)

		orig := getSettingErr
		getSettingErr = func(db *store.Store, key string) (string, error) {
			if key == "telegram_chat_id" {
				return "", errors.New("simulated transient DB lock")
			}
			return orig(db, key)
		}
		defer func() { getSettingErr = orig }()

		ok, msg := pw.TestWebhook(t.Context(), "telegram")
		if ok {
			t.Fatalf("TestWebhook ok=true with a failing chat_id read (msg %q)", msg)
		}
		if msg != "database error reading provider settings" {
			t.Fatalf("TestWebhook msg = %q, want the database error", msg)
		}
		if n := atomic.LoadInt32(&reqCount); n != 0 {
			t.Fatalf("endpoint received %d request(s); want 0 (the test must fail before any POST)", n)
		}
	})
}

// TestTestWebhookDiscordPayloadMatchesDelivery (review 2026-11-10 #8): the
// discord test-alert payload must be structurally identical to the
// production delivery payloads — deliverOne and deliverStormSummary both
// send {"content", "allowed_mentions": {"parse": []}}. Pre-fix the test
// button sent map[string]string{"content": ...} with no allowed_mentions:
// no mention-injection risk (hardcoded text), but the test button is where
// an operator verifies their webhook config, and a payload shape the
// production path never sends is a weaker verification — a bridge that
// chokes on allowed_mentions would pass the test and fail real alerts.
func TestTestWebhookDiscordPayloadMatchesDelivery(t *testing.T) {
	withPlainTransport(t, func() {
		db := newTestDB(t)
		_ = db.SetSetting("discord_enabled", "1")
		var (
			mu       sync.Mutex
			captured []byte
		)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			captured = b
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		_ = db.SetSetting("discord_url", srv.URL)
		pw := NewProbeWorker(db)

		ok, msg := pw.TestWebhook(t.Context(), "discord")
		if !ok {
			t.Fatalf("TestWebhook discord: ok=false (%s)", msg)
		}
		mu.Lock()
		body := captured
		mu.Unlock()
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("captured body is not a JSON object: %v (%q)", err, body)
		}
		if _, ok := payload["content"]; !ok {
			t.Errorf("discord test payload missing 'content': %q", body)
		}
		am, ok := payload["allowed_mentions"].(map[string]any)
		if !ok {
			t.Fatalf("discord test payload missing the 'allowed_mentions' object (deliverOne and deliverStormSummary both send it): %q", body)
		}
		parse, ok := am["parse"].([]any)
		if !ok || len(parse) != 0 {
			t.Errorf("allowed_mentions.parse = %v, want an empty array (the production shape): %q", am["parse"], body)
		}
	})
}
