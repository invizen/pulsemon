package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"pulsemon/internal/store"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Telegram uses HTML parse mode (<b>bold</b>). The card carries the same
// information as the Discord/Google Chat cards, HTML-flavored.
func TestTelegramCard(t *testing.T) {
	c := telegramCard("up", "error", "zenkub1", "192.168.1.10", 0)
	for _, want := range []string{
		"❌", "<b>pulsemon: error</b>",
		"<b>Sensor:</b> zenkub1", "<b>Target:</b> 192.168.1.10",
		"<b>State:</b> error",
	} {
		if !strings.Contains(c, want) {
			t.Fatalf("telegramCard missing %q in:\n%s", want, c)
		}
	}
	// No RTT for a down ICMP sensor: no <b>Ping:</b> line.
	if strings.Contains(c, "<b>Ping:</b>") {
		t.Fatalf("unexpected Ping line in down card:\n%s", c)
	}
}

func TestTelegramCardWithRTT(t *testing.T) {
	c := telegramCard("up", "warning", "nas", "10.0.0.5", 120.4)
	if !strings.Contains(c, "<b>Ping:</b> 120 ms") {
		t.Fatalf("expected Ping line, got:\n%s", c)
	}
}

func TestTelegramCardRe(t *testing.T) {
	c := telegramCardRe("error", "zenkub1", "192.168.1.10", 0)
	for _, want := range []string{
		"❌", "re-alert", "<b>State:</b> error",
	} {
		if !strings.Contains(c, want) {
			t.Fatalf("telegramCardRe missing %q in:\n%s", want, c)
		}
	}
}

func TestTelegramCardIcons(t *testing.T) {
	cases := map[string]string{
		"up":      "✅",
		"warning": "⚠️",
		"error":   "❌",
	}
	for state, icon := range cases {
		c := telegramCard("up", state, "s", "t", 0)
		if !strings.Contains(c, icon) {
			t.Fatalf("state %s: expected icon %s in:\n%s", state, icon, c)
		}
	}
}

// TestTelegramCardEscapesAmpersandInTarget locks the finding-9 fix: a URL
// query string with a raw & (validURL accepts it) must reach the card as
// &amp; — an unescaped & in Telegram HTML parse mode can make the API
// reject the message with 400 "can't parse entities", silently dropping
// the alert. Both card variants are checked.
func TestTelegramCardEscapesAmpersandInTarget(t *testing.T) {
	target := "https://host.lan/health?service=a&check=1"
	for _, c := range []string{
		telegramCard("up", "error", "zenkub1", target, 0),
		telegramCardRe("error", "zenkub1", target, 0),
	} {
		if !strings.Contains(c, "&amp;check=1") {
			t.Fatalf("expected escaped &amp;check=1 in:\n%s", c)
		}
		if strings.Contains(c, "a&check") {
			t.Fatalf("unescaped & reached the card:\n%s", c)
		}
	}
}

// TestTelegramCardEscapesMarkupInTarget locks the other half: url.Parse
// (and thus validURL) accepts raw markup in the URL path (verified on
// Go 1.26: https://host.lan/<b>bold</b> parses fine), so an unescaped
// target would inject live <b> markup into the Telegram card. It must be
// escaped to &lt;b&gt; instead.
func TestTelegramCardEscapesMarkupInTarget(t *testing.T) {
	target := "https://host.lan/<b>bold</b>"
	for _, c := range []string{
		telegramCard("up", "error", "zenkub1", target, 0),
		telegramCardRe("error", "zenkub1", target, 0),
	} {
		if !strings.Contains(c, "&lt;b&gt;bold&lt;/b&gt;") {
			t.Fatalf("expected escaped markup in:\n%s", c)
		}
		if strings.Contains(c, "<b>bold</b>") {
			t.Fatalf("unescaped markup injected into the card:\n%s", c)
		}
		// The card's own intentional tags must survive escaping.
		if !strings.Contains(c, "<b>Sensor:</b> zenkub1") {
			t.Fatalf("intentional card tags were damaged:\n%s", c)
		}
	}
}

// TestResolveDestinationsResolvesTelegramChatID (2026-10-30 review #3):
// the chat_id is resolved up front, alongside the URL, and carried on the
// dest — the delivery goroutines must never re-read it live.
func TestResolveDestinationsResolvesTelegramChatID(t *testing.T) {
	db := newTestDB(t)
	_ = db.SetSetting("telegram_enabled", "1")
	_ = db.SetSetting("telegram_url", "https://api.telegram.org/botTEST/sendMessage")
	_ = db.SetSetting("telegram_chat_id", "111222")
	pw := NewProbeWorker(db)
	dests, ok := pw.resolveDestinations()
	if !ok {
		t.Fatal("resolveDestinations: ok=false with a readable DB")
	}
	if len(dests) != 1 {
		t.Fatalf("dests = %d, want 1 (the configured telegram provider)", len(dests))
	}
	if dests[0].p.Kind != "telegram" || dests[0].chatID != "111222" {
		t.Fatalf("dest = {%s chatID=%q}, want telegram with chatID = the configured value",
			dests[0].p.Kind, dests[0].chatID)
	}
}

// TestTelegramDeliveryFailsClosedOnChatIDReadError (2026-10-30 review #3):
// a transient settings-read failure on telegram_chat_id must fail the whole
// send (reported not-delivered, so the caller retries) — never post an
// empty chat_id, which Telegram answers 400 and the storm-summary path
// (no retry) would drop. Pre-fix the chat_id was re-read live in the
// delivery goroutine via the swallow-to-"" GetSetting, so a DB lock at
// delivery time posted {"chat_id": ""}.
func TestTelegramDeliveryFailsClosedOnChatIDReadError(t *testing.T) {
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

	if dests, ok := pw.resolveDestinations(); ok {
		t.Fatalf("resolveDestinations ok=true with a failing chat_id read (dests=%v)", dests)
	}
	if pw.sendWebhookDeliver("s1", "s1", "10.0.0.1", "up", "error", 0, false) {
		t.Fatal("sendWebhookDeliver reported delivered with a failing chat_id read")
	}
	if n := atomic.LoadInt32(&reqCount); n != 0 {
		t.Fatalf("endpoint received %d request(s); want 0 (the send must fail before any POST)", n)
	}
}

// TestTelegramDeliveryPostsResolvedChatID (2026-10-30 review #3): the POST
// carries the chat_id resolved in resolveDestinations — the healthy-path
// half of the fail-closed contract above. The cleartext client's dial-time
// SSRF check (dialCheckedCleartext) refuses loopback by design, so the test
// swaps in a plain dialer — the same seam idiom the SMTP delivery test uses
// for smtpDial.
func TestTelegramDeliveryPostsResolvedChatID(t *testing.T) {
	transport := webhookClientCleartext.Transport.(*http.Transport)
	origDial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
	}
	t.Cleanup(func() { transport.DialContext = origDial })

	db := newTestDB(t)
	_ = db.SetSetting("telegram_enabled", "1")
	var mu sync.Mutex
	var gotChatID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		mu.Lock()
		gotChatID, _ = payload["chat_id"].(string)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	_ = db.SetSetting("telegram_url", srv.URL)
	_ = db.SetSetting("telegram_chat_id", "111222")
	pw := NewProbeWorker(db)

	if !pw.sendWebhookDeliver("s1", "s1", "10.0.0.1", "up", "error", 0, false) {
		t.Fatal("sendWebhookDeliver reported not-delivered with a working endpoint")
	}
	mu.Lock()
	defer mu.Unlock()
	if gotChatID != "111222" {
		t.Fatalf("POST chat_id = %q, want the resolved %q", gotChatID, "111222")
	}
}
