package main

// SMTP snapshot-resolution pins (m2): the mail config rides the alert
// settings snapshot like the Telegram chat_id, so the delivery hot path
// performs ZERO settings reads. Pre-fix, sendSMTP ran 7 swallow-to-""
// GetSetting calls per send: a transient DB lock degraded into
// "not configured", which the in-band retry loop classifies as permanent
// and skips.

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http/httptest"
	"pulsemon/internal/store"
	"strings"
	"sync"
	"testing"
	"time"
)

// smtpTestServer is a minimal in-process plaintext SMTP relay that
// captures the delivered message; returns the listen host/port and a
// channel closed once the message is fully received.
func smtpTestServer(t *testing.T) (host, port string, got func() string, done <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	h, p, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	var mu sync.Mutex
	var body string
	ch := make(chan struct{})
	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			close(ch)
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		w := func(s string) { fmt.Fprint(conn, s) }
		w("220 test ESMTP\r\n")
		dataMode := false
		var dataLines []string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				mu.Lock()
				body = strings.Join(dataLines, "\n")
				mu.Unlock()
				close(ch)
				return
			}
			trimmed := strings.TrimRight(line, "\r\n")
			upper := strings.ToUpper(trimmed)
			switch {
			case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
				w("250-test\r\n250 OK\r\n")
			case strings.HasPrefix(upper, "MAIL"), strings.HasPrefix(upper, "RCPT"):
				w("250 OK\r\n")
			case strings.HasPrefix(upper, "DATA"):
				w("354 go ahead\r\n")
				dataMode = true
			case dataMode:
				if trimmed == "." {
					dataMode = false
					mu.Lock()
					body = strings.Join(dataLines, "\n")
					mu.Unlock()
					w("250 OK\r\n")
					close(ch)
					// stay in the loop: the client still has QUIT to
					// send, and hanging up first would fail the send.
				}
				dataLines = append(dataLines, trimmed)
			case strings.HasPrefix(upper, "QUIT"):
				w("221 bye\r\n")
				return
			default:
				w("250 OK\r\n")
			}
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return h, p, func() string { mu.Lock(); defer mu.Unlock(); return body }, ch
}

// loopbackDial overrides smtpDial for tests: production dialChecked
// refuses loopback by design.
func loopbackDial(t *testing.T) {
	t.Helper()
	orig := smtpDial
	smtpDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
	}
	t.Cleanup(func() { smtpDial = orig })
}

// TestSMTPDestCarriesSnapshotConfig: the snapshot resolves the FULL mail
// config into the dest (not just the host), defaults included.
func TestSMTPDestCarriesSnapshotConfig(t *testing.T) {
	db := newTestDB(t)
	db.SetSetting("smtp_enabled", "1")
	db.SetSetting("smtp_host", "mail.test.local")
	db.SetSetting("smtp_port", "2525")
	db.SetSetting("smtp_from", "alert@test.local")
	db.SetSetting("smtp_to", "ops@test.local")
	db.SetSetting("smtp_username", "user")
	db.SetSetting("smtp_password", "secret")
	db.SetSetting("smtp_tls_mode", "starttls")
	pw := NewProbeWorker(db) // loads the snapshot
	dests, ok := pw.resolveDestinations()
	if !ok || len(dests) != 1 || dests[0].p.Kind != "smtp" {
		t.Fatalf("dests = %+v ok=%v, want exactly one smtp dest", dests, ok)
	}
	cfg := dests[0].smtp
	if cfg == nil {
		t.Fatal("smtp dest carries no resolved config (delivery would read settings live)")
	}
	if cfg.Host != "mail.test.local" || cfg.Port != 2525 || cfg.From != "alert@test.local" ||
		cfg.To != "ops@test.local" || cfg.User != "user" || cfg.Pass != "secret" || cfg.TLS != "starttls" {
		t.Fatalf("resolved config = %+v, want all seven seeded keys", *cfg)
	}
}

// TestSMTPDeliveryZeroSettingsReads is the sabotage pin: with a good
// snapshot in place, the delivery path must not touch the DB at all —
// proven by CLOSING the store. Pre-fix, the closed DB mapped all 7
// GetSetting reads to "" and the send died as non-retryable
// "not configured"; now the dest carries everything.
func TestSMTPDeliveryZeroSettingsReads(t *testing.T) {
	host, port, got, done := smtpTestServer(t)
	db := newTestDB(t)
	db.SetSetting("smtp_enabled", "1")
	db.SetSetting("smtp_host", host)
	db.SetSetting("smtp_port", port)
	db.SetSetting("smtp_from", "pulsemon@test.local")
	db.SetSetting("smtp_to", "ops@test.local")
	db.SetSetting("smtp_tls_mode", "none")
	pw := NewProbeWorker(db) // snapshot resolves the smtp dest + config

	dests, ok := pw.resolveDestinations()
	if !ok || len(dests) != 1 || dests[0].smtp == nil {
		t.Fatalf("want one smtp dest with resolved config, got %+v ok=%v", dests, ok)
	}

	loopbackDial(t)

	if err := db.Close(); err != nil {
		t.Fatalf("closing the test store: %v", err)
	}
	if !pw.deliverOne(dests[0], "zenkub1", "10.0.0.1", "ok", "error", 12.5, false) {
		t.Fatal("smtp delivery with the DB closed failed: the delivery path still reads settings live")
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the relay to receive the message")
	}
	if body := got(); !strings.Contains(body, "zenkub1") {
		t.Fatalf("relay received %q, want the sensor alert body", body)
	}
}

// TestTestWebhookSMTPSurfacesDBError: the settings Test button must map a
// bulk-read failure to a database error, never to "not configured".
func TestTestWebhookSMTPSurfacesDBError(t *testing.T) {
	db := newTestDB(t)
	db.SetSetting("smtp_enabled", "1")
	db.SetSetting("smtp_host", "mail.test.local")
	db.SetSetting("smtp_port", "25")
	db.SetSetting("smtp_from", "a@test.local")
	db.SetSetting("smtp_to", "b@test.local")
	pw := NewProbeWorker(db)

	orig := getAllSettings
	getAllSettings = func(*store.Store) (map[string]string, error) {
		return nil, fmt.Errorf("SQLITE_BUSY: simulated transient lock")
	}
	t.Cleanup(func() { getAllSettings = orig })

	req := httptest.NewRequest("POST", "/api/test-webhook", nil)
	ok, msg := pw.TestWebhook(req.Context(), "smtp")
	if ok || msg != "database error reading provider settings" {
		t.Fatalf("TestWebhook(smtp) = (%v, %q), want (false, database error)", ok, msg)
	}
}
