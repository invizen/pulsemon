package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- card / subject builders (no network) ---

func TestSmtpBody(t *testing.T) {
	b := smtpBody("up", "error", "zenkub1", "192.168.1.10", 0)
	for _, want := range []string{
		"❌", "pulsemon: error", "Sensor: zenkub1",
		"Target: 192.168.1.10", "State: error",
	} {
		if !strings.Contains(b, want) {
			t.Fatalf("smtpBody missing %q in:\n%s", want, b)
		}
	}
	// No RTT for a down ICMP sensor: no Ping line.
	if strings.Contains(b, "Ping:") {
		t.Fatalf("unexpected Ping line in down body:\n%s", b)
	}
}

func TestSmtpBodyWithRTT(t *testing.T) {
	b := smtpBody("up", "warning", "nas", "10.0.0.5", 120.4)
	if !strings.Contains(b, "Ping: 120 ms") {
		t.Fatalf("expected Ping line, got:\n%s", b)
	}
}

func TestSmtpBodyRe(t *testing.T) {
	b := smtpBodyRe("error", "zenkub1", "192.168.1.10", 0)
	for _, want := range []string{"❌", "re-alert", "State: error"} {
		if !strings.Contains(b, want) {
			t.Fatalf("smtpBodyRe missing %q in:\n%s", want, b)
		}
	}
}

func TestSmtpSubject(t *testing.T) {
	if got := smtpSubject("error", "up"); got != "✅ pulsemon: recovered" {
		t.Fatalf("recovery subject = %q", got)
	}
	if got := smtpSubject("error", "warning"); got != "⚠️ pulsemon: partial recovery" {
		t.Fatalf("partial-recovery subject = %q", got)
	}
	if got := smtpSubject("up", "error"); got != "pulsemon: error" {
		t.Fatalf("error subject = %q", got)
	}
}

func TestSmtpPort(t *testing.T) {
	cases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"587", 587, false},
		{"465", 465, false},
		{"25", 25, false},
		{"  993  ", 993, false}, // trimmed
		{"0", 0, true},          // out of range
		{"65536", 0, true},      // out of range
		{"abc", 0, true},        // not a number
		{"", 0, true},           // empty
	}
	for _, c := range cases {
		got, err := smtpPort(c.in)
		if c.wantErr && err == nil {
			t.Fatalf("smtpPort(%q): expected error, got %d", c.in, got)
		}
		if !c.wantErr && err != nil {
			t.Fatalf("smtpPort(%q): unexpected error %v", c.in, err)
		}
		if !c.wantErr && got != c.want {
			t.Fatalf("smtpPort(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestSmtpHasURL(t *testing.T) {
	db := newTestDB(t)
	// No host, no to → false.
	if smtpHasURL(db) {
		t.Fatal("expected false with no config")
	}
	// Host only (no recipient) → false: a host alone can't deliver.
	db.SetSetting("smtp_host", "smtp.example.com")
	if smtpHasURL(db) {
		t.Fatal("expected false with host but no recipient")
	}
	// Both → true.
	db.SetSetting("smtp_to", "ops@example.com")
	if !smtpHasURL(db) {
		t.Fatal("expected true with host and recipient")
	}
}

func TestSmtpConfigDefaults(t *testing.T) {
	db := newTestDB(t)
	pw := NewProbeWorker(db)
	cfg := pw.smtpConfig()
	// No port set → default 587.
	if cfg.Port != 587 {
		t.Fatalf("default port = %d, want 587", cfg.Port)
	}
	// No tls_mode set → default auto.
	if cfg.TLS != "auto" {
		t.Fatalf("default tls = %q, want auto", cfg.TLS)
	}
	// Explicit values are honored.
	db.SetSetting("smtp_host", "mail.local")
	db.SetSetting("smtp_port", "25")
	db.SetSetting("smtp_tls_mode", "none")
	db.SetSetting("smtp_from", "a@b.c")
	db.SetSetting("smtp_to", "x@y.z")
	cfg = pw.smtpConfig()
	if cfg.Host != "mail.local" || cfg.Port != 25 || cfg.TLS != "none" || cfg.From != "a@b.c" || cfg.To != "x@y.z" {
		t.Fatalf("smtpConfig did not honor explicit values: %+v", cfg)
	}
}

// --- settings persistence (mirrors the Telegram settings test) ---

func TestApplyProviderUpdateSMTP(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))

	extra := map[string]string{
		"port": "587", "from": "pulsemon@home.lan", "to": "ops@home.lan",
		"username": "pulsemon", "tls_mode": "starttls",
	}
	if err := srv.applyProviderUpdate("smtp", strPtr("10.0.0.25"), boolPtr(true), extra); err != nil {
		t.Fatalf("applyProviderUpdate smtp: %v", err)
	}
	// Host is stored under smtp_host (the URL field is repurposed as host).
	if got := db.GetSetting("smtp_host"); got != "10.0.0.25" {
		t.Fatalf("smtp_host = %q, want 10.0.0.25", got)
	}
	if got := db.GetSetting("smtp_port"); got != "587" {
		t.Fatalf("smtp_port = %q, want 587", got)
	}
	if got := db.GetSetting("smtp_to"); got != "ops@home.lan" {
		t.Fatalf("smtp_to = %q, want ops@home.lan", got)
	}
	if got := db.GetSetting("smtp_enabled"); got != "1" {
		t.Fatalf("smtp_enabled = %q, want 1", got)
	}
}

func TestApplyProviderUpdateSMTPRejectsBadPort(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	if err := srv.applyProviderUpdate("smtp", strPtr("10.0.0.25"), nil, map[string]string{"port": "notanumber"}); err == nil {
		t.Fatal("expected bad port to be rejected, got nil")
	}
}

func TestApplyProviderUpdateSMTPRejectsBadTLSMode(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	if err := srv.applyProviderUpdate("smtp", strPtr("10.0.0.25"), nil, map[string]string{"tls_mode": "weird"}); err == nil {
		t.Fatal("expected bad tls_mode to be rejected, got nil")
	}
}

// --- end-to-end: a real in-process plaintext SMTP server ---
//
// Exercises sendSMTP over a real TCP socket (no transport mocking): the server
// speaks EHLO/MAIL/RCPT/DATA/QUIT and captures the message, then we assert the
// subject and body arrived intact.
func TestSendSMTPEndToEnd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	host, portStr, _ := net.SplitHostPort(addr)

	var mu sync.Mutex
	var subject, body string
	done := make(chan struct{})

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(done)
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
				close(done)
				return
			}
			trimmed := strings.TrimRight(line, "\r\n")
			upper := strings.ToUpper(trimmed)
			switch {
			case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
				w("250-test\r\n250 OK\r\n")
			case strings.HasPrefix(upper, "MAIL"):
				w("250 OK\r\n")
			case strings.HasPrefix(upper, "RCPT"):
				w("250 OK\r\n")
			case strings.HasPrefix(upper, "DATA"):
				w("354 go ahead\r\n")
				dataMode = true
			case dataMode:
				if trimmed == "." {
					dataMode = false
					mu.Lock()
					body = strings.Join(dataLines, "\n")
					for _, l := range dataLines {
						if strings.HasPrefix(l, "Subject: ") {
							subject = strings.TrimPrefix(l, "Subject: ")
						}
					}
					mu.Unlock()
					w("250 OK\r\n")
					close(done) // message fully received; unblock the test
				} else {
					dataLines = append(dataLines, trimmed)
				}
			case strings.HasPrefix(upper, "QUIT"):
				w("221 bye\r\n")
				return
			default:
				w("250 OK\r\n")
			}
		}
	}()

	db := newTestDB(t)
	db.SetSetting("smtp_host", host)
	db.SetSetting("smtp_port", portStr)
	db.SetSetting("smtp_from", "pulsemon@test.local")
	db.SetSetting("smtp_to", "ops@test.local")
	db.SetSetting("smtp_tls_mode", "none")
	pw := NewProbeWorker(db)

	// The production dial (smtpDial = dialChecked) refuses loopback by
	// design — this test needs a plain dialer to reach the in-process
	// server on 127.0.0.1.
	origDial := smtpDial
	smtpDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
	}
	t.Cleanup(func() { smtpDial = origDial })

	if err := pw.sendSMTP(t.Context(), "pulsemon: error", "❌ pulsemon: error\nSensor: zenkub1"); err != nil {
		t.Fatalf("sendSMTP: %v", err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the SMTP server to receive the message")
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(body, "❌ pulsemon: error") || !strings.Contains(body, "Sensor: zenkub1") {
		t.Fatalf("server did not receive expected body:\n%s", body)
	}
	if subject != "pulsemon: error" {
		t.Fatalf("server subject = %q, want %q", subject, "pulsemon: error")
	}
}

// TestSendSMTPRefusesLoopbackEndToEnd pins the dial-time blocklist on the
// SMTP path: a stored host that is a reserved address must be refused at dial
// time — the same guarantee the webhook path proves in
// TestWebhookClientRefusesLoopbackEndToEnd. Uses the DEFAULT smtpDial
// (dialChecked); no seam override, so this is the production code path.
func TestSendSMTPRefusesLoopbackEndToEnd(t *testing.T) {
	for _, reserved := range []string{"127.0.0.1", "169.254.169.254"} {
		db := newTestDB(t)
		db.SetSetting("smtp_host", reserved)
		db.SetSetting("smtp_port", "25")
		db.SetSetting("smtp_from", "pulsemon@test.local")
		db.SetSetting("smtp_to", "ops@test.local")
		db.SetSetting("smtp_tls_mode", "none")
		pw := NewProbeWorker(db)
		err := pw.sendSMTP(t.Context(), "pulsemon: test", "body")
		if err == nil {
			t.Fatalf("sendSMTP connected to reserved host %s, want a blocked-address refusal", reserved)
		}
		if !strings.Contains(err.Error(), "blocked address") {
			t.Fatalf("sendSMTP(%s) error = %q, want a 'blocked address' refusal", reserved, err)
		}
	}
}

// TestApplyProviderUpdateSMTPRejectsExtraHost pins the extra-fields bypass
// fix: "host" is no longer an accepted extra key for smtp — the host travels
// in the url field, where validateSMTPHost enforces the reserved-range
// blocklist. The extra loop persists its keys without host validation, so
// accepting "host" there let a client write smtp_host (e.g. 127.0.0.1)
// straight to SQLite, bypassing the check.
func TestApplyProviderUpdateSMTPRejectsExtraHost(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	err := srv.applyProviderUpdate("smtp", nil, nil, map[string]string{"host": "127.0.0.1"})
	if err == nil {
		t.Fatal("expected extra host to be rejected, got nil")
	}
	if got := db.GetSetting("smtp_host"); got != "" {
		t.Fatalf("smtp_host = %q, want empty (extra host must not persist)", got)
	}
}

// tarpitListener accepts TCP connections and then says nothing — the
// worst-case relay: the 220 greeting never arrives, so any sendSMTP phase
// that reads the socket blocks until a deadline or cancellation frees it.
func tarpitListener(t *testing.T) (host, port string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tarpit listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn // deliberately held open and silent
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	return h, p
}

// TestSendSMTPDeadlineBoundsHungGreeting pins the conn-deadline fix: a relay
// that accepts TCP and never sends the 220 greeting must not block sendSMTP
// forever — the absolute conn deadline (smtpConnDeadline) turns the hang into
// a bounded error. Pre-fix this test hangs until -test.timeout kills it.
func TestSendSMTPDeadlineBoundsHungGreeting(t *testing.T) {
	host, port := tarpitListener(t)
	db := newTestDB(t)
	db.SetSetting("smtp_host", host)
	db.SetSetting("smtp_port", port)
	db.SetSetting("smtp_from", "pulsemon@test.local")
	db.SetSetting("smtp_to", "ops@test.local")
	db.SetSetting("smtp_tls_mode", "none")
	pw := NewProbeWorker(db)

	origDial := smtpDial
	smtpDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
	}
	origDeadline := smtpConnDeadline
	smtpConnDeadline = 700 * time.Millisecond
	t.Cleanup(func() { smtpDial = origDial; smtpConnDeadline = origDeadline })

	start := time.Now()
	err := pw.sendSMTP(t.Context(), "subject", "body")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("sendSMTP succeeded against a silent relay, want a deadline error")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("hung greeting not bounded by the conn deadline: %v", elapsed)
	}
}

// TestSendSMTPContextCancelAborts pins the context.AfterFunc fix: cancelling
// ctx (what StopAlerts does at shutdown, what an abandoned test request does)
// must abort an in-flight SMTP conversation. net/smtp has no ctx-aware API —
// the abort is a conn close. The conn deadline is set LONG here on purpose:
// the test must return via CANCELLATION, not the deadline, proving the
// AfterFunc path. Pre-fix, a cancelled ctx left the delivery blocked on the
// socket read forever.
func TestSendSMTPContextCancelAborts(t *testing.T) {
	host, port := tarpitListener(t)
	db := newTestDB(t)
	db.SetSetting("smtp_host", host)
	db.SetSetting("smtp_port", port)
	db.SetSetting("smtp_from", "pulsemon@test.local")
	db.SetSetting("smtp_to", "ops@test.local")
	db.SetSetting("smtp_tls_mode", "none")
	pw := NewProbeWorker(db)

	origDial := smtpDial
	smtpDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
	}
	origDeadline := smtpConnDeadline
	smtpConnDeadline = 30 * time.Second
	t.Cleanup(func() { smtpDial = origDial; smtpConnDeadline = origDeadline })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- pw.sendSMTP(ctx, "subject", "body") }()
	time.Sleep(200 * time.Millisecond) // let it reach the greeting read
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("sendSMTP returned nil after ctx cancellation, want an abort error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ctx cancellation did not abort the in-flight SMTP conversation")
	}
}
