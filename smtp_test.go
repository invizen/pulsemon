package main

import (
	"bufio"
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
	if err := srv.applyProviderUpdate("smtp", strPtr("smtp.home.lan"), boolPtr(true), extra); err != nil {
		t.Fatalf("applyProviderUpdate smtp: %v", err)
	}
	// Host is stored under smtp_host (the URL field is repurposed as host).
	if got := db.GetSetting("smtp_host"); got != "smtp.home.lan" {
		t.Fatalf("smtp_host = %q, want smtp.home.lan", got)
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
	if err := srv.applyProviderUpdate("smtp", strPtr("smtp.home.lan"), nil, map[string]string{"port": "notanumber"}); err == nil {
		t.Fatal("expected bad port to be rejected, got nil")
	}
}

func TestApplyProviderUpdateSMTPRejectsBadTLSMode(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	if err := srv.applyProviderUpdate("smtp", strPtr("smtp.home.lan"), nil, map[string]string{"tls_mode": "weird"}); err == nil {
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
