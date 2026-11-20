package main

// Finding 23 (SMTP transport edge cases): the tls_mode switch in
// sendSMTPWith had two gaps — it ran the STARTTLS probe in case "auto" even
// when the conn was already implicit-TLS (auto+465), and it had no
// fail-closed default for an unknown mode (a legacy/corrupt stored value
// would fall through to plaintext). These pins lock both.

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// TestWantsStartTLSMatrix locks the finding-23 SMTP guard: wantsStartTLS is
// the exact predicate the sendSMTPWith switch uses to decide whether to
// attempt a STARTTLS upgrade. The critical case is auto+465 → false: auto on
// the implicit-TLS port must NOT attempt a nested STARTTLS on the
// already-encrypted wire (pre-fix it did, and a relay advertising STARTTLS
// would make the send fail).
func TestWantsStartTLSMatrix(t *testing.T) {
	cases := []struct {
		tls  string
		port int
		want bool
	}{
		{"starttls", 587, true},
		{"starttls", 465, true}, // explicit starttls is honored (starttls+465 is the operator's choice)
		{"auto", 587, true},     // opportunistic on a non-465 port
		{"auto", 25, true},
		{"auto", 465, false}, // THE FIX: auto+465 is implicit TLS, no nested STARTTLS
		{"none", 587, false},
		{"none", 465, false},
		{"tls", 465, false},
		{"tls", 587, false},
		{"bogus", 587, false}, // unknown mode → false (the caller fail-closes)
		{"", 587, false},      // empty (shouldn't reach send: smtpConfig defaults to auto)
	}
	for _, c := range cases {
		if got := wantsStartTLS(smtpConfig{TLS: c.tls, Port: c.port}); got != c.want {
			t.Errorf("wantsStartTLS(tls=%q port=%d) = %v, want %v", c.tls, c.port, got, c.want)
		}
	}
}

// plaintextSMTPServer starts an in-process plaintext SMTP relay on
// 127.0.0.1:0 that speaks 220/EHLO/MAIL/RCPT/DATA/QUIT. advertiseStartTLS
// controls whether EHLO offers STARTTLS. It returns the host:port and a done
// channel closed when the message is fully received (or the conn drops).
func plaintextSMTPServer(t *testing.T, advertiseStartTLS bool) (addr string, done chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	done = make(chan struct{})
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
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				close(done)
				return
			}
			trimmed := strings.TrimRight(line, "\r\n")
			upper := strings.ToUpper(trimmed)
			switch {
			case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
				if advertiseStartTLS {
					w("250-STARTTLS\r\n250 OK\r\n")
				} else {
					w("250 OK\r\n")
				}
			case dataMode:
				if trimmed == "." {
					dataMode = false
					w("250 OK\r\n")
					close(done)
					// No return: keep the conn open for the client's QUIT.
				}
			case strings.HasPrefix(upper, "DATA"):
				w("354 go ahead\r\n")
				dataMode = true
			case strings.HasPrefix(upper, "QUIT"):
				w("221 bye\r\n")
				return
			default:
				w("250 OK\r\n")
			}
		}
	}()
	return ln.Addr().String(), done
}

// TestSendSMTPUnknownTLSModeFailsClosed locks the finding-23 fail-closed
// default: an unknown tls_mode (a legacy/corrupt stored value that slipped
// past save-time validation) must return a hard error, never silently fall
// through to plaintext. The server advertises STARTTLS so the ONLY reason
// the send fails is the unknown-mode guard, not a missing extension.
func TestSendSMTPUnknownTLSModeFailsClosed(t *testing.T) {
	addr, _ := plaintextSMTPServer(t, true)
	host, portStr, _ := net.SplitHostPort(addr)

	db := newTestDB(t)
	db.SetSetting("smtp_host", host)
	db.SetSetting("smtp_port", portStr)
	db.SetSetting("smtp_from", "pulsemon@test.local")
	db.SetSetting("smtp_to", "ops@test.local")
	db.SetSetting("smtp_tls_mode", "bogus")
	pw := NewProbeWorker(db)

	origDial := smtpDial
	smtpDial = func(ctx context.Context, network, daddr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, daddr)
	}
	t.Cleanup(func() { smtpDial = origDial })

	err := pw.sendSMTP(t.Context(), "pulsemon: test", "body")
	if err == nil {
		t.Fatal("sendSMTP with an unknown tls_mode succeeded, want a fail-closed error")
	}
	if !strings.Contains(err.Error(), "unknown tls_mode") {
		t.Fatalf("sendSMTP error = %q, want an 'unknown tls_mode' refusal", err)
	}
}

// TestSendSMTPAutoPlaintextNoStartTLS pins that the auto guard did not break
// the legitimate case: auto on a non-465 relay that does NOT advertise
// STARTTLS still delivers (opportunistic → falls back to plaintext, no
// credentials configured). This is the wantsStartTLS=true + extension-false
// path of the switch.
func TestSendSMTPAutoPlaintextNoStartTLS(t *testing.T) {
	addr, done := plaintextSMTPServer(t, false)
	host, portStr, _ := net.SplitHostPort(addr)

	db := newTestDB(t)
	db.SetSetting("smtp_host", host)
	db.SetSetting("smtp_port", portStr)
	db.SetSetting("smtp_from", "pulsemon@test.local")
	db.SetSetting("smtp_to", "ops@test.local")
	db.SetSetting("smtp_tls_mode", "auto")
	pw := NewProbeWorker(db)

	origDial := smtpDial
	smtpDial = func(ctx context.Context, network, daddr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, daddr)
	}
	t.Cleanup(func() { smtpDial = origDial })

	if err := pw.sendSMTP(t.Context(), "pulsemon: test", "body"); err != nil {
		t.Fatalf("sendSMTP auto (no STARTTLS offered): %v", err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the SMTP server to receive the message")
	}
}
