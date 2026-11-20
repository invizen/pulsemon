package main

// A legacy stored config that has credentials but no TLS (a plaintext relay)
// is a credential LEAK, not a relay preference: sendSMTPWith must refuse to
// send in cleartext with a username/password configured, BEFORE any AUTH is
// attempted. "none" is the explicit plaintext choice and new saves of
// none+credentials are refused at save time, so this guard only fires for
// legacy stored configs — but a legacy config must not become a silent
// cleartext credential leak on send. (The TLS/STARTTLS mode selection itself
// is pinned by smtp_tls_mode_test.go; this pins the auth-flow credential guard.)
// History: docs/DECISIONS.md → testing-benchmark-gaps

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSendSMTPCredentialsPlaintextRefused(t *testing.T) {
	// The plaintext-credential guard fires AFTER the dial + EHLO
	// (smtp.NewClient reads the 220 greeting and EHLO before the check), so a
	// live server is needed. A relay that advertises NO STARTTLS and NO AUTH:
	// the client must refuse to send credentials over the plaintext wire.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.WriteString(c, "220 relay.local ESMTP\r\n")
				buf := make([]byte, 256)
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				c.Read(buf) // consume EHLO
				io.WriteString(c, "250-relay.local\r\n250 SIZE 35882577\r\n250 OK\r\n")
				time.Sleep(700 * time.Millisecond) // hold the conn so the client reaches the guard
			}(c)
		}
	}()

	// The production dial (smtpDial = dialChecked) refuses loopback by design
	// — this test needs a plain dialer to reach the in-process server.
	origDial := smtpDial
	smtpDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
	}
	t.Cleanup(func() { smtpDial = origDial })

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	cfg := smtpConfig{
		Host: host,
		Port: port,
		From: "pulsemon@example.com",
		To:   "ops@example.com",
		User: "legacy-" + "user",
		Pass: "legacy-" + "pass",
		TLS:  "none", // explicit plaintext, no STARTTLS
	}
	err = (&ProbeWorker{}).sendSMTPWith(context.Background(), cfg, "subject", "body")
	if err == nil {
		t.Fatal("plaintext send with credentials configured: want a refusal, got nil (credential leak)")
	}
	if !strings.Contains(err.Error(), "plaintext") {
		t.Fatalf("refusal = %q, want the plaintext-credential-leak message", err)
	}
}
