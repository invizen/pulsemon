package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Tests for the SMTP delivery budget + classification fixes (external review
// MAJOR-14): one 15s total transport budget (dial + conversation), a QUIT
// failure after the MTA accepted the message must not fail the delivery
// (no duplicate resends), and permanent 5xx server replies must not be
// retried (no fail2ban/lockout factories).

// plainSMTPServer speaks a minimal plaintext conversation and, per its
// flags: onQuitDrops closes the socket on QUIT WITHOUT a 221 (an MTA that
// drops the connection after accepting the message), rejectRCPT answers
// RCPT TO with a permanent 550. It counts accepted connections (one per
// delivery attempt).
func plainSMTPServer(t *testing.T, onQuitDrops, rejectRCPT bool) (host, port string, attempts func() int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var n int
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			n++
			mu.Unlock()
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				w := func(s string) { fmt.Fprint(c, s) }
				w("220 test ESMTP\r\n")
				dataMode := false
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					trimmed := strings.TrimRight(line, "\r\n")
					upper := strings.ToUpper(trimmed)
					switch {
					case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
						w("250-test\r\n250 OK\r\n")
					case strings.HasPrefix(upper, "AUTH"):
						w("535 5.7.8 Authentication credentials invalid\r\n")
					case strings.HasPrefix(upper, "MAIL"):
						w("250 OK\r\n")
					case strings.HasPrefix(upper, "RCPT"):
						if rejectRCPT {
							w("550 5.1.1 no such user\r\n")
						} else {
							w("250 OK\r\n")
						}
					case strings.HasPrefix(upper, "DATA"):
						w("354 go ahead\r\n")
						dataMode = true
					case dataMode:
						if trimmed == "." {
							dataMode = false
							w("250 OK\r\n")
						}
					case strings.HasPrefix(upper, "QUIT"):
						if !onQuitDrops {
							w("221 bye\r\n")
						}
						return // with onQuitDrops: close WITHOUT the 221
					default:
						w("250 OK\r\n")
					}
				}
			}(conn)
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	return h, p, func() int { mu.Lock(); defer mu.Unlock(); return n }
}

// TestSMTPQuitFailureAfterAcceptIsNotAnError pins the QUIT fix: the MTA
// returned 250 OK to the DATA end (the message is ACCEPTED), then drops the
// socket on QUIT. Pre-fix sendSMTPWith returned c.Quit()'s error and
// retryAlert resends the already-accepted email (up to 3x duplicates).
func TestSMTPQuitFailureAfterAcceptIsNotAnError(t *testing.T) {
	host, port, attempts := plainSMTPServer(t, true, false)
	loopbackDial(t)
	pw := NewProbeWorker(newTestDB(t))
	cfg := smtpConfig{Host: host, Port: mustPort(t, port), From: "a@b.c", To: "x@y.z", TLS: "none"}

	start := time.Now()
	err := pw.sendSMTPWith(t.Context(), cfg, "pulsemon: test", "body")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("sendSMTPWith returned %v after the MTA accepted the message (250 OK) and dropped QUIT; a QUIT failure must not fail a delivered email", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("delivery took %v; the QUIT EOF must not stall the send", elapsed)
	}
	if n := attempts(); n != 1 {
		t.Fatalf("server saw %d connections, want 1 (no resend of an accepted message)", n)
	}
}

// TestSMTPTotalBudgetCoversDial pins the 15s TOTAL budget: the dial phase
// consumes budget time, so a dial that alone exceeds smtpConnDeadline must
// fail fast. Pre-fix the dial had its own 10s context and the conversation
// a separate 15s deadline (25s/attempt → 87s worst job, over the 60s FIFO
// recovery budget).
func TestSMTPTotalBudgetCoversDial(t *testing.T) {
	host, port, _ := plainSMTPServer(t, false, false)
	// A dial that SUCCEEDS, but only after 400ms — longer than the 250ms
	// total budget below. Pre-fix (own 10s dial context) this dial
	// succeeded and the send completed; post-fix the budget expires during
	// the dial and the attempt fails at ~250ms.
	origDial := smtpDial
	smtpDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		select {
		case <-time.After(400 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(ctx, network, addr)
	}
	t.Cleanup(func() { smtpDial = origDial })
	origDeadline := smtpConnDeadline
	smtpConnDeadline = 250 * time.Millisecond
	t.Cleanup(func() { smtpConnDeadline = origDeadline })

	pw := NewProbeWorker(newTestDB(t))
	cfg := smtpConfig{Host: host, Port: mustPort(t, port), From: "a@b.c", To: "x@y.z", TLS: "none"}
	start := time.Now()
	err := pw.sendSMTPWith(t.Context(), cfg, "pulsemon: test", "body")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a dial exceeding the total transport budget succeeded; dial + conversation must share ONE smtpConnDeadline budget")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("over-budget dial took %v; the shared 250ms budget must fail the attempt fast", elapsed)
	}
}

// TestSMTPPermanent5xxNotRetried pins the retry classification end-to-end
// through deliverOne: a permanent 5xx refusal (550 no such user — the
// 535-auth case is covered by the unit pin) cannot succeed on retry and
// re-hitting it is a fail2ban/account-lockout factory. Pre-fix deliverOne
// retried every non-not-configured error: 3 attempts at the same refusal.
// (Credential-free config: with a username stored, tls_mode=none is
// refused by the plaintext-credential guard before AUTH is ever sent.)
func TestSMTPPermanent5xxNotRetried(t *testing.T) {
	host, port, attempts := plainSMTPServer(t, false, true)
	loopbackDial(t)
	pw := NewProbeWorker(newTestDB(t))
	t.Cleanup(pw.StopAlerts)
	cfg := smtpConfig{Host: host, Port: mustPort(t, port), From: "a@b.c", To: "x@y.z", TLS: "none"}
	d := dest{p: providerMeta{Kind: "smtp"}, url: host, smtp: &cfg}

	start := time.Now()
	ok := pw.deliverOne(d, "s1", "127.0.0.1", "up", "error", 0, false)
	elapsed := time.Since(start)
	if ok {
		t.Fatal("deliverOne reported success on a 535-auth refusal")
	}
	if n := attempts(); n != 1 {
		t.Fatalf("server saw %d connections, want 1: a permanent 535 must not be retried (fail2ban/lockout factory)", n)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("delivery took %v; a non-retryable refusal must fail fast, not run out the 2s+10s retry delays", elapsed)
	}
}

// TestSMTPPermanentClassification pins the classifier itself: 5xx server
// replies (wrapped or bare) are permanent; 4xx replies are transient by RFC;
// transport errors are retryable.
func TestSMTPPermanentClassification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"535 auth failed", &textproto.Error{Code: 535, Msg: "5.7.8 Authentication credentials invalid"}, true},
		{"550 recipient rejected", &textproto.Error{Code: 550, Msg: "5.1.1 no such user"}, true},
		{"554 transaction failed", &textproto.Error{Code: 554, Msg: "5.3.5 rate limited"}, true},
		{"501 syntax error", &textproto.Error{Code: 501, Msg: "5.5.2 bad address"}, true},
		{"wrapped 535", fmt.Errorf("smtp auth: %w", &textproto.Error{Code: 535, Msg: "auth failed"}), true},
		{"450 transient", &textproto.Error{Code: 450, Msg: "4.2.1 try again later"}, false},
		{"421 closing connection", &textproto.Error{Code: 421, Msg: "4.3.2 too many connections"}, false},
		{"dial refused", errors.New("smtp dial 127.0.0.1:587: connection refused"), false},
		{"dial timeout", &net.DNSError{Err: "i/o timeout", IsTimeout: true}, false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		if got := smtpPermanent(c.err); got != c.want {
			t.Fatalf("smtpPermanent(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

func mustPort(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("bad port %q: %v", s, err)
	}
	return n
}
