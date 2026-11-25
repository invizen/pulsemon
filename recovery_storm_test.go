package main

// MAJOR-6 (2026-11-25): a mass recovery after an outage bypassed storm
// coalescing (stormAdmit admitted every recovery unconditionally), fanned
// out N×providers concurrent deliveries against unbounded transport dials
// (MaxConnsPerHost 0) and uncapped SMTP sessions, and re-fired every
// failed recovery in lockstep 60s later (unjittered recoveryRetryDelay) —
// a second thundering herd that dropped most recovery alerts. These pins
// cover the symmetric recovery storm budget, the transport/SMTP caps, and
// the retry jitter.
// History: docs/DECISIONS.md → recovery-storm-budget.

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// withRecoveryStormBudget runs fn with the recovery storm budget shrunk to
// (budget, window), restoring the originals afterwards.
func withRecoveryStormBudget(t *testing.T, budget int, window time.Duration, fn func()) {
	t.Helper()
	oldBudget, oldWindow := recoveryStormBudget, recoveryStormWindow
	recoveryStormBudget, recoveryStormWindow = budget, window
	defer func() { recoveryStormBudget, recoveryStormWindow = oldBudget, oldWindow }()
	fn()
}

// TestRecoveryStormIndependentBudgets: the down-storm and recovery-storm
// budgets are SEPARATE — a down storm burning its budget must not consume
// recovery budget, and vice versa. A mass outage followed by a mass
// recovery must coalesce in both directions without starving either.
func TestRecoveryStormIndependentBudgets(t *testing.T) {
	withStormBudget(t, 0, 500*time.Millisecond, func() {
		withRecoveryStormBudget(t, 10, 500*time.Millisecond, func() {
			withPlainTransport(t, func() { // loopback httptest vs the SSRF blocklist
				pw, db, getBodies, cleanup := newStormTestWorker(t)
				defer cleanup()
				insertStormSensor(t, db, "d0")
				insertStormSensor(t, db, "r0")
				if _, err := db.Exec(`UPDATE sensors SET status = 'error' WHERE id = 'd0'`); err != nil {
					t.Fatalf("set d0 error: %v", err)
				}
				if _, err := db.Exec(`UPDATE sensors SET status = 'up' WHERE id = 'r0'`); err != nil {
					t.Fatalf("set r0 up: %v", err)
				}
				// d0's down alert is coalesced (down budget 0); r0's
				// recovery is delivered individually (recovery budget 10,
				// untouched by the down storm).
				pw.launchAlert(func() { pw.sendAlert("d0", "d0", "127.0.0.1", "up", "error", 0) })
				pw.launchAlert(func() { pw.sendAlert("r0", "r0", "127.0.0.1", "error", "up", 0) })
				// The down summary lands at window end (500ms); the
				// recovery card lands immediately. Poll for both.
				var bodies []string
				deadline := time.Now().Add(2 * time.Second)
				for {
					bodies = getBodies()
					if len(bodies) >= 2 || time.Now().After(deadline) {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				var sawDownSummary, sawRecoveryCard bool
				for _, b := range bodies {
					if strings.Contains(b, "alert storm") && strings.Contains(b, "d0") {
						sawDownSummary = true
					}
					if strings.Contains(b, "recovered") && strings.Contains(b, "r0") {
						sawRecoveryCard = true
					}
				}
				joined := strings.Join(bodies, "\n---\n")
				if !sawDownSummary {
					t.Errorf("d0's down alert must be coalesced into a down storm summary:\n%s", joined)
				}
				if !sawRecoveryCard {
					t.Errorf("r0's recovery must be delivered individually (recovery budget untouched):\n%s", joined)
				}
			})
		})
	})
}

// TestRecoveryStormDropsFlappedBack: a recovery queued in the recovery
// storm whose sensor flaps back to error before the flush must not appear
// in the summary — its fresh error transition owns the chat. Symmetric
// with TestStormFlushDropsRecovered (a down-storm entry that recovers
// before the flush is dropped).
func TestRecoveryStormDropsFlappedBack(t *testing.T) {
	withRecoveryStormBudget(t, 0, 500*time.Millisecond, func() {
		withPlainTransport(t, func() { // loopback httptest vs the SSRF blocklist
			pw, db, getBodies, cleanup := newStormTestWorker(t)
			defer cleanup()
			insertStormSensor(t, db, "a0")
			insertStormSensor(t, db, "a1")
			// Both up in the DB (mirrors the engine: status stamped
			// before the alert fires).
			if _, err := db.Exec(`UPDATE sensors SET status = 'up' WHERE id IN ('a0','a1')`); err != nil {
				t.Fatalf("set a0/a1 up: %v", err)
			}
			pw.launchAlert(func() { pw.sendAlert("a0", "a0", "127.0.0.1", "error", "up", 0) })
			pw.launchAlert(func() { pw.sendAlert("a1", "a1", "127.0.0.1", "error", "up", 0) })
			// Wait until BOTH are in the recovery queue (budget 0: both
			// are queued deterministically, no admission coin flip).
			deadline := time.Now().Add(3 * time.Second)
			for {
				pw.stormMu.Lock()
				n := len(pw.recoveryStormQueue)
				pw.stormMu.Unlock()
				if n >= 2 || time.Now().After(deadline) {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			// a1 flaps back to error before the window elapses.
			if _, err := db.Exec(`UPDATE sensors SET status = 'error' WHERE id = 'a1'`); err != nil {
				t.Fatalf("mark a1 error: %v", err)
			}
			// Poll for the recovery storm summary (the flush lands after
			// the individual deliveries drain alertWG).
			var bodies []string
			deadline = time.Now().Add(2 * time.Second)
			for {
				bodies = getBodies()
				hasSummary := false
				for _, b := range bodies {
					if strings.Contains(b, "recovery storm") {
						hasSummary = true
					}
				}
				if hasSummary || time.Now().After(deadline) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			var summaries []string
			for _, b := range bodies {
				if strings.Contains(b, "recovery storm") {
					summaries = append(summaries, b)
				}
			}
			if len(summaries) != 1 {
				t.Fatalf("recovery storm summaries = %d, want 1", len(summaries))
			}
			s := summaries[0]
			if !strings.Contains(s, "a0: error → up") {
				t.Errorf("summary missing the still-up sensor a0:\n%s", s)
			}
			if strings.Contains(s, "a1:") {
				t.Errorf("summary includes the flapped-back sensor a1:\n%s", s)
			}
		})
	})
}

// TestRecoveryRetryJitterRange: the recovery retry delay is jittered
// UPWARD only — [base, 1.5×base], 60..90s at the production 1m base. The
// floor must stay at base: TestInFifoRetryBudgetUnderRecoveryRetryDelay
// checks the worst in-band FIFO job (50s) against recoveryRetryDelay
// (60s); a sub-base jitter (the finding's 45s floor) would re-open the
// permanent-drop window that invariant closes.
func TestRecoveryRetryJitterRange(t *testing.T) {
	const base = time.Minute
	var maxD time.Duration
	for i := 0; i < 200; i++ {
		d := recoveryRetryJitter(base)
		if d < base {
			t.Fatalf("jittered delay %v < base %v: a sub-base jitter re-opens the FIFO budget window (TestInFifoRetryBudgetUnderRecoveryRetryDelay)", d, base)
		}
		if d >= 3*base/2 {
			t.Fatalf("jittered delay %v >= 1.5×base %v", d, 3*base/2)
		}
		if d > maxD {
			maxD = d
		}
	}
	if maxD == base {
		t.Fatal("200 jittered draws all landed exactly on the base: the jitter is a no-op")
	}
	// Sub-millisecond bases must not panic (Int63n(0)) — they jitter to
	// the base itself.
	if d := recoveryRetryJitter(time.Nanosecond); d != time.Nanosecond {
		t.Fatalf("nanosecond base: jitter = %v, want unchanged %v", d, time.Nanosecond)
	}
}

// TestWebhookTransportCapsConnsPerHost: a mass-recovery fan-out must not
// open unbounded parallel dials (TLS handshakes) to one provider host —
// the cap makes excess requests queue in the transport instead of
// dialing, so the provider's rate limit (Discord ~5 req/2s, Telegram
// ~1 msg/s) is met with bounded concurrency.
func TestWebhookTransportCapsConnsPerHost(t *testing.T) {
	if webhookTransport.MaxConnsPerHost != 8 {
		t.Fatalf("webhookTransport.MaxConnsPerHost = %d, want 8 (0 = unlimited active dials per host)", webhookTransport.MaxConnsPerHost)
	}
}

// withSMTPSem runs fn with the SMTP concurrency semaphore shrunk to n
// slots, restoring the original afterwards.
func withSMTPSem(t *testing.T, n int, fn func()) {
	t.Helper()
	old := smtpSem
	smtpSem = make(chan struct{}, n)
	defer func() { smtpSem = old }()
	fn()
}

// TestSMTPSendCapsConcurrency: N concurrent SMTP sends must never exceed
// the semaphore's slots — a mass recovery fans out one conversation per
// sensor per SMTP provider, and an unbounded fan-out would open hundreds
// of parallel sessions against one relay.
func TestSMTPSendCapsConcurrency(t *testing.T) {
	withSMTPSem(t, 2, func() {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		var (
			inFlight  atomic.Int64
			maxFlight atomic.Int64
			served    atomic.Int64
		)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					n := inFlight.Add(1)
					for {
						old := maxFlight.Load()
						if n <= old || maxFlight.CompareAndSwap(old, n) {
							break
						}
					}
					defer func() {
						inFlight.Add(-1)
						served.Add(1)
					}()
					_ = smtpServeConversation(c, 150*time.Millisecond)
				}(c)
			}
		}()
		// The production dial (smtpDial = dialChecked) refuses loopback
		// by design — this test needs a plain dialer (same swap as
		// smtp_auth_flow_test.go).
		origDial := smtpDial
		smtpDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
		}
		t.Cleanup(func() { smtpDial = origDial })

		host, portStr, _ := net.SplitHostPort(ln.Addr().String())
		port, _ := strconv.Atoi(portStr)
		cfg := smtpConfig{Host: host, Port: port, From: "pulsemon@example.com", To: "ops@example.com", TLS: "none"}

		const n = 6
		var wg sync.WaitGroup
		start := time.Now()
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := (&ProbeWorker{}).sendSMTPWith(context.Background(), cfg, "subject", "body"); err != nil {
					t.Errorf("send: %v", err)
				}
			}()
		}
		wg.Wait()
		elapsed := time.Since(start)
		// Bounded poll: the server's per-conn goroutine runs its defer (served++)
		// right after the client's QUIT round-trip, a hair after wg.Wait() here.
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) && served.Load() != n {
			time.Sleep(5 * time.Millisecond)
		}
		if got := served.Load(); got != n {
			t.Fatalf("served = %d, want %d", got, n)
		}
		if got := maxFlight.Load(); got > 2 {
			t.Fatalf("max concurrent SMTP conversations = %d, want <= 2 (the semaphore cap)", got)
		}
		// Teeth: 6 sends × 150ms at cap 2 takes >= 3 waves (~450ms);
		// uncapped they overlap into ~150ms.
		if elapsed < 300*time.Millisecond {
			t.Fatalf("all %d sends finished in %v: the cap is not constraining (3 waves want >= ~450ms)", n, elapsed)
		}
	})
}

// smtpServeConversation runs a minimal plaintext SMTP conversation (no
// STARTTLS, no AUTH) and holds the wire for hold at the DATA point so
// concurrent conversations overlap in a measurable window.
func smtpServeConversation(c net.Conn, hold time.Duration) error {
	io.WriteString(c, "220 test.local ESMTP\r\n")
	r := bufio.NewReader(c)
	inData := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		if inData {
			// Data lines are consumed silently — a real server responds only
			// at the "." terminator; a reply per line desyncs the client's
			// stream (QUIT then reads a leftover 250).
			if strings.TrimRight(line, "\r\n") == "." {
				inData = false
				io.WriteString(c, "250 OK\r\n")
			}
			continue
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			// Continuation lines must carry the dash; a dashless line ends the
			// multi-line reply early and desyncs the client by one response.
			io.WriteString(c, "250-test.local\r\n250-SIZE 35882577\r\n250 OK\r\n")
		case strings.HasPrefix(cmd, "MAIL"):
			io.WriteString(c, "250 OK\r\n")
		case strings.HasPrefix(cmd, "RCPT"):
			io.WriteString(c, "250 OK\r\n")
		case cmd == "DATA":
			time.Sleep(hold)
			io.WriteString(c, "354 go ahead\r\n")
			inData = true
		case cmd == "QUIT":
			io.WriteString(c, "221 bye\r\n")
			return nil
		default:
			io.WriteString(c, "250 OK\r\n")
		}
	}
}
