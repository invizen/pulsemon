package main

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestDrainAlertsWaitsForInFlightDelivery pins the shutdown alert-drain: a
// fire-and-forget alert delivery started via launchAlert must still be
// running when DrainAlerts is called, and DrainAlerts must block until it
// completes. Without the drain (the pre-fix behavior), main's deferred
// db.Close() would land mid-delivery — the webhook POST's first act is a
// settings read, so the alert dies the instant the store closes.
func TestDrainAlertsWaitsForInFlightDelivery(t *testing.T) {
	pw := &ProbeWorker{
		sensors:    make(map[string]*ProbeState),
		loops:      make(map[string]context.CancelFunc),
		db:         nil,
		statsCache: make(map[string]*probeSeries),
	}
	var started, finished atomic.Bool
	pw.launchAlert(func() {
		started.Store(true)
		time.Sleep(300 * time.Millisecond) // simulate TLS + POST
		finished.Store(true)
	})

	// Wait until the delivery is actually in flight before draining.
	deadline := time.Now().Add(2 * time.Second)
	for !started.Load() {
		if time.Now().After(deadline) {
			t.Fatal("delivery never started")
		}
		time.Sleep(time.Millisecond)
	}

	pw.DrainAlerts(2 * time.Second)
	if !finished.Load() {
		t.Fatal("DrainAlerts returned before the in-flight delivery finished — db.Close() would abort it")
	}

	// A second drain with nothing in flight must return immediately.
	start := time.Now()
	pw.DrainAlerts(2 * time.Second)
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("empty DrainAlerts took %v, want immediate", elapsed)
	}
}

// rawStallServer stands up a raw TCP listener that accepts one connection,
// records the hit, and then STALLS (sends no response) for up to stallDur
// before replying. Unlike httptest.NewServer, its .Close() returns
// immediately — it does not wait for the in-flight handler — so the test can
// assert on the client's abort latency without the test itself blocking on
// the handler. This isolates the context-cancellation behavior (the handler
// would otherwise hold the connection for the full stallDur, so only a
// cancelled client context can end the request early).
func rawStallServer(t *testing.T, stallDur time.Duration) (url string, hit *atomic.Bool) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	hit = &atomic.Bool{}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Read the request line so the client's write completes.
		bufio.NewReader(c).ReadLine()
		hit.Store(true)
		// Stall: hold the connection with no response. The client's context
		// cancellation (or 10s Timeout) is the only thing that ends it.
		time.Sleep(stallDur)
		c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	}()
	return "http://" + ln.Addr().String(), hit
}

// withPlainTransport temporarily points webhookClient at a stock transport
// (no dialChecked SSRF blocklist) for the duration of fn, then restores the
// hardened one. The SSRF dial-check blocks loopback, which the raw test server
// binds to — so in-flight-delivery tests that need a POST to actually reach
// the server must run without it. The two concerns (SSRF blocklist, context
// cancellation) are independent and tested separately; this isolates the
// latter.
func withPlainTransport(t *testing.T, fn func()) {
	t.Helper()
	old := webhookClient.Transport
	webhookClient.Transport = &http.Transport{}
	defer func() { webhookClient.Transport = old }()
	fn()
}

// TestStopAlertsAbortsInFlightPOST pins the context fix: a webhook POST stuck
// mid-delivery (server accepts the connection but stalls before sending a
// response) must be aborted promptly by StopAlerts instead of running to the
// client's full 10s timeout. The handler holds the connection for 10s, so a
// cancelled stopCtx is the only thing that ends the POST early.
func TestStopAlertsAbortsInFlightPOST(t *testing.T) {
	withPlainTransport(t, func() {
		url, hit := rawStallServer(t, 10*time.Second)
		pw := NewProbeWorker(nil)

		done := make(chan struct{})
		start := time.Now()
		go func() {
			defer close(done)
			pw.postJSON(url, map[string]string{"text": "slow"})
		}()

		// Wait until the POST is actually in flight (reached the server).
		deadline := time.Now().Add(2 * time.Second)
		for !hit.Load() {
			if time.Now().After(deadline) {
				t.Fatal("POST never reached the server")
			}
			time.Sleep(time.Millisecond)
		}

		// Shutdown: abort the in-flight POST.
		pw.StopAlerts()

		// The POST must return promptly (the context is cancelled), not run
		// the handler's full 10s stall. Pre-fix (no context on the POST) this
		// would block ~10s.
		select {
		case <-done:
			elapsed := time.Since(start)
			if elapsed > 5*time.Second {
				t.Errorf("in-flight POST took %v after StopAlerts, want prompt abort (<5s)", elapsed)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("in-flight POST did not return after StopAlerts — stopCtx did not abort it")
		}
	})
}

// TestPostJSONContextCancelledBeforeStart pins the degenerate case: a delivery
// launched into an already-cancelled stopCtx must fail fast with the context
// error, not attempt a connection.
func TestPostJSONContextCancelledBeforeStart(t *testing.T) {
	url, _ := rawStallServer(t, 5*time.Second)
	pw := NewProbeWorker(nil)
	pw.StopAlerts() // cancel before the POST starts
	start := time.Now()
	pw.postJSON(url, map[string]string{"text": "never"})
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("postJSON with pre-cancelled stopCtx took %v, want immediate failure", elapsed)
	}
}

// TestTestWebhookBoundedByRequestContext pins TestWebhook's context: a
// cancelled caller context aborts the in-flight POST at the next read instead
// of waiting for the server's stall. The handler holds the connection for 10s,
// so only the cancelled caller context ends the POST early.
func TestTestWebhookBoundedByRequestContext(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "testwebhook.db")
	db, err := NewDB(dbPath)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	withPlainTransport(t, func() {
		url, _ := rawStallServer(t, 10*time.Second)
		_ = db.SetSetting("google_chat_url", url)
		pw := NewProbeWorker(db)

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		start := time.Now()
		go func() {
			defer close(done)
			pw.TestWebhook(ctx, "google_chat")
		}()

		// Let the POST get in flight, then cancel the caller context.
		time.Sleep(300 * time.Millisecond)
		cancel()
		select {
		case <-done:
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Errorf("TestWebhook took %v after context cancel, want prompt abort", elapsed)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("TestWebhook did not return after caller context was cancelled")
		}
	})
}
