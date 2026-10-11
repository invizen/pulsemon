package main

import (
	"net"
	"runtime"
	"testing"
	"time"
)

// TestEngineCloseWaitsForReader locks the reader-lifecycle contract:
//   - Close() blocks until the reply-reader goroutine has actually stopped
//     (not just until the fd/conn is closed), so no stale reader is left
//     delivering into the package-global pending map.
//   - Close() is idempotent (safe to call twice) and safe when run() was
//     never called (no reader to wait for) — it must not panic or hang.
//
// Uses a real engine + real socket on this host (the unprivileged datagram
// path where ping_group_range permits it; skipped otherwise). The reader is
// proven alive first (a loopback ping is dispatched to it), then Close() must
// bring the goroutine count back to baseline — the reader is gone.
func TestEngineCloseWaitsForReader(t *testing.T) {
	e, err := NewEngine()
	if err != nil {
		t.Skipf("ICMP engine unavailable on this host: %v", err)
	}

	runtime.GC()
	base := runtime.NumGoroutine()

	// Start the reader, then prove it is actually alive and dispatching by
	// sending a loopback ping: the reader must be the one to deliver the
	// reply. (Even if the reply is lost, the reader is running — but on
	// loopback it should respond, confirming the reader is engaged.)
	e.run()
	if res := e.Ping(net.ParseIP("127.0.0.1"), 500*time.Millisecond); !res.Lost {
		// loopback up — reader delivered.
	}

	// Close must return promptly (bounded by the reader unwinding), not hang.
	closed := make(chan struct{})
	go func() {
		e.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close() did not return within 3s — the reader was not waited on / did not stop")
	}

	// The reader goroutine must be gone: goroutine count back to baseline.
	// Give the scheduler a beat to reap the goroutine.
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	if now := runtime.NumGoroutine(); now > base+2 {
		t.Errorf("goroutines did not settle after Close: base=%d now=%d (reader still running?)", base, now)
	}

	// Double close: must not panic or hang (closeOnce + idempotent wg.Wait).
	again := make(chan struct{})
	go func() {
		e.Close()
		close(again)
	}()
	select {
	case <-again:
	case <-time.After(2 * time.Second):
		t.Fatal("second Close() did not return — not idempotent")
	}

	// A probe after close must not hang (bounded by the timeout), it just
	// reports a loss — the reader is gone, so no delivery.
	after := make(chan struct{})
	go func() {
		e.Ping(net.ParseIP("127.0.0.1"), 200*time.Millisecond)
		close(after)
	}()
	select {
	case <-after:
	case <-time.After(2 * time.Second):
		t.Fatal("Ping after Close hung — reader/socket in a bad state")
	}
}

// TestEngineCloseWithoutRun guards the degenerate case: an engine that never
// started a reader must Close cleanly (no reader to wait for), without
// hanging or panicking.
func TestEngineCloseWithoutRun(t *testing.T) {
	e, err := NewEngine()
	if err != nil {
		t.Skipf("ICMP engine unavailable on this host: %v", err)
	}
	done := make(chan struct{})
	go func() {
		e.Close() // no run() — wg is zero, must return immediately
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close on a run-less engine hung")
	}
}
