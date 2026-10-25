package main

import (
	"testing"
	"time"
)

// Regression tests for the alert-gate enqueue fix (review 2026-10-24):
// enqueueAlert must DROP (return false) when the sensor's 8-slot FIFO is
// full instead of blocking while holding the GLOBAL alertMu. A blocking
// send under that lock stalled every other sensor's enqueue AND every idle
// consumer's exit check behind one stuck sensor for up to ~5 minutes during
// provider degradation. sendWebhook must also abort its <-done wait when
// stopCtx is cancelled, so a caller whose job never runs releases its
// alertWG count and DrainAlerts can finish.

// fillGateFull parks the consumer on a blocking job 1, then fills the
// 8-slot buffer with 7 more no-op jobs: the 10th enqueue finds the buffer
// full. It returns the release channel (close it to unblock the consumer)
// and asserts the 8 accepted enqueues.
func fillGateFull(t *testing.T, pw *ProbeWorker) (release chan struct{}) {
	t.Helper()
	release = make(chan struct{})
	started := make(chan struct{})
	if !pw.enqueueAlert("s1", func() { close(started); <-release }) {
		t.Fatal("job 1 dropped unexpectedly (buffer was empty)")
	}
	<-started // consumer has dequeued job 1 and is blocked inside it; buffer is empty
	for i := 2; i <= 9; i++ {
		if !pw.enqueueAlert("s1", func() {}) {
			t.Fatalf("job %d dropped unexpectedly (buffer should have room)", i)
		}
	}
	return release
}

// TestEnqueueAlertDropsWhenFull pins the core fix: with the 8-slot buffer
// full, enqueueAlert returns false immediately instead of blocking on
// `ch <- job` while holding alertMu. Pre-fix this test times out on the
// 10th enqueue (the blocking send never completes because the consumer is
// parked on job 1).
func TestEnqueueAlertDropsWhenFull(t *testing.T) {
	pw := NewProbeWorker(nil)
	release := fillGateFull(t, pw)
	defer close(release)

	done := make(chan bool, 1)
	go func() { done <- pw.enqueueAlert("s1", func() {}) }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("10th job was accepted into a full buffer (want drop, got accept)")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("enqueueAlert blocked on a full buffer (pre-fix behavior) — it must drop, not block")
	}
}

// TestSendWebhookAbortsOnStop pins the shutdown escape: a sendWebhook whose
// job is queued behind a blocked job must release its caller (and thus its
// alertWG count) when stopCtx is cancelled, instead of parking on <-done for
// the full DrainAlerts backstop. Pre-fix (plain `return <-done`) this test
// times out because the blocked job 1 is not stopCtx-aware.
func TestSendWebhookAbortsOnStop(t *testing.T) {
	pw := NewProbeWorker(nil)
	release := fillGateFull(t, pw)
	defer close(release)

	done := make(chan bool, 1)
	go func() { done <- pw.sendWebhook("s1", "n", "127.0.0.1", "up", "error", 0, false) }()
	// Shutdown begins: the <-done wait must abort, not run the full backstop.
	pw.StopAlerts()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sendWebhook did not abort on stopCtx — parked on <-done (leaks its alertWG count)")
	}
}
