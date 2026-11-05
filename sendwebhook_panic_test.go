package main

// 2026-10-24 review (m1): the alert consumer recovers a panicking job
// (sacrifice the delivery, keep the loop alive), but sendWebhook's `done`
// channel is written by the job closure itself — a panic skips the write,
// and the goroutine calling sendWebhook blocks on `<-done` forever (leaking
// the goroutine AND its alertWG count, so DrainAlerts burns the full
// backstop at every shutdown). The job must guarantee a `done` value.

import (
	"testing"
	"time"
)

// TestSendWebhookReturnsOnPanickedJob pins the m1 fix: a panicking job
// still writes its `done` value (the delivery is sacrificed, the loop and
// the caller's `<-done` wait survive). The panic is forced through the
// deliverDestinations seam — destination resolution is the FIRST step of
// sendWebhookDeliver, so a panic there stands in for any future panic in
// the delivery path, independent of the per-provider recovers. (Pre-snapshot
// the same role was played by a nil DB: activeProviders derefed pw.db.Ping()
// first. The settings snapshot removed that DB read from the hot path, so the
// seam is the deterministic panic source now.)
func TestSendWebhookReturnsOnPanickedJob(t *testing.T) {
	pw := NewProbeWorker(newTestDB(t))
	origDeliver := deliverDestinations
	deliverDestinations = func(pw *ProbeWorker) ([]dest, bool) {
		panic("simulated job-level panic in the delivery path")
	}
	defer func() { deliverDestinations = origDeliver }()

	done := make(chan bool, 1)
	go func() {
		done <- pw.sendWebhook("panic-sensor", "panic", "127.0.0.1", "up", "error", 0, false)
	}()
	select {
	case ok := <-done:
		if ok {
			t.Error("panicked delivery reported ok=true, want false")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sendWebhook blocked forever after a panicked job (done channel never written)")
	}
}
