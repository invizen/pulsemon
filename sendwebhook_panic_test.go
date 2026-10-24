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

// TestSendWebhookReturnsOnPanickedJob pins the m1 fix. A nil DB stands in
// for any future panic inside sendWebhookDeliver: activeProviders derefs
// pw.db.Ping() first, so the job panics deterministically on its very first
// step — the same contract the fix must hold for any panic in the delivery
// path.
func TestSendWebhookReturnsOnPanickedJob(t *testing.T) {
	pw := NewProbeWorker(newTestDB(t))
	pw.db = nil // first delivery step (activeProviders → db.Ping) panics

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
