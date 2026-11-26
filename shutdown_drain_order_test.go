package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestShutdownAlertsPreDrainLetsFastDeliveryLand is the MINOR-19 pin: a
// final-tick delivery (a recovery) that finishes quickly must COMPLETE
// across shutdown — shutdownAlerts' pre-abort drain runs BEFORE
// StopAlerts cancels stopCtx. Pre-fix (StopAlerts first), stopCtx
// cancelled under the in-flight delivery: sendWebhook's stopCtx escape
// reported NOT delivered, and the recovery's one retry
// (scheduleRecoveryRetry) was scheduled and then aborted by the same
// cancellation — permanently lost, because alert_state already says
// "up" and no re-alert tick comes for a sensor that is up.
// History: docs/DECISIONS.md → shutdown-alert-drain-first.
func TestShutdownAlertsPreDrainLetsFastDeliveryLand(t *testing.T) {
	withPlainTransport(t, func() {
		db := newTestDB(t)
		pw := NewProbeWorker(db)
		var hits atomic.Int32
		relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond) // in flight when the old shape cancelled stopCtx
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		defer relay.Close()
		pw.alertCfg.Store(&alertSettings{
			maintenance: false,
			scope:       "all",
			filter:      map[string]bool{},
			realertMin:  30,
			dests:       []dest{{p: providerList[0], url: relay.URL}},
		})

		// The final-tick delivery, in flight (launchAlert = the doProbe shape).
		delivered := make(chan bool, 1)
		pw.launchAlert(func() {
			delivered <- pw.sendAlert("s1", "svc", "192.0.2.1", "error", "up", 0)
		})

		start := time.Now()
		shutdownAlerts(pw)
		elapsed := time.Since(start)

		if got := <-delivered; !got {
			t.Fatal("final-tick delivery reported NOT delivered across shutdown — the pre-abort drain must let it land before stopCtx cancels")
		}
		if hits.Load() != 1 {
			t.Errorf("relay hits = %d, want 1", hits.Load())
		}
		if elapsed > 2*time.Second {
			t.Errorf("shutdownAlerts took %v with a fast delivery; the pre-drain should return as soon as the delivery lands", elapsed)
		}
	})
}

// TestShutdownAlertsBoundedWithHungDelivery pins the other half of the
// MINOR-19 contract: a GENUINELY hung delivery (a relay that accepts and
// never answers) must not hold shutdown for its full client timeout —
// the pre-drain is bounded, StopAlerts aborts the in-flight POST at its
// next read, and the cleanup drain is short. A pre-drain that regrows to
// an unbounded (or 15s-class) backstop re-opens the slow-exit window the
// sequence is designed to close.
// History: docs/DECISIONS.md → shutdown-alert-drain-first.
func TestShutdownAlertsBoundedWithHungDelivery(t *testing.T) {
	withPlainTransport(t, func() {
		pw := NewProbeWorker(nil)
		url, hit := rawStallServer(t, 10*time.Second)
		pw.alertCfg.Store(&alertSettings{
			maintenance: false,
			scope:       "all",
			filter:      map[string]bool{},
			realertMin:  30,
			dests:       []dest{{p: providerList[0], url: url}},
		})

		pw.launchAlert(func() {
			pw.sendAlert("s1", "svc", "192.0.2.1", "error", "up", 0)
		})

		// Wait until the POST is actually in flight (reached the server).
		deadline := time.Now().Add(2 * time.Second)
		for !hit.Load() {
			if time.Now().After(deadline) {
				t.Fatal("POST never reached the server")
			}
			time.Sleep(time.Millisecond)
		}

		// Shrink the production drains so the test stays fast: the BOUND
		// is the contract, not the exact seconds.
		oldPre, oldClean := shutdownPreDrain, shutdownCleanupDrain
		shutdownPreDrain, shutdownCleanupDrain = 500*time.Millisecond, 300*time.Millisecond
		t.Cleanup(func() { shutdownPreDrain, shutdownCleanupDrain = oldPre, oldClean })

		start := time.Now()
		shutdownAlerts(pw)
		elapsed := time.Since(start)

		if elapsed > 2500*time.Millisecond {
			t.Errorf("shutdownAlerts took %v with a hung delivery, want pre-drain + cleanup + margin (bounded abort, not the client's 10s timeout)", elapsed)
		}
		select {
		case <-pw.stopCtx.Done():
		case <-time.After(time.Second):
			t.Fatal("stopCtx not cancelled after shutdownAlerts")
		}
	})
}
