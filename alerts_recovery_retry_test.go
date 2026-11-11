package main

import (
	"testing"
	"time"
)

// Tests for the dropped-recovery retry (review 2026-11-10 M1): when a
// recovery alert's first delivery fails — dropped on a full per-sensor
// FIFO during provider degradation, or every provider down — it must be
// re-offered exactly once after recoveryRetryDelay. The error direction
// self-heals via scheduleAlertRetry + the re-alert tick, but recovery has
// no such path (alert_state is already stamped "up" and maybeRealert only
// runs on sustained-error ticks), so pre-fix a dropped recovery was lost
// forever and the chat's last word for a recovered sensor stayed "error".

// withRecoveryRetryDelay shrinks the retry delay for tests and restores
// the production value afterwards.
func withRecoveryRetryDelay(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	old := recoveryRetryDelay
	recoveryRetryDelay = d
	defer func() { recoveryRetryDelay = old }()
	fn()
}

// TestDroppedRecoveryAlertIsRetried pins the fix: with the sensor's FIFO
// full (the production provider-degradation shape), the recovery sendAlert
// reports failure, and scheduleRecoveryRetry must land the recovery on the
// same provider once the queue drains.
func TestDroppedRecoveryAlertIsRetried(t *testing.T) {
	withPlainTransport(t, func() {
		withRecoveryRetryDelay(t, 50*time.Millisecond, func() {
			pw, db, getBodies, cleanup := newStormTestWorker(t)
			defer cleanup()
			insertStormSensor(t, db, "s1")

			release := fillGateFull(t, pw) // park consumer + fill s1's FIFO
			if pw.sendAlert("s1", "s1", "127.0.0.1", "error", "up", 1.0) {
				t.Fatal("recovery sendAlert must report failure on a full FIFO")
			}
			if n := len(getBodies()); n != 0 {
				t.Fatalf("deliveries after a dropped sendAlert = %d, want 0", n)
			}

			pw.scheduleRecoveryRetry("s1", "s1", "127.0.0.1", "error", "up", 1.0)
			close(release) // drain the parked queue so the retry's job can run

			// Mirror the engine: the probe loop stamps the new status in
			// the DB before the alert fires — the fire-time guard reads it.
			if _, err := db.Exec(`UPDATE sensors SET status = 'up' WHERE id = 's1'`); err != nil {
				t.Fatal(err)
			}

			deadline := time.Now().Add(2 * time.Second)
			var n int
			for {
				n = len(getBodies())
				if n >= 1 || time.Now().After(deadline) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if n != 1 {
				t.Fatalf("recovery deliveries after retry = %d, want 1 (dropped recovery never retried)", n)
			}
			pw.DrainAlerts(2 * time.Second)
			if n := len(getBodies()); n != 1 {
				t.Fatalf("recovery deliveries after drain = %d, want exactly 1 (one retry, no loop)", n)
			}
		})
	})
}

// TestRecoveryRetrySkippedWhenSensorReflapped pins the fire-time guard: a
// sensor that fell back into error during the delay must NOT get a stale
// "recovered" line — the fresh error transition owns the chat. The
// per-sensor FIFO orders the queue, not a delayed re-entry, so the guard
// is the only thing keeping the last word correct.
func TestRecoveryRetrySkippedWhenSensorReflapped(t *testing.T) {
	withPlainTransport(t, func() {
		withRecoveryRetryDelay(t, 100*time.Millisecond, func() {
			pw, db, getBodies, cleanup := newStormTestWorker(t)
			defer cleanup()
			insertStormSensor(t, db, "s1")

			pw.scheduleRecoveryRetry("s1", "s1", "127.0.0.1", "error", "up", 1.0)
			// Flap back to error BEFORE the delay fires.
			if _, err := db.Exec(`UPDATE sensors SET status = 'error' WHERE id = 's1'`); err != nil {
				t.Fatal(err)
			}
			time.Sleep(400 * time.Millisecond)
			pw.DrainAlerts(2 * time.Second)
			if n := len(getBodies()); n != 0 {
				t.Fatalf("deliveries after a flapped recovery retry = %d, want 0", n)
			}
		})
	})
}

// TestRecoveryRetryAbortedByStop pins the shutdown path: a retry pending
// when StopAlerts fires must be released by stopCtx immediately (never
// sleeping out the delay) and must not deliver — shutdown's own summary
// owns the chat.
func TestRecoveryRetryAbortedByStop(t *testing.T) {
	withPlainTransport(t, func() {
		withRecoveryRetryDelay(t, 10*time.Second, func() {
			pw, db, getBodies, cleanup := newStormTestWorker(t)
			defer cleanup()
			insertStormSensor(t, db, "s1")

			pw.scheduleRecoveryRetry("s1", "s1", "127.0.0.1", "error", "up", 1.0)
			start := time.Now()
			pw.StopAlerts() // cancels stopCtx; must not wait out the 10s delay
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("StopAlerts waited %v with a pending retry; stopCtx must release it", elapsed)
			}
			pw.DrainAlerts(2 * time.Second)
			if n := len(getBodies()); n != 0 {
				t.Fatalf("deliveries after StopAlerts = %d, want 0", n)
			}
		})
	})
}
