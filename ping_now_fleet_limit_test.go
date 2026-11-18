package main

import (
	"context"
	"errors"
	"testing"
)

// TestPingNowFleetLimit pins finding #7: PingNow enforces a FLEET-WIDE
// in-flight cap (pulseSem), not just the per-sensor cooldown. A viewer with
// many sensors could otherwise fan out ~N/2 concurrent outbound probes (each
// holding a request handler for up to the sensor's timeout and writing a row).
// When the semaphore is full, PingNow returns errPulseBusy (→ 429) without
// probing; once a slot frees, it proceeds.
func TestPingNowFleetLimit(t *testing.T) {
	db := newTestDB(t)
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('s1', 's1', '10.255.255.1', 60, 100, 25, 1, 5, 'active', 'up', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("seed sensor: %v", err)
	}
	pw := NewProbeWorker(db)

	// Fill the semaphore to its cap: no in-flight pulse slot is available.
	for i := 0; i < cap(pw.pulseSem); i++ {
		pw.pulseSem <- struct{}{}
	}
	if _, err := pw.PingNow(context.Background(), "s1"); !errors.Is(err, errPulseBusy) {
		t.Fatalf("PingNow with a full semaphore: err = %v, want errPulseBusy", err)
	}
	// Free one slot: PingNow gets past the cap (the probe itself may report a
	// loss for the unreachable target, but it must NOT be the busy refusal).
	<-pw.pulseSem
	if _, err := pw.PingNow(context.Background(), "s1"); errors.Is(err, errPulseBusy) {
		t.Fatalf("PingNow after freeing a slot: err = %v, want not errPulseBusy", err)
	}
}
