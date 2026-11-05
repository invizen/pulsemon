package main

import (
	"context"
	"testing"
	"time"
)

// TestDoProbeStatusAndEventCommitAtomically pins finding #7: the status
// UPDATE and the event INSERT commit in ONE transaction. In the old
// non-atomic code, if the event INSERT failed after the UPDATE succeeded,
// rememberStatus had already advanced lastStatus, so the next tick saw
// oldStatus == newStatus and the transition (and its event row) was lost
// forever. A single tx makes the two atomic: a failed INSERT rolls back the
// UPDATE too, lastStatus is not advanced, and the next tick retries.
func TestDoProbeStatusAndEventCommitAtomically(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "a", "a", "active")
	pw := NewProbeWorker(db)
	pw.sensors["a"] = &ProbeState{id: "a", lastStatus: "up"}
	old := probeTarget
	defer func() { probeTarget = old }()
	probeTarget = func(ctx context.Context, typ, target string, d time.Duration) probeOutcome {
		// broken -> c.probeBroken -> deriveStatus = warning (lastStatus != "error"),
		// a clean single up->warning transition with no probe-history seeding.
		return probeOutcome{broken: true}
	}
	c := sensorConfig{id: "a", name: "a", target: "10.0.0.1", probeType: "icmp", intervalS: 60, timeoutMS: 100, lossWarn: 25, downAfter: 2}

	// Make the events INSERT fail while the status UPDATE succeeds.
	if _, err := db.Exec(`CREATE TRIGGER noevent BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'nope'); END`); err != nil {
		t.Fatal(err)
	}
	// up -> warning. The event INSERT fails.
	pw.doProbe(context.Background(), c)

	// The failed INSERT must have rolled back the status UPDATE too: status
	// not advanced in the DB, lastStatus not advanced in memory, no event row.
	var st string
	db.QueryRow(`SELECT status FROM sensors WHERE id='a'`).Scan(&st)
	if st != "up" {
		t.Fatalf("after a failed event INSERT the status UPDATE was not rolled back: status=%q, want up", st)
	}
	if got := pw.sensors["a"].lastStatus; got == "warning" {
		t.Fatalf("lastStatus advanced to %q even though the event INSERT failed; the transition must be retried", got)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM events WHERE sensor_id='a'`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d events after the failed INSERT; want 0", n)
	}

	// DB recovers: the transition is retried and lands atomically.
	db.Exec(`DROP TRIGGER noevent`)
	pw.doProbe(context.Background(), c)
	db.QueryRow(`SELECT status FROM sensors WHERE id='a'`).Scan(&st)
	if st != "warning" {
		t.Fatalf("after the DB recovered the transition was not retried: status=%q, want warning", st)
	}
	db.QueryRow(`SELECT COUNT(*) FROM events WHERE sensor_id='a'`).Scan(&n)
	if n != 1 {
		t.Fatalf("%d events after recovery; want 1 (up->warning)", n)
	}

	// Drain any alert goroutines BEFORE the DB closes (t.Cleanup): an in-flight
	// delivery holds a pool connection open past db.Close() (same shutdown
	// order as main: StopAlerts -> DrainAlerts -> db.Close). up->warning is
	// dashboard-only (no alert), so this is normally a no-op.
	pw.DrainAlerts(5 * time.Second)
}
