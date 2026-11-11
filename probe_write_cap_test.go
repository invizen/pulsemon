package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"pulsemon/internal/store"
)

// TestDoProbeWritesCappedUnderWriteStall pins finding #4: a stalled writer
// must park a sensor loop for at most store.ProbeWriteTimeout, not the main
// pool's 15s busy_timeout. The cap is a DRIVER-level pragma on the dedicated
// probe-write handle, not a context deadline: modernc.org/sqlite v1.29.1
// does not preempt a busy-parked write with ctx (empirically verified — a
// parked write with a 300ms ctx returns SQLITE_BUSY at 15.05s), so a
// context.WithTimeout wrapper would be decorative. Old behavior: doProbe's
// writes ran on the main pool and parked the full 15s per write phase.
func TestDoProbeWritesCappedUnderWriteStall(t *testing.T) {
	// The handle's busy_timeout is read at NewStore time — set the seam
	// BEFORE opening the store.
	oldCap := store.ProbeWriteTimeout
	store.ProbeWriteTimeout = 300 * time.Millisecond
	defer func() { store.ProbeWriteTimeout = oldCap }()

	db, err := store.NewStore(filepath.Join(t.TempDir(), "cap.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	fcSensor(t, db, "a", "a", "active")
	pw := NewProbeWorker(db)
	pw.sensors["a"] = &ProbeState{id: "a", lastStatus: "up"}
	old := probeTarget
	defer func() { probeTarget = old }()
	probeTarget = func(ctx context.Context, typ, target string, d time.Duration) probeOutcome {
		return probeOutcome{broken: true} // up -> warning transition
	}
	c := sensorConfig{id: "a", name: "a", target: "10.0.0.1", probeType: "icmp", intervalS: 60, timeoutMS: 100, lossWarn: 25, downAfter: 2}

	// Stall the writer: hold the write lock on a main-pool connection for
	// the whole test body (simulates a long-running writer; busy_timeout
	// makes everyone else park).
	hold, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("Conn: %v", err)
	}
	defer hold.Close()
	if _, err := hold.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("BEGIN IMMEDIATE: %v", err)
	}

	start := time.Now()
	pw.doProbe(context.Background(), c)
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("stalled writer parked doProbe for %v; probe writes must be capped by store.ProbeWriteTimeout (300ms), not the 15s busy_timeout", elapsed)
	}

	// The capped write failed by design; the write-failure contract must
	// hold: no status advance in DB, lastStatus not advanced (retry
	// semantics), no event row.
	var st string
	if err := db.QueryRow(`SELECT status FROM sensors WHERE id='a'`).Scan(&st); err != nil {
		t.Fatal(err)
	}
	if st != "up" {
		t.Fatalf("status advanced to %q despite the capped write failing", st)
	}
	if got := pw.sensors["a"].lastStatus; got != "up" {
		t.Fatalf("lastStatus advanced to %q despite the write failing; the transition must be retried", got)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE sensor_id='a'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d events after the capped write failed; want 0", n)
	}

	// Writer recovers: the transition lands on the next tick.
	if _, err := hold.ExecContext(context.Background(), "ROLLBACK"); err != nil {
		t.Fatalf("ROLLBACK: %v", err)
	}
	pw.doProbe(context.Background(), c)
	if err := db.QueryRow(`SELECT status FROM sensors WHERE id='a'`).Scan(&st); err != nil {
		t.Fatal(err)
	}
	if st != "warning" {
		t.Fatalf("transition not retried after the stall cleared: status=%q, want warning", st)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE sensor_id='a'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("%d events after recovery; want 1", n)
	}
}
