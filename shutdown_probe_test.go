package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// TestRunWaitsForInFlightProbes pins the graceful-shutdown fix: ProbeWorker.Run
// must NOT return the moment its context is cancelled while a per-sensor loop
// is mid-probe — it must wait for every spawned loop to exit, so the caller
// (main's shutdown path) can close the database without aborting a probe write.
//
// The old code returned immediately on ctx.Done(); the N sensor loops kept
// running, and main's deferred db.Close() could land inside doProbe's
// INSERT→UPDATE window, leaving an unrecorded status and lock noise across a
// restart.
//
// Method: 10 sensors at a 1s interval with a 700ms ICMP timeout against
// TEST-NET-1 (192.0.2.1 — black-holed, so every probe runs the full 700ms
// timeout deterministically). At any instant, probes are staggered across a
// 1s window, so a cancel() mid-run catches at least one loop inside doProbe.
// Run() may only return after that probe has committed, which we observe two
// ways: probe rows strictly increase across the cancel, AND at least one row
// has a timestamp AFTER the cancel instant (the in-flight probe landed during
// the wait, not before it).
func TestRunWaitsForInFlightProbes(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "shutdown.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE sensors (
		id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, target TEXT NOT NULL,
		type TEXT NOT NULL DEFAULT 'icmp', tag TEXT,
		interval_s INTEGER NOT NULL, timeout_ms INTEGER NOT NULL, loss_warn INTEGER NOT NULL,
		down_after INTEGER NOT NULL, spike_mult INTEGER NOT NULL DEFAULT 5,
		state TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE probes (
		id INTEGER PRIMARY KEY AUTOINCREMENT, sensor_id TEXT NOT NULL,
		ts DATETIME NOT NULL, rtt_ms REAL, resolved_ip TEXT, http_status INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE events (
		id INTEGER PRIMARY KEY AUTOINCREMENT, sensor_id TEXT NOT NULL, ts DATETIME NOT NULL,
		from_status TEXT, to_status TEXT, note TEXT)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		id := string(rune('a' + i))
		if _, err := db.Exec(
			`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, state, status)
			 VALUES (?, ?, '192.0.2.1', 1, 700, 25, 4, 'active', 'up')`,
			id, "sensor-"+id); err != nil {
			t.Fatal(err)
		}
	}

	pw := NewProbeWorker(db)
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		pw.Run(ctx)
	}()

	// Let the staggered probes get mid-flight.
	time.Sleep(800 * time.Millisecond)
	countBefore := probeCount(t, db)
	cancelInstant := time.Now().UTC().Format(time.RFC3339Nano)
	cancel()

	select {
	case <-runDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return within 10s of cancel")
	}

	// 1. The in-flight probes committed during the wait: the row count grew
	// past the pre-cancel snapshot.
	countAfter := probeCount(t, db)
	if countAfter <= countBefore {
		t.Fatalf("probe rows did not grow after cancel (before=%d after=%d) — Run returned before the in-flight probe committed, so db.Close() would abort it", countBefore, countAfter)
	}

	// 2. At least one row is timestamped AFTER the cancel instant: a probe
	// started before cancel and committed during the wait (the exact window
	// the old code's db.Close() would have hit).
	var after int
	if err := db.QueryRow("SELECT COUNT(*) FROM probes WHERE ts > ?", cancelInstant).Scan(&after); err != nil {
		t.Fatalf("post-cancel count: %v", err)
	}
	if after == 0 {
		t.Fatalf("no probe committed after the cancel instant (countBefore=%d) — cannot prove the wait covered an in-flight probe", countBefore)
	}

	// 3. No torn writes: every probe row references an existing sensor.
	var orphan int
	if err := db.QueryRow(`SELECT COUNT(*) FROM probes p WHERE NOT EXISTS (SELECT 1 FROM sensors s WHERE s.id = p.sensor_id)`).Scan(&orphan); err != nil {
		t.Fatalf("orphan check: %v", err)
	}
	if orphan != 0 {
		t.Fatalf("%d probe rows reference missing sensors — torn writes", orphan)
	}
}

func probeCount(t *testing.T, db *DB) int {
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM probes").Scan(&n); err != nil {
		t.Fatalf("count probes: %v", err)
	}
	return n
}

// TestRunExitsPromptlyWithNoLoops guards the other direction: with zero
// active sensors Run must return quickly on cancel (no 5s-ticker or loop
// stall), so a healthy shutdown never waits.
func TestRunExitsPromptlyWithNoLoops(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "empty.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE sensors (
		id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, target TEXT NOT NULL,
		type TEXT NOT NULL DEFAULT 'icmp', tag TEXT,
		interval_s INTEGER NOT NULL, timeout_ms INTEGER NOT NULL, loss_warn INTEGER NOT NULL,
		down_after INTEGER NOT NULL, spike_mult INTEGER NOT NULL DEFAULT 5,
		state TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE probes (
		id INTEGER PRIMARY KEY AUTOINCREMENT, sensor_id TEXT NOT NULL,
		ts DATETIME NOT NULL, rtt_ms REAL, resolved_ip TEXT, http_status INTEGER)`); err != nil {
		t.Fatal(err)
	}
	pw := NewProbeWorker(db)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		pw.Run(ctx)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit promptly with no active sensors")
	}
}
