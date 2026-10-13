package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// TestRunAbortsInFlightProbesOnCancel pins the finding-6 shutdown contract:
// when Run's context is cancelled while per-sensor loops are mid-probe, the
// in-flight probes ABORT (they run on the loop ctx, not
// context.Background()) and none of them commit a row after the cancel
// instant. Run returns promptly — well inside main's 10s worker budget — so
// db.Close() never lands in a probe's write window.
//
// This replaces the older contract (let the in-flight probes run out and
// commit, then return): aborting is strictly safer. A probe that completes
// during shutdown writes a row for a state the operator no longer cares
// about, and for a sensor that was just deleted it is an FK violation.
//
// Method: 10 sensors at a 1s interval with a 700ms ICMP timeout against
// TEST-NET-1 (192.0.2.1 — black-holed, so every probe runs the full 700ms
// timeout deterministically). At any instant, probes are staggered across a
// 1s window, so a cancel() mid-run catches at least one loop inside
// doProbe. Under the OLD behavior those in-flight probes committed up to
// 700ms AFTER cancel; under the new contract they abort, so no row may carry
// a timestamp after cancel+100ms (the 100ms absorbs a microsecond-scale
// race where a probe passed the ctx check a hair before the cancel landed).
func TestRunAbortsInFlightProbesOnCancel(t *testing.T) {
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
	cancelInstant := time.Now().UTC().Format(time.RFC3339Nano)
	start := time.Now()
	cancel()

	select {
	case <-runDone:
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("Run took %v after cancel, want < 2s (main's shutdown budget is 10s; in-flight 700ms probes must abort, not run out)", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return within 10s of cancel")
	}

	// 1. No probe committed after the cancel instant (±100ms race margin):
	// the in-flight probes were aborted, so nothing wrote a row for the
	// cancelled window. Under the old behavior this count was > 0 (the
	// in-flight probes landed up to 700ms late).
	var after int
	if err := db.QueryRow("SELECT COUNT(*) FROM probes WHERE ts > ?",
		add100ms(cancelInstant)).Scan(&after); err != nil {
		t.Fatalf("post-cancel count: %v", err)
	}
	if after != 0 {
		t.Fatalf("%d probe rows committed after the cancel instant — in-flight probes must abort, not commit late (old shutdown behavior regressed)", after)
	}

	// 2. No torn writes: every probe row references an existing sensor.
	var orphan int
	if err := db.QueryRow(`SELECT COUNT(*) FROM probes p WHERE NOT EXISTS (SELECT 1 FROM sensors s WHERE s.id = p.sensor_id)`).Scan(&orphan); err != nil {
		t.Fatalf("orphan check: %v", err)
	}
	if orphan != 0 {
		t.Fatalf("%d probe rows reference missing sensors — torn writes", orphan)
	}
}

// add100ms shifts an RFC3339Nano timestamp forward by 100ms (the race
// margin documented in TestRunAbortsInFlightProbesOnCancel).
func add100ms(rfc3339 string) string {
	ts, err := time.Parse(time.RFC3339Nano, rfc3339)
	if err != nil {
		return rfc3339
	}
	return ts.Add(100 * time.Millisecond).UTC().Format(time.RFC3339Nano)
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
