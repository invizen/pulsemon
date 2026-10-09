package main

import (
	"context"
	"path/filepath"
	"testing"
)

// TestDeriveStatusDBErrorNeverFakesUp pins the "never fake up" principle for
// the DB-read path in deriveStatus: when the probe-history query fails
// (transient SQLite/WAL error), a sensor that was genuinely down must NOT
// read "up" for that tick. The safe default is "warning" (unknown) — the
// same status the broken-socket path returns — because a monitoring tool
// must not claim a recovery it cannot confirm.
//
// A pre-fix regression would return "up": an operator's downed router reads
// recovered the instant the DB hiccups, and doProbe records an event + a
// "recovered" alert on a transient hiccup. Post-fix the tick reads degraded
// and self-clears next tick; and because warning is dashboard-only
// (alertableTransition(_, "warning") == false), a DB hiccup can never fire an alert.
func TestDeriveStatusDBErrorNeverFakesUp(t *testing.T) {
	probeErrCount.Store(0) // isolate the DB-error path from the socket gate
	db, err := NewDB(filepath.Join(t.TempDir(), "dberr.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// A genuinely DOWN sensor: 4 consecutive losses with down_after=4, so a
	// healthy DB read derives "error". Under the old bug, a Query failure
	// returned "up" — the exact fake-recovery the fix prevents.
	pw := seedSensor(t, db, "dberr-down", 25, 4, 3,
		[]*float64{f64(10), f64(10), f64(10), f64(10), nil, nil, nil, nil})

	// Sanity: with the DB open, the downed sensor correctly reads "error".
	// Mirror doProbe's first line — the broken-socket gate compares
	// probeErrCount (a global other tests may have raised) against
	// c.lastErrCount, so an unset lastErrCount would make that gate trip.
	c := sensorConfig{id: "dberr-down", lossWarn: 25, downAfter: 4, spikeMult: 3}
	c.lastErrCount = probeErrCount.Load()
	if got := pw.deriveStatus(c, "up"); got != "error" {
		t.Fatalf("deriveStatus with healthy DB = %q, want error (test precondition)", got)
	}

	// Close the DB: deriveStatus's history Query now fails deterministically.
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := pw.deriveStatus(c, "error"); got != "warning" {
		t.Fatalf("deriveStatus on DB read error = %q, want warning (never fake up)", got)
	}
}

// TestDeriveStatusDBErrorNoAlert pins the alerting half of the fix: the
// warning a DB error produces must not alert (it is dashboard-only), so a
// transient SQLite hiccup can never fire a false "recovered" or "down"
// webhook.
func TestDeriveStatusDBErrorNoAlert(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "dberr-alert.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	pw := &ProbeWorker{
		sensors: make(map[string]*ProbeState),
		loops:   make(map[string]context.CancelFunc),
		db:      db,
	}
	c := sensorConfig{id: "dberr-alert"}
	// A DB-error tick reads warning from a warning baseline (same-state) and
	// must not alert even if it did flip — both sides are dashboard-only.
	if pw.shouldAlertNow(c, "warning", "warning") || pw.shouldAlertNow(c, "up", "warning") {
		t.Error("shouldAlertNow(-> warning) = true, want false — a DB-error status must not alert")
	}
}
