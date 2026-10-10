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
// A pre-fix regression #1 would return "up": an operator's downed router
// reads recovered the instant the DB hiccups, and doProbe records an event +
// a "recovered" alert on a transient hiccup. Pre-fix regression #2 (the
// alerting bug) returned "warning": for a sensor in "error" that
// manufactured an error->warning "partial recovery" transition that
// alertableTransition treats as alertable, firing a false recovery webhook and
// corrupting the DB status. Post-fix the tick RETAINS the last known state
// (lastStatus), so doProbe sees a same-state tick (no UPDATE, no event, no
// alert) and the sustained-error re-alert path handles a still-down sensor.
// A brand-new sensor (no lastStatus) reads "warning" (unknown), never "up".
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
	// Post-fix: a downed sensor retains its last known state ("error") — it
	// does NOT read "up" (the fake-recovery the principle guards against) and
	// does NOT read "warning" (the old bug, which manufactured an
	// error->warning "partial recovery" transition that alerts).
	if got := pw.deriveStatus(c, "error"); got != "error" {
		t.Fatalf("deriveStatus on DB read error = %q, want error (retain last state; never fake up)", got)
	}
}

// TestDeriveStatusDBErrorRetainsLastError pins the alerting half of the fix
// at the deriveStatus boundary: a sensor in "error" whose probe-history query
// fails must retain "error" (its last known state), not flip to "warning".
// That is what stops the false "partial recovery" webhook: with the old
// "warning" return, doProbe saw newStatus="warning" != oldStatus="error" and
// alertableTransition("error","warning") is true, so it fired. Post-fix
// newStatus==oldStatus, so doProbe takes the same-state branch (no UPDATE, no
// event, no alert) and routes to the sustained-error re-alert.
func TestDeriveStatusDBErrorRetainsLastError(t *testing.T) {
	probeErrCount.Store(0)
	db, err := NewDB(filepath.Join(t.TempDir(), "dberr-last.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	pw := seedSensor(t, db, "dberr-last", 25, 4, 3,
		[]*float64{f64(10), f64(10), f64(10), f64(10), nil, nil, nil, nil})
	c := sensorConfig{id: "dberr-last", lossWarn: 25, downAfter: 4, spikeMult: 3}
	c.lastErrCount = probeErrCount.Load()

	// Sanity: healthy DB reads "error" for a downed sensor.
	if got := pw.deriveStatus(c, "error"); got != "error" {
		t.Fatalf("deriveStatus with healthy DB = %q, want error (precondition)", got)
	}
	// Document WHY the old behavior alerted: the old "warning" return WOULD be
	// an alertable transition from "error".
	if !alertableTransition("error", "warning") {
		t.Fatalf("precondition: alertableTransition(error, warning) must be true (that's what made the old 'warning' return alert)")
	}

	// Close the DB: the history query now fails deterministically.
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got := pw.deriveStatus(c, "error")
	if got != "error" {
		t.Fatalf("deriveStatus on DB read error = %q, want error (retain last state \u2014 a 'warning' here would fire a false partial-recovery alert)", got)
	}
	// Same-state => no transition => doProbe never reaches the alert path.
	if alertableTransition("error", got) {
		t.Errorf("post-fix transition error->%q is alertable; want false (same-state, no alert)", got)
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
