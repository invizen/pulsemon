package main

import (
	"context"
	"sync/atomic"
	"testing"
)

// ---------------------------------------------------------------- M11

func TestFix_M11_PartialSyncDoesNotCancelHealthyLoops(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "good", "good", "active")
	fcSensor(t, db, "bad", "bad", "active")
	// SQLite is dynamically typed: a non-numeric string in an INTEGER column makes Scan fail for that row.
	if _, err := db.Exec(`UPDATE sensors SET interval_s='abc' WHERE id='bad'`); err != nil {
		t.Fatal(err)
	}
	pw := NewProbeWorker(db)
	var badCancelled atomic.Bool
	pw.loops["bad"] = func() { badCancelled.Store(true) } // pretend "bad" already had a healthy loop
	pw.sensors["bad"] = &ProbeState{id: "bad", lastStatus: "error"}
	ctx, cancel := context.WithCancel(context.Background())
	pw.syncSensors(ctx)
	cancel()
	pw.wg.Wait()
	if badCancelled.Load() {
		t.Fatal("a row that failed to Scan caused its running loop to be cancelled")
	}
	if pw.sensors["bad"] == nil || pw.sensors["bad"].lastStatus != "error" {
		t.Fatal("ProbeState of the unreadable sensor was deleted")
	}
	if _, ok := pw.loops["good"]; !ok {
		t.Fatal("healthy sensor loop was not started")
	}
}
