package main

// Review 2026-10-24 (Major): armStormFlushLocked spawned the storm-summary
// flush goroutine UNTRACKED by alertWG, while the only launchAlert Add for
// that path had already been released — an armed flush was invisible to
// DrainAlerts, which returned immediately and let main reach db.Close while
// the flush fired later (fatal "Add called concurrently with Wait" /
// send-on-closed-db window at shutdown). The fix Adds at ARM time (the
// arming caller holds a WG count, so it can never race Wait at 0) and the
// goroutine keeps its stopCtx escape so shutdown is not delayed.

import (
	"path/filepath"
	"testing"
	"time"
)

func stormFixture(t *testing.T) *ProbeWorker {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "storm-wg.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return NewProbeWorker(db)
}

// TestStormFlushTrackedByAlertWG: a queued flush must hold a DrainAlerts-
// visible count. Pre-fix, DrainAlerts returned ~instantly while the flush
// was still 500ms out — the shutdown race. Post-fix it JOINS the pending
// window and the queue is provably flushed by the time it returns.
func TestStormFlushTrackedByAlertWG(t *testing.T) {
	pw := stormFixture(t)
	defer pw.stopCancel()

	oBudget, oWindow := stormBudget, stormWindow
	defer func() { stormBudget, stormWindow = oBudget, oWindow }()
	stormBudget = 0 // everything queues (and arms the flush)
	stormWindow = 500 * time.Millisecond

	if pw.stormAdmit("s1", "n1", "t1", "up", "error", 0) {
		t.Fatalf("budget 0 must queue the alert, not admit it")
	}

	start := time.Now()
	pw.DrainAlerts(5 * time.Second)
	elapsed := time.Since(start)
	if elapsed < 400*time.Millisecond {
		t.Fatalf("DrainAlerts returned after %v with a flush armed ~500ms out — the flush goroutine is NOT tracked by alertWG (the pre-fix shutdown race)", elapsed)
	}

	pw.stormMu.Lock()
	q := len(pw.stormQueue)
	pw.stormMu.Unlock()
	if q != 0 {
		t.Errorf("flush did not run: %d entries still queued after DrainAlerts returned", q)
	}
}

// TestStormFlushExitsOnStopAlerts: the fix must not turn a pending flush
// window into a shutdown stall — StopAlerts cancels stopCtx and the armed
// goroutine must release its WG count promptly, NOT sit out a 10s window.
func TestStormFlushExitsOnStopAlerts(t *testing.T) {
	pw := stormFixture(t)
	defer pw.stopCancel()

	oBudget, oWindow := stormBudget, stormWindow
	defer func() { stormBudget, stormWindow = oBudget, oWindow }()
	stormBudget = 0
	stormWindow = 10 * time.Second // far beyond any sane drain

	if pw.stormAdmit("s1", "n1", "t1", "up", "error", 0) {
		t.Fatalf("budget 0 must queue the alert")
	}
	pw.StopAlerts()

	done := make(chan struct{})
	go func() { pw.DrainAlerts(5 * time.Second); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("DrainAlerts stuck on a 10s storm window after StopAlerts — the flush goroutine lost its stopCtx escape hatch")
	}
}
