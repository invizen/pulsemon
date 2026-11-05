package main

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"pulsemon/internal/store"
)

// exhaustConns opens and holds all 10 pooled connections (SetMaxOpenConns(10)
// in store.NewStore) so any subsequent db.Query blocks on the pool, not on
// SQLite. Used to pin syncSensors deterministically in its DB-read phase.
func exhaustConns(t *testing.T, db *store.Store) func() {
	t.Helper()
	var conns []*sql.Conn
	for i := 0; i < 10; i++ {
		c, err := db.Conn(context.Background())
		if err != nil {
			t.Fatalf("open conn %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	return func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}
}

// TestSyncSensorsGenerationSkip pins finding #6 (correctness): a Restart
// landing in the read→apply gap of an in-flight syncSensors pass is detected
// via the per-sensor generation, so the pass SKIPS the sensor (no stale-config
// spawn). The bumping op owns the re-sync.
//
// The pool-exhaustion trick pins syncSensors in its DB-read phase: it has
// already captured the generation fingerprint (genAtRead) before the read, so
// a Restart issued now lands in the gap and the under-lock reconcile must
// detect the mismatch.
func TestSyncSensorsGenerationSkip(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "s1", "s1", "active")
	pw := NewProbeWorker(db)

	release := exhaustConns(t, db)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		pw.syncSensors(ctx)
		close(done)
	}()
	// Let syncSensors reach the (now-blocking) config read. It captures
	// genAtRead (gens[s1] absent → 0) before the read, so a Restart issued
	// after this sleep lands in the read→apply gap.
	time.Sleep(100 * time.Millisecond)

	// Bump the generation mid-read: a PATCH+Restart landing in the gap.
	pw.Restart("s1")

	release() // complete the read; the reconcile now sees the generation change
	<-done

	// The in-flight pass must have SKIPPED s1 (generation mismatch): no loop
	// spawned. A stale-config spawn is the bug this pins.
	if _, ok := pw.loops["s1"]; ok {
		t.Fatal("in-flight syncSensors pass spawned a sensor whose generation changed in the read→apply gap (stale-config spawn)")
	}
	// The bumping op owns the re-sync: a fresh pass spawns s1 with the current
	// config.
	pw.syncSensors(ctx)
	if _, ok := pw.loops["s1"]; !ok {
		t.Fatal("fresh pass did not spawn the sensor after the Restart")
	}
}

// TestSyncSensorsNoDBUnderLock pins finding #6 (performance): syncSensors does
// NOT hold pw.mu across its DB reads. While the config read is blocked on the
// exhausted pool, pw.mu must stay acquirable — healthz ActiveCount and every
// sensorLoop's twice-per-tick lock must not stall up to the 15s busy_timeout.
func TestSyncSensorsNoDBUnderLock(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "s1", "s1", "active")
	pw := NewProbeWorker(db)

	release := exhaustConns(t, db)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		pw.syncSensors(ctx)
		close(done)
	}()
	// Let syncSensors reach the (now-blocking) config read.
	time.Sleep(100 * time.Millisecond)

	// pw.mu must be acquirable while the DB read is in flight. ActiveCount
	// takes pw.mu; if syncSensors still held it across the read (the old
	// behavior), this blocks until the pool is released and the 2s guard
	// fires.
	lockFree := make(chan struct{})
	go func() {
		_ = pw.ActiveCount()
		close(lockFree)
	}()
	select {
	case <-lockFree:
		// pw.mu was acquirable during the DB read: the fix holds.
	case <-time.After(2 * time.Second):
		t.Fatal("pw.mu was held across the DB read (ActiveCount blocked >2s)")
	}

	release()
	<-done
}
