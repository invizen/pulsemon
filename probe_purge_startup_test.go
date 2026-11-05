package main

import (
	"context"
	"testing"
	"time"

	"pulsemon/internal/store"
)

// TestRunPurgesAtStartup pins finding #9: the 24h retention sweep runs ONCE at
// startup, not only on the hourly retention ticker. A process that restarts
// more often than an hour — crash loops, frequent updates — must still purge,
// or the probes/events tables grow without bound. The sweep is synchronous
// before the Run select loop, so a short-lived context proves it ran without
// waiting an hour.
func TestRunPurgesAtStartup(t *testing.T) {
	db := fcDB(t)
	// A PAUSED sensor: syncSensors filters state='active', so no probe loop is
	// spawned (nothing else writes probe rows during the test) — the startup
	// sweep is the only thing that can remove the old rows.
	fcSensor(t, db, "purge1", "purge1", "paused")
	// Old rows (25h ago) that the retention sweep must remove.
	oldBase := time.Now().Add(-25 * time.Hour)
	for i := 0; i < 5; i++ {
		fcProbe(t, db, "purge1", oldBase.Add(time.Duration(i)*time.Minute), nil)
	}
	// A recent row (1h ago), inside the 24h window, that must survive.
	fcProbe(t, db, "purge1", time.Now().Add(-1*time.Hour), 12.5)

	pw := NewProbeWorker(db)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pw.Run(ctx)
		close(done)
	}()
	// Run performs the sweep synchronously before entering the select loop;
	// give it a moment to finish, then cancel. This is far under the 1h
	// retention ticker, so the only purge that can have run is the startup one.
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	cutoff := store.FormatTS(time.Now().Add(-24 * time.Hour))
	var oldCount, recentCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM probes WHERE sensor_id='purge1' AND ts < ?`, cutoff).Scan(&oldCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM probes WHERE sensor_id='purge1' AND ts >= ?`, cutoff).Scan(&recentCount); err != nil {
		t.Fatal(err)
	}
	if oldCount != 0 {
		t.Errorf("old rows after startup = %d, want 0 (finding #9: retention must run at startup, not only after 1h)", oldCount)
	}
	if recentCount != 1 {
		t.Errorf("recent rows after startup = %d, want 1 (the 24h window must survive the sweep)", recentCount)
	}
}
