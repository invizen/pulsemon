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
	// Old rows at 25h..94h ago — 70 of them, deliberately BEYOND the
	// per-sensor 60-row tail exemption (finding #6), so the sweep has rows
	// it MUST remove: survivors = the newest 60 (the 1 recent row + the 59
	// newest old rows), the 11 oldest old rows are deleted. Hour spacing
	// keeps EVERY seeded old row unambiguously past the 24h cutoff.
	oldBase := time.Now().Add(-25 * time.Hour)
	for i := 0; i < 70; i++ {
		fcProbe(t, db, "purge1", oldBase.Add(-time.Duration(i)*time.Hour), nil)
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
	var oldCount, recentCount, total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM probes WHERE sensor_id='purge1' AND ts < ?`, cutoff).Scan(&oldCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM probes WHERE sensor_id='purge1' AND ts >= ?`, cutoff).Scan(&recentCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM probes WHERE sensor_id='purge1'`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	// 71 rows seeded; the startup sweep must have removed exactly the 11
	// oldest (everything past the 60-row tail).
	if total != seriesTailProbes || oldCount != seriesTailProbes-1 {
		t.Errorf("after startup purge: total=%d old=%d, want total=%d old=%d (finding #9: retention must run at startup, not only after 1h; finding #6: the newest 60 are exempt)",
			total, oldCount, seriesTailProbes, seriesTailProbes-1)
	}
	if recentCount != 1 {
		t.Errorf("recent rows after startup = %d, want 1 (the 24h window must survive the sweep)", recentCount)
	}
}
