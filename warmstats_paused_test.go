package main

import (
	"context"
	"path/filepath"
	"pulsemon/internal/store"
	"testing"
	"time"
)

// TestWarmStatsLoadsPausedSensors pins the fix for "paused sensors lose their
// history after a restart": warmStats must load history for PAUSED sensors at
// startup too, not just active ones. recordProbe starts a resumed sensor from
// whatever is already in the cache and nothing else ever re-loads a sensor's
// history, so pre-fix a paused-then-resumed sensor (the maintenance →
// update --restart → resume sequence) came back with a blank 24h graph,
// uptime counting only post-resume probes, and an empty 60-probe inspector —
// while /history (a direct DB read) still showed the data. The raw tier is
// capped per sensor (max(1h, last 60)), so warming paused sensors is
// memory-safe.
func TestWarmStatsLoadsPausedSensors(t *testing.T) {
	db, err := store.NewStore(filepath.Join(t.TempDir(), "warmstats-paused.db"))
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	now := time.Now().UTC()
	seed := func(id, state string) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
			VALUES (?, ?, '127.0.0.1', 30, 1000, 25, 4, 3, ?, 'up', ?)`,
			id, id, state, now.Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert sensor %s: %v", id, err)
		}
		// 10 recent probes (all within the last 24h) — enough to populate the
		// series and drive the slow-sensor (n24 < 60) phase-2 backfill.
		for i := 0; i < 10; i++ {
			ts := now.Add(-time.Duration(9-i) * 30 * time.Second).UnixMilli()
			if _, err := db.Exec("INSERT INTO probes (sk, ts_ms, rtt_ms, resolved_ip) VALUES ((SELECT sk FROM sensors WHERE id = ?), ?, ?, '127.0.0.1')",
				id, ts, 12.0); err != nil {
				t.Fatalf("insert probe %d for %s: %v", i, id, err)
			}
		}
	}
	seed("paused-sensor", "paused")
	seed("active-sensor", "active") // control: guards a query edit that drops the active path

	// A fresh worker (a restart) warms its cache from the DB.
	pw := &ProbeWorker{db: db, statsCache: make(map[string]*probeSeries)}
	pw.warmStats(context.Background())

	// The core pin: the PAUSED sensor must be warmed. Pre-fix (WHERE state =
	// 'active') it is absent from statsCache and this fails.
	series, ok := pw.statsCache["paused-sensor"]
	if !ok {
		t.Fatalf("warmStats did not load the PAUSED sensor into statsCache — paused sensors must be warmed at startup so a resume after a restart keeps its history")
	}
	if snap := series.snapshot(); len(snap) != 10 {
		t.Fatalf("paused sensor series len = %d, want 10 (its recent probes) — a resume after a restart must not start from an empty series", len(snap))
	}

	// Control: the active sensor is still warmed (the query edit must not have
	// dropped the active path).
	if _, ok := pw.statsCache["active-sensor"]; !ok {
		t.Fatalf("warmStats did not load the ACTIVE sensor — the query edit dropped the active path")
	}
}
