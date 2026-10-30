package main

// 2026-10-24 review (m4): TestWarmStatsKeepsLiveTail pins the CARRY branch
// of the warm-stats publish merge (live entries newer than the warmed
// snapshot are appended). This is the complementary branch: live entries
// OLDER than the warmed snapshot's newest entry are NOT carried — the DB
// read is authoritative for the past (it covers the full retention window),
// so a stale live entry is at best a duplicate and at worst would push the
// series backwards. The merge must keep exactly: DB rows + live tail
// strictly newer than the DB's newest row.

import (
	"context"
	"path/filepath"
	"pulsemon/internal/store"
	"testing"
	"time"
)

func TestWarmStatsDropsStaleLiveEntries(t *testing.T) {
	db, err := store.NewStore(filepath.Join(t.TempDir(), "warm-stale.db"))
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	const id = "warmstale"
	now := time.Now().UTC()
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES (?, ?, '127.0.0.1', 30, 1000, 25, 4, 3, 'active', 'up', ?)`,
		id, id, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}
	// DB rows: three scheduled probes at 180s / 120s / 60s ago (newest 60s).
	for i, age := range []int{180, 120, 60} {
		ts := now.Add(-time.Duration(age) * time.Second)
		if _, err := db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip) VALUES (?, ?, 1.0, '127.0.0.1')`,
			id, ts.Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert probe %d: %v", i, err)
		}
	}

	// Model the race: the live cache holds two entries OLDER than the
	// warm snapshot's newest row (240s and 90s ago) and one NEWER (30s).
	pw := &ProbeWorker{db: db, statsCache: make(map[string]*probeSeries)}
	live := &probeSeries{}
	live.append(probeEntry{ts: now.Add(-240 * time.Second).Unix(), rtt: 9.9, manual: true})
	live.append(probeEntry{ts: now.Add(-90 * time.Second).Unix(), rtt: 8.8, manual: true})
	live.append(probeEntry{ts: now.Add(-30 * time.Second).Unix(), rtt: 4.2, manual: true})
	pw.statsCache[id] = live

	pw.warmStats(context.Background())

	series := pw.statsCache[id]
	if series == nil {
		t.Fatal("no warmed series")
	}
	snap := series.snapshot()
	count := func(rtt float32) int {
		n := 0
		for _, e := range snap {
			if e.rtt == rtt {
				n++
			}
		}
		return n
	}
	if n := count(9.9); n != 0 {
		t.Errorf("stale live entry (240s ago) was carried into the warmed series (count %d), want 0", n)
	}
	if n := count(8.8); n != 0 {
		t.Errorf("stale live entry (90s ago) was carried into the warmed series (count %d), want 0", n)
	}
	if n := count(4.2); n != 1 {
		t.Errorf("newer live tail entry (30s ago) count = %d, want 1", n)
	}
	// The three DB rows must all be present exactly once.
	for _, want := range []float32{1.0} {
		if n := count(want); n != 3 {
			t.Errorf("DB row count = %d, want 3", n)
		}
	}
	if len(snap) != 4 {
		t.Errorf("series length = %d, want 4 (3 DB rows + 1 carried tail): %+v", len(snap), snap)
	}
}
