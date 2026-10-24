package main

// Review 2026-10-24 minor batch — warmStats could clobber a LIVE write:
// recordProbe (probe loop or API PingNow) can append to the cache while the
// warm chunk query is still in flight, and the publish loop then replaced
// the whole series with the snapshot built from the DB read, silently
// dropping the newer entry. The publish now carries any tail newer than the
// warmed snapshot forward (append keeps the 24h counters coherent).

import (
	"path/filepath"
	"testing"
	"time"
)

func TestWarmStatsKeepsLiveTail(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "warm-tail.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	const id = "warmtail"
	now := time.Now().UTC()
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES (?, ?, '127.0.0.1', 30, 1000, 25, 4, 3, 'active', 'up', ?)`,
		id, id, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}
	// DB rows: three scheduled probes, newest 60s ago.
	for i := 0; i < 3; i++ {
		ts := now.Add(-time.Duration(180-i*60) * time.Second)
		if _, err := db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip) VALUES (?, ?, 1.0, '127.0.0.1')`,
			id, ts.Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert probe %d: %v", i, err)
		}
	}

	// Model the race: a live PingNow entry landed in the cache AFTER the
	// warm DB read but BEFORE the publish loop.
	pw := &ProbeWorker{db: db, statsCache: make(map[string]*probeSeries)}
	live := &probeSeries{}
	liveTs := now.Unix()
	live.append(probeEntry{ts: liveTs, rtt: 4.2, manual: true})
	pw.statsCache[id] = live

	pw.warmStats()

	series := pw.statsCache[id]
	if series == nil {
		t.Fatal("no warmed series")
	}
	var found bool
	for _, e := range series.snapshot() {
		if e.ts == liveTs {
			found = true
			if !e.manual || e.rtt != 4.2 {
				t.Fatalf("live tail entry altered: %+v", e)
			}
		}
	}
	if !found {
		t.Fatal("warmStats dropped the live cache entry written during the warm read")
	}
}
