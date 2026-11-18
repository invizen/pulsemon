package main

import (
	"context"
	"path/filepath"
	"pulsemon/internal/store"
	"testing"
	"time"
)

// TestRestartRebuilds24hGraphAndUptime is the end-to-end pin for the one
// genuine test gap in finding #9: after a RESTART (a fresh ProbeWorker whose
// in-memory cache is empty), the 24h graph and uptime must be reconstructed
// from the DB via warmStats — not come back blank. warmstats_paused_test.go
// proves the series is LOADED; this proves the user-facing outputs the
// dashboard shows (Uptime24h and the 24h graph) survive a restart.
//
// The scenario is the maintenance → update --restart → resume sequence: the
// process comes back with an empty cache, so everything the dashboard renders
// has to be rebuilt from the probe table.
func TestRestartRebuilds24hGraphAndUptime(t *testing.T) {
	db, err := store.NewStore(filepath.Join(t.TempDir(), "restart-24h.db"))
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	now := time.Now().UTC()
	const id = "r24"
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES (?, ?, '127.0.0.1', 300, 1000, 25, 4, 3, 'active', 'up', ?)`,
		id, id, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}
	// 288 probes over the last 24h at 300s (5-min) intervals, every 10th a
	// loss (rtt_ms NULL) → ~10% loss → ~90% uptime. All timestamps sit inside
	// the 24h warm window; the newest is 5 min ago so none land on the now
	// boundary.
	for i := 0; i < 288; i++ {
		ts := now.Add(-time.Duration(288-i) * 5 * time.Minute).Format(time.RFC3339)
		var rtt any
		if i%10 == 0 {
			rtt = nil // a loss
		} else {
			rtt = 12.5
		}
		if _, err := db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip) VALUES (?, ?, ?, '127.0.0.1')", id, ts, rtt); err != nil {
			t.Fatalf("insert probe %d: %v", i, err)
		}
	}

	// A RESTART: a fresh worker with an empty in-memory cache warms from the DB.
	pw := &ProbeWorker{db: db, statsCache: make(map[string]*probeSeries)}
	pw.warmStats(context.Background())

	// Uptime: the 24h counter is rebuilt from the DB → ~90% (the seeded 10%
	// loss). If warmStats missed the 24h window this reads 0 (or nil stats).
	st := pw.GetStats(id)
	if st == nil {
		t.Fatalf("GetStats after restart = nil — the 24h series was not rebuilt from the DB")
	}
	if st.Uptime24h < 88 || st.Uptime24h > 92 {
		t.Fatalf("Uptime24h after restart = %.1f%%, want ~90%% (the seeded 10%% loss) — uptime must survive a restart", st.Uptime24h)
	}

	// Graph: the 24h graph is rebuilt (not blank) after a restart — 5-min
	// buckets over a 24h range must return points spanning the history.
	pts := pw.Graph(id, 300, 86400)
	if len(pts) == 0 {
		t.Fatalf("Graph after restart = empty — the 24h graph must be rebuilt from the DB, not come back blank")
	}
	// The rebuilt graph must carry loss data (some buckets lost, some replied),
	// not a flat all-reply or all-loss line.
	var sawLost, sawReply bool
	for _, p := range pts {
		if p.Lost > 0 {
			sawLost = true
		}
		if p.Total-p.Lost > 0 {
			sawReply = true
		}
	}
	if !sawLost || !sawReply {
		t.Fatalf("Graph after restart lost the loss/reply pattern (sawLost=%v sawReply=%v) — the 24h shape must survive a restart", sawLost, sawReply)
	}
}
