package main

import (
	"context"
	"fmt"
	"path/filepath"
	"pulsemon/internal/store"
	"sync"
	"testing"
	"time"
)

// TestRespawnLoopFirstTickCapped pins the 2026-10-20 external-review fix:
// a probe loop that is DROPPED (the sync pass removes paused sensors within
// ~5s; Restart deletes on config edit; maintenance-mode end drops every
// snapshot sensor) and then RESPAWNED must probe soon — within
// respawnFirstTickCap plus margin — NOT after the full staggered phase,
// which on an hourly sensor means up to an hour of darkness (no data, no
// status, no alerts) after a resume. SetPaused's F28 kick is a no-op once
// the loop is gone, so the respawn path owns the bound.
//
// The complementary half: a FIRST spawn (process start, brand-new sensor)
// must keep the full staggered phase — the anti-write-herd property the
// stagger exists for (see the staggerPhase comment).
func TestRespawnLoopFirstTickCapped(t *testing.T) {
	dir := t.TempDir()
	db, err := store.NewStore(filepath.Join(dir, "respawn-tick.db"))
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	// The probe loops spawned by syncSensors are children of this context.
	// Cancelling it stops them. Declared AFTER defer db.Close() so it runs
	// FIRST (LIFO) — the loop must not tick a probe into an already-closed
	// DB.
	lctx, lcancel := context.WithCancel(context.Background())
	defer db.Close()
	defer lcancel()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// Hourly sensor. Walk deterministic ids until the stagger phase is
	// LARGE (>5s) so a first-spawn loop provably does not probe within the
	// 1.5s window below (fnv is deterministic, so this is stable).
	const intervalS = 3600
	id := ""
	for i := 0; ; i++ {
		candidate := fmt.Sprintf("respawn-sensor-%d", i)
		if staggerPhase(candidate, time.Duration(intervalS)*time.Second) > 5*time.Second {
			id = candidate
			break
		}
	}
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES (?, ?, '127.0.0.1', 'icmp', ?, 200, 25, 2, 3, 'active', 'up', ?)`,
		id, id, intervalS, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}

	// Stub the probe transport so the loop ticks on the timer alone, with
	// no real socket. Record each tick's time.
	var mu sync.Mutex
	var stamps []time.Time
	origTarget := probeTarget
	probeTarget = func(ctx context.Context, probeType, target string, timeout time.Duration) probeOutcome {
		mu.Lock()
		stamps = append(stamps, time.Now())
		mu.Unlock()
		return probeOutcome{lost: false, rttMs: 5, ip: "127.0.0.1"} // a clean "up" probe
	}
	// LIFO: this restore runs FIRST at test end — after the explicit
	// lcancel() below has stopped the loop, so no concurrent read.
	defer func() { probeTarget = origTarget }()

	pw := NewProbeWorker(db)

	// (1) FIRST spawn: the staggered phase must be honored (anti-herd).
	pw.syncSensors(lctx)
	time.Sleep(1500 * time.Millisecond)
	mu.Lock()
	nFirst := len(stamps)
	mu.Unlock()
	if nFirst != 0 {
		t.Fatalf("first-spawn loop probed %d time(s) within 1.5s — staggered phase (>5s) not honored (anti-herd regression)", nFirst)
	}

	// (2) Simulate the sync pass dropping the sensor — the end state of a
	// >5s pause, a maintenance-mode end, or a config-edit Restart:
	// loop + state gone, DB row still active.
	pw.mu.Lock()
	if cancel, ok := pw.loops[id]; ok {
		cancel()
		delete(pw.loops, id)
	}
	delete(pw.sensors, id)
	pw.mu.Unlock()

	// (3) RESPAWN: the next sync pass must probe within the cap, not the
	// full phase.
	pw.syncSensors(lctx)
	deadline := time.Now().Add(3 * time.Second) // cap 1s + generous margin
	for {
		mu.Lock()
		n := len(stamps)
		mu.Unlock()
		if n > nFirst {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("respawned loop did not probe within 3s (cap %v) — a resumed sensor would be dark for up to a full interval", respawnFirstTickCap)
		}
		time.Sleep(20 * time.Millisecond)
	}
	lcancel() // stop the loop before the probeTarget restore defer runs
}
