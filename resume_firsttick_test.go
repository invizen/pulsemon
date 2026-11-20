package main

// First-tick pins for the resume paths (m3):
//   - a sensor CREATED paused and then resumed is a first spawn, so the
//     spawnedIDs respawn cap alone misses it — the sync passes must read
//     paused rows and mark wasPaused, capping the resume's first probe at
//     respawnFirstTickCap instead of the full staggered phase.
//   - FIRST spawns (process start) keep the full staggered phase: probe
//     times are phase + k*interval, so capping first-spawn phases
//     (min(interval, 60s)) would pack every same-interval sensor's
//     steady-state probes into the same 60-second window every interval —
//     the herd the stagger exists to prevent.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"pulsemon/internal/store"
)

// hourlyStaggerID returns a deterministic sensor id whose first-tick
// phase at a 1h interval exceeds one minute (so the pre-fix full-stagger
// path is observably distinct from the 1s cap within the test's budget).
func hourlyStaggerID(t *testing.T) string {
	t.Helper()
	for i := 0; ; i++ {
		id := fmt.Sprintf("m3-hourly-%d", i)
		if staggerPhase(id, time.Hour) > time.Minute {
			return id
		}
	}
}

// TestResumeCreatedPausedSensorProbesPromptly pins the created-paused
// resume: a sensor INSERTed with state='paused' (POST creates paused by
// design), never spawned, then resumed, must probe within ~cap+slack —
// not sit dark for its staggered phase (up to an hour on an hourly
// sensor). Pre-fix the resume was a first spawn: spawnedIDs is false and
// the full phase applied.
func TestResumeCreatedPausedSensorProbesPromptly(t *testing.T) {
	db := newTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	id := hourlyStaggerID(t)
	if staggerPhase(id, time.Hour) <= respawnFirstTickCap {
		t.Fatalf("test id %q has a sub-cap phase; pick a discriminating id", id)
	}
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, created_at, status)
		VALUES (?, 'hourly', '10.99.99.9', 'ping', 3600, 2000, 2, 3, 2, 'paused', ?, 'up')`,
		id, store.FormatTS(time.Now())); err != nil {
		t.Fatalf("insert paused sensor: %v", err)
	}

	probed := make(chan time.Time, 4)
	old := probeTarget
	probeTarget = func(ctx context.Context, probeType, target string, timeout time.Duration) probeOutcome {
		select {
		case probed <- time.Now():
		default:
		}
		return probeOutcome{}
	}
	t.Cleanup(func() {
		probeTarget = old
		cancel()
	})

	pw := NewProbeWorker(db)
	pw.syncSensors(ctx)
	if _, ok := pw.loops[id]; ok {
		t.Fatal("paused sensor got a loop on the first pass")
	}
	select {
	case <-probed:
		t.Fatal("paused sensor probed without a resume")
	case <-time.After(50 * time.Millisecond):
	}

	if _, err := db.Exec(`UPDATE sensors SET state = 'active' WHERE id = ?`, id); err != nil {
		t.Fatalf("resume: %v", err)
	}
	start := time.Now()
	pw.syncSensors(ctx) // the pass that sees the resume (syncReq is Run's job; direct call here)
	select {
	case at := <-probed:
		if el := at.Sub(start); el > 3*time.Second {
			t.Fatalf("resumed sensor probed %v after resume, want <= respawnFirstTickCap+slack", el)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("resumed hourly sensor never probed within 3s — it got the full staggered phase (resume must count as a respawn)")
	}
	if _, ok := pw.loops[id]; !ok {
		t.Fatal("resumed sensor has no loop after the resume pass")
	}
	pw.mu.Lock()
	if len(pw.wasPaused) != 0 {
		pw.mu.Unlock()
		t.Fatal("resume marker not consumed by the spawn")
	}
	pw.mu.Unlock()
}

// TestFirstSpawnKeepsFullStagger pins the process-start contract the m3
// re-flag proposed to relax: first spawns are NOT capped. The cap is for
// operator-initiated resumes only; capping first spawns (the proposed
// min(interval, 60s)) aligns every same-interval sensor's steady-state
// probes into one 60-second window per interval.
func TestFirstSpawnKeepsFullStagger(t *testing.T) {
	id := hourlyStaggerID(t)
	if got, want := firstTickPhase(id, time.Hour, false), staggerPhase(id, time.Hour); got != want {
		t.Fatalf("first-spawn phase = %v, want the full staggered %v (no cap at process start)", got, want)
	}
	if firstTickPhase(id, time.Hour, false) <= respawnFirstTickCap {
		t.Fatal("discriminating id lost its stagger")
	}
	// F18: the resumed phase is HASHED into the cap window
	// ([250ms, cap+250ms)) — the old exact-cap assertion pinned the
	// clamp, which was the thundering herd.
	if got := firstTickPhase(id, time.Hour, true); got < 250*time.Millisecond || got >= respawnFirstTickCap+250*time.Millisecond {
		t.Fatalf("resumed phase = %v, want within [250ms, %v)", got, respawnFirstTickCap+250*time.Millisecond)
	}
	// Sub-cap phases are untouched by the cap (cap is a ceiling, not a floor).
	if got, want := firstTickPhase("m3-fast", time.Second, true), staggerPhase("m3-fast", time.Second); got != want {
		t.Fatalf("short-interval resumed phase = %v, want the staggered %v", got, want)
	}
}
