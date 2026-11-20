package main

import (
	"fmt"
	"testing"
	"time"
)

// TestFirstTickPhaseRespawnSpread pins the external-review 2026-11-19
// F18 fix: a RESPAWNED sensor's first tick is hashed into the cap window
// ([250ms, cap+250ms)) instead of clamped to the cap. Pre-fix, every
// resumed sensor whose staggered phase exceeded the cap (~98% of 60s
// sensors) landed on the EXACT same 1.000s instant, so a bulk
// maintenance-resume of hundreds of sensors was one synchronized write
// burst against probeDB (MaxOpenConns(1)).
func TestFirstTickPhaseRespawnSpread(t *testing.T) {
	const n = 200

	distinct := make(map[time.Duration]bool)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("f18-resume-%d", i)
		phase := firstTickPhase(id, time.Minute, true)
		distinct[phase] = true
		if phase < 250*time.Millisecond || phase >= respawnFirstTickCap+250*time.Millisecond {
			t.Fatalf("resumed phase for %q = %v, want within [250ms, %v) — the respawn window moved", id, phase, respawnFirstTickCap+250*time.Millisecond)
		}
	}
	if len(distinct) < 100 {
		t.Fatalf("%d resumed 60s sensors collapsed to %d distinct first-tick phases — the clamp herd is back (want a hash spread across the cap window)", n, len(distinct))
	}

	// Determinism: the same id always gets the same phase (stable FNV
	// hash), so respawns of the same sensor set land at the same
	// per-sensor offsets on every maintenance exit.
	id := "f18-resume-0"
	if a, b := firstTickPhase(id, time.Minute, true), firstTickPhase(id, time.Minute, true); a != b {
		t.Fatalf("resumed phase for %q is not deterministic: %v vs %v", id, a, b)
	}
}

// TestFirstTickPhaseFirstSpawnUnchanged pins the positive controls for
// F18: the fix touches ONLY the respawn branch. First spawns keep the
// full staggered phase (the steady-state anti-herd), and a sub-cap
// interval is never re-hashed — its already-small stagger stands.
func TestFirstTickPhaseFirstSpawnUnchanged(t *testing.T) {
	id := hourlyStaggerID(t)
	if got, want := firstTickPhase(id, time.Hour, false), staggerPhase(id, time.Hour); got != want {
		t.Fatalf("first-spawn phase = %v, want the full staggered %v (no cap at process start)", got, want)
	}
	if got, want := firstTickPhase("f18-fast", time.Second, true), staggerPhase("f18-fast", time.Second); got != want {
		t.Fatalf("sub-cap-interval resumed phase = %v, want the staggered %v (no re-hash below the cap)", got, want)
	}
}
