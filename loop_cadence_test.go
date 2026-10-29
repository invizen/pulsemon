package main

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestSensorLoopResetCadence pins the sensorLoop timer-reset behavior the
// "drain the timer channel before Reset" review finding targets. It drives a
// REAL sensorLoop (interval=1s) with a stubbed probeTarget, records each tick's
// wall-clock time, and asserts the loop maintains its intended cadence:
//
//   - No SPURIOUS rapid tick: every gap between consecutive ticks must be >=
//     ~0.7*interval. A pre-Go-1.23-style stale token (or a reset that left a
//     queued tick) would produce a near-0 gap.
//   - No MISSED tick: every gap must be <= ~2.5*interval, and the loop must
//     keep ticking (>= 4 ticks in the window). Forgetting to Reset the timer
//     would make it fire ONCE and then stop (gaps -> infinity / no further
//     ticks).
//
// Why this is correct on Go 1.26 without a Stop+drain preamble: since Go 1.23
// the timer channel is SYNCHRONOUS (capacity 0), and sensorLoop drains timer.C
// in the select (probe.go:724) before calling timer.Reset(nextDelay) (line
// 751) in the same goroutine. The stdlib (time/sleep.go) guarantees "any
// receive from t.C after Reset has returned is guaranteed not to receive a
// time value corresponding to the previous timer settings" — so a stale token
// cannot be read after the reset. The reviewer's "if !timer.Stop() { <-timer.C
// }" preamble is a pre-1.23 idiom; it is harmless on 1.26 but unnecessary, and
// it does NOT fix any bug here. nextDelay is always >= 1s (interval is
// 1-3600 per the API, and the fast-retry path is min(30s, interval) —
// never faster than the interval), so "rapid spurious firing from dynamic
// reconfiguration" is also impossible.
func TestSensorLoopResetCadence(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "loop-cadence.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	const id = "cad"
	const intervalS = 1 // minimum allowed; keeps the test fast
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES (?, ?, '127.0.0.1', 'icmp', ?, 200, 25, 2, 3, 'active', 'up', ?)`,
		id, id, intervalS, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}

	// Stub the probe transport so sensorLoop ticks on the timer alone, with no
	// real socket/HTTP. Record each tick's time to measure the cadence.
	var mu sync.Mutex
	var stamps []time.Time
	var calls atomic.Int64
	origTarget := probeTarget
	probeTarget = func(ctx context.Context, probeType, target string, timeout time.Duration) probeOutcome {
		calls.Add(1)
		mu.Lock()
		stamps = append(stamps, time.Now())
		mu.Unlock()
		return probeOutcome{lost: false, rttMs: 5, ip: "127.0.0.1"} // a clean "up" probe
	}
	defer func() { probeTarget = origTarget }()

	pw := &ProbeWorker{
		sensors:         make(map[string]*ProbeState),
		loops:           make(map[string]context.CancelFunc),
		db:              db,
		statsCache:      make(map[string]*probeSeries),
		alertOrderGates: make(map[string]chan func()),
	}
	pw.sensors[id] = &ProbeState{id: id}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pw.sensorLoop(ctx, sensorConfig{
		id: id, name: id, target: "127.0.0.1", probeType: "icmp",
		intervalS: intervalS, timeoutMS: 200,
		// Match the seeded row (loss_warn=25, down_after=2): a zeroed
		// config is unreachable via the API and would trip the
		// consec >= downAfter check on every tick.
		lossWarn: 25, downAfter: 2,
	}, false) // false = first-spawn semantics (this test never went through syncSensors)

	// Let it tick. interval=1s + a deterministic per-sensor phase (>=0.25s)
	// puts ticks ~1.25s apart; 5.5s yields ~4 ticks.
	time.Sleep(5500 * time.Millisecond)
	cancel()
	// Give the in-flight loop a moment to exit; sensorLoop returns on ctx.Done.
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(stamps)
		mu.Unlock()
		if n >= 4 {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	mu.Lock()
	got := stamps
	mu.Unlock()
	if calls.Load() < 4 {
		t.Fatalf("sensorLoop fired %d times in 5.5s with interval=1s — expected >= 4; a timer that stopped resetting would fire once then hang", calls.Load())
	}
	const minGap, maxGap = 0.7, 2.5 // seconds, around the ~1.25s expected cadence
	for i := 1; i < len(got); i++ {
		gap := got[i].Sub(got[i-1]).Seconds()
		if gap < minGap {
			t.Fatalf("tick %d came %.3fs after tick %d — spurious rapid tick (a stale timer token fired immediately after Reset)", i, gap, i-1)
		}
		if gap > maxGap {
			t.Fatalf("tick %d came %.3fs after tick %d — a tick was missed (the timer stopped resetting)", i, gap, i-1)
		}
	}
	t.Logf("sensorLoop cadence OK: %d ticks, gaps all within [%.1fs, %.1fs] (interval=%ds, no spurious, no missed)",
		len(got), minGap, maxGap, intervalS)
}

// TestSensorLoopFastRetryMatchesInterval pins the fast-retry cadence of a
// sub-30s sensor in ERROR: a 5s-interval sensor that is down must be
// re-checked every 5s — min(errorRetryInterval, interval) — NOT every 10s.
// The 10s floor that used to sit here made an erroring 5s sensor re-check
// HALF as often as its normal pace, slowing recovery detection and
// contradicting the fast-retry contract (the fastRetry comment in probe.go
// says "re-check on the shortened cadence"). The min() cap alone already
// guarantees the fast path is never faster than the user's pace, so the
// floor protected no load bound. Fails on the old code (gap ~10s).
func TestSensorLoopFastRetryMatchesInterval(t *testing.T) {
	dir := t.TempDir()
	db, err := NewDB(filepath.Join(dir, "fast-retry.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	lctx, lcancel := context.WithCancel(context.Background())
	defer db.Close()
	defer lcancel()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// 5s sensor, down_after=2: an all-loss window is two+ consecutive
	// losses -> status error -> fastRetry on.
	const intervalS = 5
	// Walk deterministic ids until the stagger phase is >= 2s: the loop
	// must not tick before we seed the history (fnv is deterministic, so
	// this is stable).
	id := ""
	for i := 0; ; i++ {
		candidate := fmt.Sprintf("fastretry-sensor-%d", i)
		if staggerPhase(candidate, time.Duration(intervalS)*time.Second) >= 2*time.Second {
			id = candidate
			break
		}
	}
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES (?, ?, '127.0.0.1', 'icmp', ?, 200, 25, 2, 3, 'active', 'up', ?)`,
		id, id, intervalS, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}

	// Stub the probe transport: the sensor is DOWN — every probe is lost.
	var mu sync.Mutex
	var stamps []time.Time
	origTarget := probeTarget
	probeTarget = func(ctx context.Context, probeType, target string, timeout time.Duration) probeOutcome {
		mu.Lock()
		stamps = append(stamps, time.Now())
		mu.Unlock()
		return probeOutcome{lost: true}
	}
	defer func() { probeTarget = origTarget }()

	pw := NewProbeWorker(db)
	pw.syncSensors(lctx)

	// Seed 8 prior losses into the DURABLE history: deriveStatus reads an
	// 8-row window (statusWindow) and only trusts the in-memory cache once
	// it holds a full one, so the DB is what the first probe sees. The
	// loop's first lost probe then makes the whole window loss.
	for i := 1; i <= 8; i++ {
		ts := time.Now().UTC().Add(-time.Duration(i) * 5 * time.Second)
		if _, err := db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip, http_status, manual) VALUES (?, ?, NULL, ?, NULL, 0)`,
			id, fmtTS(ts), "127.0.0.1"); err != nil {
			t.Fatalf("seed loss %d: %v", i, err)
		}
	}

	// Timeline — the loop reads fastRetry at the TOP of each iteration,
	// so the first delay computed with fast=true is the one AFTER the
	// probe that flips the sensor to error:
	//   tick 1 at the stagger phase: fast=false -> delay = 5s; probe
	//     (all-loss window) -> error, fastRetry=true
	//   tick 2 at +5s: fast=true -> delay = min(30s, 5s) = 5s (new) /
	//     10s (old floor)
	//   tick 3: the gap between 2 and 3 is the assertion.
	deadline := time.Now().Add(22 * time.Second)
	for {
		mu.Lock()
		n := len(stamps)
		mu.Unlock()
		if n >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d tick(s) in 22s with interval=%ds — expected >= 3", n, intervalS)
		}
		time.Sleep(50 * time.Millisecond)
	}
	mu.Lock()
	got := stamps
	mu.Unlock()
	lcancel()

	gap := got[2].Sub(got[1]) // first gap computed with fastRetry on
	if gap < 3500*time.Millisecond || gap > 7*time.Second {
		t.Fatalf("fast-retry gap = %v, want ~%ds (min(30s, interval)) — ~10s is the removed floor slowing a 5s sensor's recovery detection", gap, intervalS)
	}
}
