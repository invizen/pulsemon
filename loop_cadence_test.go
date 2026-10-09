package main

import (
	"context"
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
// 1-3600 per the API, and the fast-retry path is floored to 10s), so "rapid
// spurious firing from dynamic reconfiguration" is also impossible.
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
	probeTarget = func(probeType, target string, timeout time.Duration) probeOutcome {
		calls.Add(1)
		mu.Lock()
		stamps = append(stamps, time.Now())
		mu.Unlock()
		return probeOutcome{lost: false, rttMs: 5, ip: "127.0.0.1"} // a clean "up" probe
	}
	defer func() { probeTarget = origTarget }()

	pw := &ProbeWorker{
		sensors:    make(map[string]*ProbeState),
		loops:      make(map[string]context.CancelFunc),
		db:         db,
		statsCache: make(map[string]*probeSeries),
	}
	pw.sensors[id] = &ProbeState{id: id}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pw.sensorLoop(ctx, sensorConfig{
		id: id, name: id, target: "127.0.0.1", probeType: "icmp",
		intervalS: intervalS, timeoutMS: 200,
	})

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
