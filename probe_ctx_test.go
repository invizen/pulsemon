package main

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestDoProbeDropsResultWhenCancelled locks the finding-6 fix: when the
// sensor loop's ctx is cancelled mid-probe (shutdown, sensor Remove or
// Restart), doProbe must NOT write a probe row for the cancelled probe.
// Pre-fix, the probe ran on context.Background() to completion and the row
// was written regardless — for a deleted sensor that is an FK violation, and
// on shutdown it races db.Close().
func TestDoProbeDropsResultWhenCancelled(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "ctxdrop.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('ctxd','ctxd','127.0.0.1','icmp',15,1000,25,1,3,'active','up','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}
	pw := NewProbeWorker(db)

	// Simulate a long probe (e.g. 30s timeout) that is cut short by the
	// cancellation: block until ctx is done, then return.
	orig := probeTarget
	probeTarget = func(ctx context.Context, probeType, target string, timeout time.Duration) probeOutcome {
		<-ctx.Done()
		return probeOutcome{lost: true, ip: "127.0.0.1"}
	}
	defer func() { probeTarget = orig }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pw.doProbe(ctx, sensorConfig{id: "ctxd", name: "ctxd", target: "127.0.0.1", probeType: "icmp", intervalS: 15, timeoutMS: 1000})
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("doProbe did not return after ctx cancel — probe is not ctx-aware")
	}

	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM probes WHERE sensor_id = ?", "ctxd").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("probe rows = %d, want 0 (a cancelled probe must not be recorded)", n)
	}
}

// TestRunReturnsWithinBudgetWhenProbeInFlight locks the shutdown path the
// finding targets: a sensor with a 30s timeout (the API maximum) mid-probe
// must not keep Run blocked past main's 10s worker budget. Pre-fix, doProbe
// ran its full probe on context.Background(), so Run sat out the whole 30s —
// shutdown then hit db.Close() with a live writer.
func TestRunReturnsWithinBudgetWhenProbeInFlight(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "runbudget.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	// 30s timeout = the maximum api.go allows; 15s interval.
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('rb','rb','127.0.0.1','icmp',15,30000,25,1,3,'active','up','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}
	pw := NewProbeWorker(db)

	var once sync.Once
	started := make(chan struct{})
	orig := probeTarget
	probeTarget = func(ctx context.Context, probeType, target string, timeout time.Duration) probeOutcome {
		once.Do(func() { close(started) })
		<-ctx.Done() // behaves like the 30s probe, aborting on cancel
		return probeOutcome{lost: true, ip: "127.0.0.1"}
	}
	defer func() { probeTarget = orig }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { pw.Run(ctx); close(done) }()

	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("sensor loop never probed within 10s (first tick has a phase delay; 10s is generous)")
	}

	start := time.Now()
	cancel()
	select {
	case <-done:
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("Run took %v after cancel, want < 5s (main's shutdown budget is 10s)", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of cancel — in-flight 30s probe is not cancellable (shutdown budget is 10s)")
	}
}
