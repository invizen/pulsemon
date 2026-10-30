package main

import (
	"context"
	"github.com/google/uuid"
	"path/filepath"
	"pulsemon/internal/store"
	"testing"
	"time"
)

func fcDB(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.NewStore(filepath.Join(t.TempDir(), "fc.db"))
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func fcSensor(t *testing.T, db *store.Store, id, name, state string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO sensors (id,name,target,type,interval_s,timeout_ms,loss_warn,down_after,spike_mult,state,status,created_at)
		VALUES (?,?,'10.0.0.1','icmp',60,1000,25,2,5,?,'up',?)`, id, name, state, store.Now()); err != nil {
		t.Fatal(err)
	}
}

func fcProbe(t *testing.T, db *store.Store, id string, ts time.Time, rtt any) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES (?,?,?)`, id, store.FormatTS(ts), rtt); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------- M1

func TestFix_M1_StaggerPhaseAlwaysInRange(t *testing.T) {
	for _, interval := range []time.Duration{time.Second, 15 * time.Second, 60 * time.Second, time.Hour} {
		low := 0
		for i := 0; i < 20000; i++ {
			p := staggerPhase(uuid.NewString(), interval)
			if p < 250*time.Millisecond {
				t.Fatalf("interval %v: phase %v < 250ms (negative/immediate => no stagger)", interval, p)
			}
			if p > interval+250*time.Millisecond {
				t.Fatalf("interval %v: phase %v exceeds interval+250ms", interval, p)
			}
			if p < interval/2 {
				low++
			}
		}
		if low < 8000 || low > 12000 { // distribution sanity: ~50% below half-interval
			t.Errorf("interval %v: %d/20000 below half interval, distribution looks skewed", interval, low)
		}
	}
}

func TestFix_M1_StaggerPhaseZeroIntervalDoesNotPanic(t *testing.T) {
	if p := staggerPhase("x", 0); p < 250*time.Millisecond {
		t.Fatalf("zero interval phase = %v", p)
	}
}

func TestFix_M1_ProbePanicIsContained(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "s1", "s1", "active")
	pw := NewProbeWorker(db)
	pw.sensors["s1"] = &ProbeState{id: "s1"}
	old := probeTarget
	defer func() { probeTarget = old }()
	probeTarget = func(ctx context.Context, typ, target string, d time.Duration) probeOutcome { panic("boom") }
	// must not propagate
	pw.safeProbe(context.Background(), sensorConfig{id: "s1", name: "s1", target: "10.0.0.1", probeType: "icmp", intervalS: 60, timeoutMS: 100, lossWarn: 25, downAfter: 2})
}
