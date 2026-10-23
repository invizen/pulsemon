package main

import (
	"context"
	"math"
	"testing"
	"time"
)

// ---------------------------------------------------------------- M10a

func TestFix_M10a_DeriveStatusReadsMemoryWhenWarm(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "a", "a", "active")
	pw := NewProbeWorker(db)
	// DB says healthy history; memory (the authority once warm) says 8 straight losses.
	now := time.Now()
	for i := 0; i < 8; i++ {
		fcProbe(t, db, "a", now.Add(time.Duration(i-20)*time.Second), 5.0)
	}
	for i := 0; i < 8; i++ {
		pw.recordProbe("a", probeEntry{ts: now.Unix() + int64(i), rtt: float32(math.NaN())})
	}
	c := sensorConfig{id: "a", downAfter: 2, lossWarn: 25}
	if got := pw.deriveStatus(c, "up"); got != "error" {
		t.Fatalf("derived %q; warm cache (8 losses) should win over the DB", got)
	}
}

func TestFix_M10a_DeriveStatusFallsBackToDBWhenCacheCold(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "a", "a", "active")
	pw := NewProbeWorker(db)
	now := time.Now()
	for i := 0; i < 4; i++ {
		fcProbe(t, db, "a", now.Add(time.Duration(i-10)*time.Second), nil)
	}
	pw.recordProbe("a", probeEntry{ts: now.Unix(), rtt: float32(math.NaN())}) // 1 cached entry < limit => DB path
	c := sensorConfig{id: "a", downAfter: 2, lossWarn: 25}
	if got := pw.deriveStatus(c, "up"); got != "error" {
		t.Fatalf("derived %q via cold cache fallback, want error", got)
	}
}

func TestFix_M10a_DoProbeStopsReadingStatusPerTick(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "a", "a", "active")
	pw := NewProbeWorker(db)
	pw.sensors["a"] = &ProbeState{id: "a"}
	old := probeTarget
	defer func() { probeTarget = old }()
	probeTarget = func(ctx context.Context, typ, target string, d time.Duration) probeOutcome {
		return probeOutcome{rttMs: 1}
	}
	c := sensorConfig{id: "a", name: "a", target: "10.0.0.1", probeType: "icmp", intervalS: 60, timeoutMS: 100, lossWarn: 25, downAfter: 2}
	pw.doProbe(context.Background(), c) // first tick reads status from DB once
	if pw.sensors["a"].lastStatus != "up" {
		t.Fatalf("lastStatus = %q after first probe", pw.sensors["a"].lastStatus)
	}
	// Corrupt the DB status behind its back: with memory authoritative, the next tick must NOT notice
	// (proves no per-tick SELECT status) and must not emit a transition.
	db.Exec(`UPDATE sensors SET status='error' WHERE id='a'`)
	pw.doProbe(context.Background(), c)
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM events WHERE sensor_id='a'`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d events; a steady 'up' sensor must not transition", n)
	}
}

func TestFix_M10a_StatusStaysConsistentWhenUpdateFails(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "a", "a", "active")
	pw := NewProbeWorker(db)
	pw.sensors["a"] = &ProbeState{id: "a"}
	old := probeTarget
	defer func() { probeTarget = old }()
	probeTarget = func(ctx context.Context, typ, target string, d time.Duration) probeOutcome {
		return probeOutcome{lost: true}
	}
	// make the UPDATE fail: trigger raises on status change
	if _, err := db.Exec(`CREATE TRIGGER nostatus BEFORE UPDATE OF status ON sensors BEGIN SELECT RAISE(ABORT,'nope'); END`); err != nil {
		t.Fatal(err)
	}
	c := sensorConfig{id: "a", name: "a", target: "10.0.0.1", probeType: "icmp", intervalS: 60, timeoutMS: 100, lossWarn: 25, downAfter: 2}
	for i := 0; i < 3; i++ {
		pw.doProbe(context.Background(), c)
	}
	if got := pw.sensors["a"].lastStatus; got == "error" {
		t.Fatal("memory says error but the DB UPDATE failed; lastStatus must only advance after persistence so the transition is retried")
	}
	db.Exec(`DROP TRIGGER nostatus`)
	pw.doProbe(context.Background(), c)
	var st string
	db.QueryRow(`SELECT status FROM sensors WHERE id='a'`).Scan(&st)
	if st != "error" {
		t.Fatalf("after the DB recovered the transition was not retried: status=%q", st)
	}
	// Drain the alert goroutines BEFORE the DB closes (t.Cleanup): the
	// up->warning->error transitions above launched alert deliveries, and an
	// in-flight delivery holds a pool connection open past db.Close(), which
	// leaves the SQLite -wal/-shm files behind and fails the TempDir cleanup
	// (same shutdown order as main: StopAlerts -> DrainAlerts -> db.Close).
	pw.DrainAlerts(5 * time.Second)
}

func TestFix_M10a_StatsForDoesNotCopyAndMatches(t *testing.T) {
	pw := NewProbeWorker(nil)
	now := time.Now().Unix()
	for i := 0; i < 500; i++ {
		pw.recordProbe("a", probeEntry{ts: now - int64(500-i), rtt: float32(i%7 + 1)})
	}
	pw.statsMu.RLock()
	sa := pw.statsCache["a"]
	want := computeSensorStats(sa.snapshot(), now, sa.total24, sa.lost24)
	pw.statsMu.RUnlock()
	got := pw.statsFor("a", now)
	if got.Total != want.Total || got.Uptime24h != want.Uptime24h || *got.RTTAvg != *want.RTTAvg {
		t.Fatalf("statsFor diverged from snapshot-based stats: %+v vs %+v", got, want)
	}
	allocs := testing.AllocsPerRun(20, func() { _ = pw.statsFor("a", now) })
	t24, l24 := sa.total24, sa.lost24
	base := testing.AllocsPerRun(20, func() { _ = computeSensorStats(sa.snapshot(), now, t24, l24) })
	if allocs >= base {
		t.Errorf("statsFor allocs %.0f not lower than snapshot path %.0f", allocs, base)
	}
}

func TestFix_M10a_DSNEnablesSynchronousNormal(t *testing.T) {
	db := fcDB(t)
	var v int
	if err := db.QueryRow(`PRAGMA synchronous`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != 1 { // 1 = NORMAL
		t.Fatalf("synchronous = %d, want 1 (NORMAL) with WAL", v)
	}
	var jm string
	db.QueryRow(`PRAGMA journal_mode`).Scan(&jm)
	if jm != "wal" {
		t.Fatalf("journal_mode = %q", jm)
	}
}
