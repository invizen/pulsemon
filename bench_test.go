package main

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"testing"
	"time"
)

// This file holds the opt-in performance benchmarks (2026-10-23 external
// review F15). They are NOT part of the normal test gate: `go test` and the
// CI `go test -race ./...` do not run them. Run them explicitly:
//
//	go test -run=^$ -bench='BenchmarkPurgeOld|BenchmarkComputeSensorStats' -benchtime=1x .
//
// -benchtime=1x is recommended for BenchmarkPurgeOld: the purge DELETES its
// target rows, so it cannot be looped without re-seeding (which would dominate
// the measurement) — one representative run of the full-scale purge is the
// honest measure of the hourly retention job. BenchmarkComputeSensorStats is a
// pure read and loops cleanly, so it can use the default -benchtime.

// benchPurgeSensors x benchPurgeRowsPerSensor = 1M old rows — the reviewer's
// scale, close to the real steady-state table (100 sensors @ 5s @ 24h ≈ 1.7M).
const benchPurgeSensors = 100
const benchPurgeRowsPerSensor = 10_000

// BenchmarkPurgeOld measures the per-sensor batched retention purge at ~1M
// old rows. The F3 rewrite replaced one full-table-scan DELETE per table with
// per-sensor covering-index range deletes in purgeBatchSize (5000) batches;
// this benchmark tracks that the rewrite stays bounded as the table grows.
//
// Single representative run (see file doc): the seed is one-time setup, the
// purge is the measured work. The young (in-window) rows confirm the purge is
// bounded — they must survive — and are logged, not hard-asserted (a
// benchmark that Fatals on a data assertion is a test, not a bench; the
// correctness is locked by TestPurgeOldMultiBatchPerSensor).
func BenchmarkPurgeOld(b *testing.B) {
	b.ReportAllocs()
	db, err := NewDB(filepath.Join(b.TempDir(), "purgebench.db"))
	if err != nil {
		b.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		b.Fatalf("InitSchema: %v", err)
	}
	seedPurgeBenchmark(b, db)

	pw := &ProbeWorker{db: db}
	b.ResetTimer()
	pw.purgeOld(context.Background()) // one representative purge of the full ~1M-row table
	b.StopTimer()

	var young int
	if err := db.QueryRow("SELECT COUNT(*) FROM probes").Scan(&young); err != nil {
		b.Fatalf("count survivors: %v", err)
	}
	want := benchPurgeSensors * 10 // the 10 in-window rows per sensor
	b.Logf("purged %d old rows across %d sensors; %d young rows survived (want %d)",
		benchPurgeSensors*benchPurgeRowsPerSensor, benchPurgeSensors, young, want)
	if young != want {
		b.Errorf("young rows after purge = %d, want %d (purge deleted in-window rows)", young, want)
	}
}

// seedPurgeBenchmark inserts benchPurgeSensors sensors, each with
// benchPurgeRowsPerSensor past-boundary (old) rows + 10 in-window (young)
// rows, in a single transaction with prepared statements (the same pattern as
// TestPurgeOldMultiBatchPerSensor, scaled up).
func seedPurgeBenchmark(b *testing.B, db *DB) {
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := db.Begin()
	if err != nil {
		b.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()
	sensSt, err := tx.Prepare(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES (?, ?, '127.0.0.1', 30, 1000, 25, 2, 3, 'active', 'up', ?)`)
	if err != nil {
		b.Fatalf("prepare sensor: %v", err)
	}
	defer sensSt.Close()
	probeSt, err := tx.Prepare(`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES (?, ?, 10.0)`)
	if err != nil {
		b.Fatalf("prepare probe: %v", err)
	}
	defer probeSt.Close()

	now := time.Now().UTC()
	oldBase := now.Add(-30 * time.Hour) // old rows: 30h .. ~27.2h old (all past the 24h boundary)
	youngBase := now.Add(-time.Hour)    // young rows: 1h .. 1h9m old (inside the window)
	for s := 0; s < benchPurgeSensors; s++ {
		id := fmt.Sprintf("s%03d", s)
		if _, err := sensSt.Exec(id, id, createdAt); err != nil {
			b.Fatalf("insert sensor %s: %v", id, err)
		}
		for i := 0; i < benchPurgeRowsPerSensor; i++ {
			ts := oldBase.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
			if _, err := probeSt.Exec(id, ts); err != nil {
				b.Fatalf("insert old probe %s/%d: %v", id, i, err)
			}
		}
		for i := 0; i < 10; i++ {
			ts := youngBase.Add(time.Duration(i) * time.Minute).Format(time.RFC3339Nano)
			if _, err := probeSt.Exec(id, ts); err != nil {
				b.Fatalf("insert young probe %s/%d: %v", id, i, err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatalf("commit: %v", err)
	}
}

// benchStatsSensors x benchStatsEntriesPerSensor: the reviewer's scale —
// 100 sensors, each with a full 24h of 5s-cadence probes (17,280 entries).
const benchStatsSensors = 100
const benchStatsEntriesPerSensor = 17_280

// BenchmarkComputeSensorStats measures the per-poll stats computation at
// 100 sensors x 17,280 entries (the 5s-cadence 24h steady state). The F4
// rewrite made the 1h and sparkline passes binary-search the hour boundary
// (skipping the older tail) and moved the 24h uptime to O(1) incremental
// counters; this benchmark tracks that the per-poll cost stays bounded as the
// series grows.
//
// computeSensorStats is a pure read (no mutation), so it loops cleanly under
// b.N. Each iteration computes stats for ALL 100 sensors = one dashboard poll
// cycle. SetBytes reports throughput over the 16-byte pointer-free entries.
func BenchmarkComputeSensorStats(b *testing.B) {
	b.ReportAllocs()
	now := time.Now().Unix()
	series := make([][]probeEntry, benchStatsSensors)
	for s := range series {
		series[s] = makeBenchSeries(benchStatsEntriesPerSensor, now)
	}
	// All entries span exactly 24h, so the 24h counters cover the whole series.
	total24 := benchStatsEntriesPerSensor
	lost24 := 0
	for i := 0; i < benchStatsEntriesPerSensor; i++ {
		if i%50 == 0 { // matches makeBenchSeries' loss pattern
			lost24++
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for s := range series {
			_ = computeSensorStats(series[s], now, total24, lost24)
		}
	}
	// 16 bytes per probeEntry (8 ts + 4 rtt + 1 manual + 3 padding).
	b.SetBytes(int64(benchStatsSensors * benchStatsEntriesPerSensor * 16))
}

// makeBenchSeries builds a ts-sorted (oldest-first) slice of n entries at a
// 5s cadence ending at now, with a realistic mix of RTTs (10-49ms) and ~2%
// losses (every 50th entry).
func makeBenchSeries(n int, now int64) []probeEntry {
	e := make([]probeEntry, n)
	for i := range e {
		e[i].ts = now - int64(n-1-i)*5
		if i%50 == 0 {
			e[i].rtt = float32(math.NaN()) // lost
		} else {
			e[i].rtt = float32(10 + (i % 40)) // 10-49 ms
		}
	}
	return e
}
