package main

// Review 2026-10-24 (Major): both clear-history handlers deleted the probes
// and events tables with single unbounded statements. At fleet scale
// (100 sensors @ 5s ≈ 1.7M rows) that held the SQLite WAL write lock for
// seconds, stalling probe INSERTs — and, via syncSensors' deliberate
// under-lock fresh reads (bounded by the 15s busy_timeout), every probe
// loop and healthz. The fix runs the two LARGE deletes batched in
// purgeBatchSize chunks (the purgeOld idiom) while keeping the small
// state-consistency steps (alert_state, status reset) atomic.

import (
	"context"
	"fmt"
	"path/filepath"
	"pulsemon/internal/store"
	"runtime"
	"strings"
	"testing"
	"time"
)

func clearBatchFixture(t *testing.T, sensorID string, rows int) *store.Store {
	t.Helper()
	db, err := store.NewStore(filepath.Join(t.TempDir(), "clearbatch.db"))
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES (?, ?, '127.0.0.1', 30, 1000, 25, 4, 3, 'active', 'up', ?)`,
		sensorID, sensorID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert sensor %s: %v", sensorID, err)
	}
	if rows > 0 {
		tx, err := db.Begin()
		if err != nil {
			t.Fatalf("begin seed tx: %v", err)
		}
		base := time.Now().UTC().Add(-24 * time.Hour)
		for i := 0; i < rows; i++ {
			if _, err := tx.Exec(
				"INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip) VALUES (?, ?, 5.0, '127.0.0.1')",
				sensorID, base.Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano)); err != nil {
				t.Fatalf("seed %d: %v", i, err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit seed: %v", err)
		}
	}
	return db
}

func countProbes(t *testing.T, db *store.Store, id string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM probes WHERE sensor_id = ?", id).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", id, err)
	}
	return n
}

// TestDeleteRowsBatchedFilters: multi-batch delete (purgeBatchSize chunks)
// removes exactly the filtered rows, reports the true total, and leaves the
// other sensor's rows untouched.
func TestDeleteRowsBatchedFilters(t *testing.T) {
	db := clearBatchFixture(t, "bulk", purgeBatchSize*2+5)
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('keep', 'keep', '127.0.0.1', 30, 1000, 25, 4, 3, 'active', 'up', ?)`,
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert keep sensor: %v", err)
	}
	base := time.Now().UTC().Add(-2 * time.Hour)
	for i := 0; i < 7; i++ {
		if _, err := db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES ('keep', ?, 5.0)",
			base.Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("keep probe: %v", err)
		}
	}

	total, err := deleteRowsBatched(context.Background(), db, "probes", "sensor_id = ?", []any{"bulk"})
	if err != nil {
		t.Fatalf("deleteRowsBatched: %v", err)
	}
	want := int64(purgeBatchSize*2 + 5)
	if total != want {
		t.Errorf("total deleted = %d, want %d (the RowsAffected sum must be exact — handlers report it to the UI)", total, want)
	}
	if n := countProbes(t, db, "bulk"); n != 0 {
		t.Errorf("bulk sensor still has %d rows", n)
	}
	if n := countProbes(t, db, "keep"); n != 7 {
		t.Errorf("unfiltered rows collateral-damaged: keep sensor has %d rows, want 7", n)
	}
}

// TestDeleteRowsBatchedAllAndEmpty: the no-filter form clears everything,
// and an already-empty table returns (0, nil) without looping.
func TestDeleteRowsBatchedAllAndEmpty(t *testing.T) {
	db := clearBatchFixture(t, "bulk", 3)
	total, err := deleteRowsBatched(context.Background(), db, "probes", "", nil)
	if err != nil {
		t.Fatalf("deleteRowsBatched all: %v", err)
	}
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
	total, err = deleteRowsBatched(context.Background(), db, "probes", "", nil)
	if err != nil || total != 0 {
		t.Errorf("empty-table delete = (%d, %v), want (0, nil)", total, err)
	}
}

// TestDeleteRowsBatchedArgSliceBuiltOnce (review 2026-11-10 #7): the
// argument slice (args + purgeBatchSize) is built ONCE per call, not per
// batch iteration — a full-table wipe loops 1.7M/purgeBatchSize times, and
// the old in-loop append(append([]any{}, args...), purgeBatchSize)
// allocated a fresh []any on every iteration. The allocation delta per
// EXTRA batch must therefore stay at the driver's per-statement baseline
// (database/sql builds its own arg slice per ExecContext): measured 5.9
// post-fix vs 6.9 pre-fix on the gate box, both with and without -race.
// The Mallocs counter is exact and the GC runs before each measurement, so
// the numbers are deterministic on a given driver — if a driver change
// moves the baseline, re-measure both sides and re-center the threshold
// (it sits midway between them). The batch spread is 2 vs 7 deliberately:
// at a 2-batch spread the 1-alloc-per-batch difference is inside the
// measurement's ±1 noise.
func TestDeleteRowsBatchedArgSliceBuiltOnce(t *testing.T) {
	db := clearBatchFixture(t, "bulk", purgeBatchSize+1)
	reseed := func(rows int) {
		tx, err := db.Begin()
		if err != nil {
			t.Fatalf("begin reseed: %v", err)
		}
		if _, err := tx.Exec("DELETE FROM probes WHERE sensor_id = 'bulk'"); err != nil {
			t.Fatalf("reseed clear: %v", err)
		}
		base := time.Now().UTC().Add(-24 * time.Hour)
		// Multi-row INSERT chunks: per-row Exec calls made the re-seed the
		// test's runtime (42s under -race); chunked statements are ~100x
		// fewer driver round-trips and the wipe itself stays the measured
		// work.
		const chunk = 500
		for start := 0; start < rows; start += chunk {
			end := start + chunk
			if end > rows {
				end = rows
			}
			var sb strings.Builder
			sb.WriteString("INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip) VALUES ")
			for i := start; i < end; i++ {
				if i > start {
					sb.WriteString(",")
				}
				fmt.Fprintf(&sb, "('bulk', '%s', 5.0, '127.0.0.1')", base.Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano))
			}
			if _, err := tx.Exec(sb.String()); err != nil {
				t.Fatalf("reseed %d-%d: %v", start, end, err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("reseed commit: %v", err)
		}
	}
	measure := func(rows, runs int) float64 {
		var total uint64
		for i := 0; i < runs; i++ {
			reseed(rows) // outside the measured window
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			if _, err := deleteRowsBatched(context.Background(), db, "probes", "", nil); err != nil {
				t.Fatalf("wipe: %v", err)
			}
			runtime.ReadMemStats(&after)
			total += after.Mallocs - before.Mallocs
		}
		return float64(total) / float64(runs)
	}
	small := measure(purgeBatchSize+1, 3) // 2 batches
	big := measure(purgeBatchSize*6+1, 3) // 7 batches
	perBatch := (big - small) / 5
	if perBatch > 6.50 {
		t.Errorf("per-extra-batch allocations = %.2f, want <= 6.50 (driver baseline ~5.9; the old in-loop slice append measured ~6.9)", perBatch)
	}
}
