package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDSNPragmaOrderPinsBusyTimeoutFirst pins the DSN ordering contract:
// the driver executes _pragma params in the order they appear, and
// journal_mode(WAL) is the only one that WRITES (it flips the file's mode
// and creates -wal/-shm). With the old order (journal_mode first), a lazy
// pool connection — and the 30s -healthz-http probe, which opens its own
// connection every check — that landed while another connection held the
// write lock ran the mode switch with busy_timeout = 0 and failed
// immediately with SQLITE_BUSY. busy_timeout must precede it.
func TestDSNPragmaOrderPinsBusyTimeoutFirst(t *testing.T) {
	dsn := dsnWithPragmas("file:/tmp/x.db", 15000)
	bt := strings.Index(dsn, "busy_timeout(15000)")
	wal := strings.Index(dsn, "journal_mode(WAL)")
	if bt < 0 || wal < 0 {
		t.Fatalf("DSN missing busy_timeout/journal_mode: %s", dsn)
	}
	if bt > wal {
		t.Fatalf("busy_timeout (offset %d) must precede journal_mode(WAL) (offset %d) — the driver runs _pragma params in order and journal_mode is the only one that writes", bt, wal)
	}
	for _, want := range []string{
		"foreign_keys(1)",
		"synchronous(NORMAL)",
		"temp_store(MEMORY)",
		"journal_size_limit(67108864)",
		"cache_size(-8000)",
	} {
		if !strings.Contains(dsn, want) {
			t.Errorf("DSN missing %s: %s", want, dsn)
		}
	}
}

// TestPragmasReachEveryPooledConnection is the functional side of the DSN
// pin: the pragmas must be in effect on a connection drawn from the pool
// (not just present in the DSN string). temp_store(MEMORY) matters in the
// FROM-scratch container (no /tmp, non-writable / — a temp B-tree spill
// would fail with SQLITE_CANTOPEN); journal_size_limit bounds the WAL
// after large deletes instead of pinning hundreds of MB on disk;
// cache_size keeps the warmStats 24h-window read from churning the
// default 2 MiB page cache.
//
// Read-back contract (verified against this driver): PRAGMA temp_store
// returns the C enum — 0=DEFAULT (the compile-time default, FILE in
// modernc), 1=FILE, 2=MEMORY. With the DSN pragma set it reads 2; with
// the pragma removed it reads 0, so the assertion discriminates.
func TestPragmasReachEveryPooledConnection(t *testing.T) {
	st, err := NewStore(filepath.Join(t.TempDir(), "tune.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer st.Close()
	if err := st.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	var tempStore int
	if err := st.QueryRow(`PRAGMA temp_store`).Scan(&tempStore); err != nil {
		t.Fatalf("PRAGMA temp_store: %v", err)
	}
	if tempStore != 2 {
		t.Errorf("temp_store = %d, want 2 (MEMORY) — the scratch container has no /tmp; a temp B-tree spill must not hit disk (0 = the compile-time FILE default)", tempStore)
	}
	var walLimit int
	if err := st.QueryRow(`PRAGMA journal_size_limit`).Scan(&walLimit); err != nil {
		t.Fatalf("PRAGMA journal_size_limit: %v", err)
	}
	if walLimit != 67108864 {
		t.Errorf("journal_size_limit = %d, want 67108864 (64 MiB) — an unbounded WAL stays at its post-purge high-water mark for the process lifetime", walLimit)
	}
	var cache int
	if err := st.QueryRow(`PRAGMA cache_size`).Scan(&cache); err != nil {
		t.Fatalf("PRAGMA cache_size: %v", err)
	}
	if cache != -8000 {
		t.Errorf("cache_size = %d, want -8000 (8 MiB, in KiB)", cache)
	}
}

// TestPragmasReachProbeHandle pins the same contract on the second handle:
// the probe-write pool opens its OWN connection from the same
// dsnWithPragmas output, so temp_store(MEMORY) must reach it too — a
// probe-path query that spills a temp B-tree in the container would
// otherwise fail on the write handle even though the main pool is fine.
func TestPragmasReachProbeHandle(t *testing.T) {
	st, err := NewStore(filepath.Join(t.TempDir(), "tune-probe.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer st.Close()
	if err := st.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	var tempStore int
	err = st.ProbeImmediateTx(context.Background(), func(c *sql.Conn) error {
		return c.QueryRowContext(context.Background(), `PRAGMA temp_store`).Scan(&tempStore)
	})
	if err != nil {
		t.Fatalf("ProbeImmediateTx: %v", err)
	}
	if tempStore != 2 {
		t.Errorf("probe handle temp_store = %d, want 2 (MEMORY)", tempStore)
	}
}

// indexColumns returns a named index's columns in index order.
func indexColumns(t *testing.T, db *Store, name string) []string {
	t.Helper()
	rows, err := db.Query("SELECT name FROM pragma_index_info('" + name + "') ORDER BY seqno")
	if err != nil {
		t.Fatalf("pragma_index_info(%s): %v", name, err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatalf("scan index column: %v", err)
		}
		cols = append(cols, c)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("index info ended early: %v", err)
	}
	return cols
}

func indexExists(t *testing.T, db *Store, name string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?`, name).Scan(&n); err != nil {
		t.Fatalf("index exists check: %v", err)
	}
	return n == 1
}

// TestProbesIndexCoveringFresh pins the fresh-DB shape after migration 14:
// the probes read path (warmStats Phase 1/2, recentFromDB, /history)
// selects (sk, ts_ms, rtt_ms, manual), so the index must COVER that list —
// the TEXT-era (sensor_id, ts) indexes forced both a column decode and a
// random table B-tree lookup per row. The old index names must be gone
// (two equivalent indexes double every probe INSERT), and the planner must
// serve the warm-stats query from the covering index.
func TestProbesIndexCoveringFresh(t *testing.T) {
	db := openTestStore(t)

	want := []string{"sk", "ts_ms", "rtt_ms", "manual"}
	got := indexColumns(t, db, "idx_probes_cov")
	if len(got) != len(want) {
		t.Fatalf("idx_probes_cov columns = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("idx_probes_cov column %d = %q, want %q (the SELECT list must be the index prefix, in order)", i, got[i], want[i])
		}
	}
	for _, dead := range []string{"idx_probes_sensor_ts", "idx_probes_sensor_ts_cov"} {
		if indexExists(t, db, dead) {
			t.Errorf("TEXT-era index %s is still present — it duplicates the covering index and doubles every probe INSERT", dead)
		}
	}

	// Seed rows so the planner has stats to choose the index (an empty
	// table makes it prefer the trivial empty scan). The sensor row must
	// exist first: the probes FK (foreign_keys=1 on every DSN) rejects
	// orphan probe rows. sk is NULL here — the autogen trigger assigns it.
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, state, status, created_at)
		VALUES ('s1', 's1', '10.0.0.1', 30, 1000, 25, 2, 'active', 'up', ?)`, Now()); err != nil {
		t.Fatalf("seed sensor: %v", err)
	}
	for i := 0; i < 200; i++ {
		if _, err := db.Exec(`INSERT INTO probes (sk, ts_ms, rtt_ms, manual)
			VALUES ((SELECT sk FROM sensors WHERE id = 's1'), ?, ?, 0)`,
			time.Now().UTC().Add(-time.Duration(86400-i)*time.Second).UnixMilli(), 5.0+float64(i%50)); err != nil {
			t.Fatalf("seed probe row: %v", err)
		}
	}
	// EXPLAIN QUERY PLAN is a top-level statement (it cannot be nested in
	// a subquery): run it raw and collect the detail column.
	rows, err := db.Query(`EXPLAIN QUERY PLAN
		SELECT sk, ts_ms, rtt_ms, manual FROM probes
		WHERE sk = (SELECT sk FROM sensors WHERE id = 's1') AND ts_ms >= ? ORDER BY sk, ts_ms`,
		time.Now().UTC().Add(-time.Hour).UnixMilli())
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
	}
	defer rows.Close()
	var detail string
	for rows.Next() {
		var id, parent, notused int
		var d string
		if err := rows.Scan(&id, &parent, &notused, &d); err != nil {
			t.Fatalf("scan EQP row: %v", err)
		}
		detail += d + " | "
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("EQP ended early: %v", err)
	}
	if !strings.Contains(detail, "COVERING INDEX") || !strings.Contains(detail, "idx_probes_cov") {
		t.Errorf("the warm-stats query is not served by the covering index: %q", detail)
	}
}

// The pre-migration-14 version of this file pinned migration 13's replay
// (old index -> covering index on the TEXT layout). That replay is no
// longer reachable on a fresh DB — migration 14 supersedes the layout —
// and the v13->v14 upgrade path is pinned by TestMigration14UpgradesV13ToV14
// in probes_int_schema_test.go.
