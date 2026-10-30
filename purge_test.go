package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
	"pulsemon/internal/store"
)

// TestRFC3339NanoStringCompareBoundary pins the "string compare on
// variable-length RFC3339Nano timestamps" review finding, directly. Go's
// RFC3339Nano strips trailing fractional zeros, so timestamps in the same
// second have DIFFERENT lengths ("...SSZ" integer-second vs "...SS.5Z"). The
// lexicographic order then diverges from chronological: because 'Z' (0x5A) >
// '.' (0x2E), an integer-second row sorts AFTER a fractional row in the same
// second. This is the exact behavior purgeOld's `WHERE ts < ?` relies on, so
// we pin it deterministically (no wall-clock dependence).
func TestRFC3339NanoStringCompareBoundary(t *testing.T) {
	// Go's actual output for the two instants:
	intSec := time.Unix(1750000000, 0).UTC().Format(time.RFC3339Nano)
	fracSec := time.Unix(1750000000, 0).Add(500 * time.Millisecond).UTC().Format(time.RFC3339Nano)

	// Confirm the format really is variable-length (the finding's premise).
	if len(intSec) == len(fracSec) {
		t.Fatalf("RFC3339Nano is not variable-length here: int=%q frac=%q", intSec, fracSec)
	}
	// The divergence: integer-second string is LARGER (sorts later) than the
	// fractional string, even though it is chronologically EARLIER.
	if !(intSec > fracSec) {
		t.Fatalf("expected integer-second %q to sort AFTER fractional %q ('Z' > '.')", intSec, fracSec)
	}
	t.Logf("divergence confirmed: %q > %q (integer second sorts after fractional, but is chronologically earlier)", intSec, fracSec)

	// And confirm it in SQLite (the engine purgeOld actually uses): ORDER BY ts
	// puts the integer-second row LAST.
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "sc.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE ts (v TEXT)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, v := range []string{intSec, fracSec} {
		if _, err := db.Exec("INSERT INTO ts VALUES (?)", v); err != nil {
			t.Fatalf("insert %q: %v", v, err)
		}
	}
	r, err := db.Query("SELECT v FROM ts ORDER BY v ASC")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer r.Close()
	var order []string
	for r.Next() {
		var s string
		if err := r.Scan(&s); err != nil {
			t.Fatalf("scan: %v", err)
		}
		order = append(order, s)
	}
	if len(order) != 2 || order[1] != intSec {
		t.Fatalf("SQLite ORDER BY ts = %v, want the integer-second row %q LAST (lexicographic divergence)", order, intSec)
	}
	t.Logf("SQLite lexicographic order: %v (integer-second %q sorts last)", order, intSec)
}

// TestPurgeOldNoEarlyDeletion drives the REAL purgeOld() and locks the safety
// property the finding cares about most: it must NEVER delete a row that is
// inside the retention window, and it must delete rows that are clearly past
// it. Offsets use comfortable margins (6h / 10s / 1h) so the sub-second
// uncertainty in purgeOld's internal time.Now() can't flake the assertions.
func TestPurgeOldNoEarlyDeletion(t *testing.T) {
	db, err := store.NewStore(filepath.Join(t.TempDir(), "purge.db"))
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('p', 'p', '127.0.0.1', 30, 1000, 25, 2, 3, 'active', 'up', ?)`,
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}

	now := time.Now().UTC()
	anchor := now.Add(-24 * time.Hour) // the ~24h boundary
	seed := func(off time.Duration) string {
		ts := anchor.Add(off).Format(time.RFC3339Nano)
		if _, err := db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip) VALUES ('p', ?, 10.0, '127.0.0.1')", ts); err != nil {
			t.Fatalf("insert probe %v: %v", off, err)
		}
		return ts
	}
	far := seed(-6 * time.Hour)        // well past the boundary -> must be DELETED
	justOld := seed(-10 * time.Second) // just past the boundary -> must be DELETED
	young := seed(1 * time.Hour)       // well inside the window -> must be KEPT

	pw := &ProbeWorker{db: db}
	pw.purgeOld(context.Background())

	present := map[string]bool{}
	rows, err := db.Query("SELECT ts FROM probes")
	if err != nil {
		t.Fatalf("query probes: %v", err)
	}
	for rows.Next() {
		var ts string
		if err := rows.Scan(&ts); err != nil {
			t.Fatalf("scan: %v", err)
		}
		present[ts] = true
	}
	rows.Close()

	// No early-deletion: the in-window row survives.
	if !present[young] {
		t.Fatalf("row %q (1h inside the window) was EARLY-DELETED — the finding's feared bug (purgeOld must never delete a young row)", young)
	}
	// Retention works: both past-boundary rows are gone.
	if present[far] {
		t.Fatalf("row %q (6h past the boundary) was NOT purged — retention is broken", far)
	}
	if present[justOld] {
		t.Fatalf("row %q (10s past the boundary) was NOT purged — retention is broken", justOld)
	}
	t.Logf("purgeOld: kept in-window %q, deleted %q and %q — no early-deletion, retention works", young, far, justOld)
}

// TestPurgeOldMultiBatchPerSensor drives the per-sensor, batched purge
// (2026-10-23 external review) through its multi-batch path: one sensor with
// 12,000 past-boundary rows forces three purgeBatchSize iterations
// (5000+5000+2000), and a second all-young sensor exercises the empty
// round-trip. It locks the two properties the rewrite must keep: EVERY
// past-boundary row is deleted (the batch loop terminates correctly) and NO
// in-window row is touched.
func TestPurgeOldMultiBatchPerSensor(t *testing.T) {
	db, err := store.NewStore(filepath.Join(t.TempDir(), "purgemulti.db"))
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	for _, id := range []string{"a", "b"} {
		if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
			VALUES (?, ?, '127.0.0.1', 30, 1000, 25, 2, 3, 'active', 'up', ?)`, id, id, createdAt); err != nil {
			t.Fatalf("insert sensor %s: %v", id, err)
		}
	}

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	st, err := tx.Prepare("INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES (?, ?, 10.0)")
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	now := time.Now().UTC()
	// 'a': 12,000 rows 30h..~26.7h old (all past the 24h boundary) + 50
	// rows 1h old (inside the window).
	oldBase := now.Add(-30 * time.Hour)
	for i := 0; i < 12000; i++ {
		if _, err := st.Exec("a", oldBase.Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert old probe %d: %v", i, err)
		}
	}
	youngBase := now.Add(-time.Hour)
	for i := 0; i < 50; i++ {
		if _, err := st.Exec("a", youngBase.Add(time.Duration(i)*time.Minute).Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert young probe %d: %v", i, err)
		}
	}
	// 'b': 100 rows, all inside the window (empty purge round trip).
	for i := 0; i < 100; i++ {
		if _, err := st.Exec("b", youngBase.Add(time.Duration(i)*time.Minute).Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert b probe %d: %v", i, err)
		}
	}
	st.Close()
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	pw := &ProbeWorker{db: db}
	pw.purgeOld(context.Background())

	var nA, nB int
	if err := db.QueryRow("SELECT COUNT(*) FROM probes WHERE sensor_id = 'a'").Scan(&nA); err != nil {
		t.Fatalf("count a: %v", err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM probes WHERE sensor_id = 'b'").Scan(&nB); err != nil {
		t.Fatalf("count b: %v", err)
	}
	if nA != 50 {
		t.Fatalf("sensor 'a': %d rows left, want exactly the 50 in-window ones (12,000 past-boundary rows must all be purged across multiple batches)", nA)
	}
	if nB != 100 {
		t.Fatalf("sensor 'b': %d rows left, want 100 (an all-young sensor must be untouched)", nB)
	}
	// And every survivor of 'a' is a young row (no early-deletion at scale).
	var oldest string
	if err := db.QueryRow("SELECT MIN(ts) FROM probes WHERE sensor_id = 'a'").Scan(&oldest); err != nil {
		t.Fatalf("min ts: %v", err)
	}
	if !strings.HasPrefix(oldest, youngBase.Format("2006-01-02T15:04")) {
		t.Fatalf("sensor 'a' oldest survivor %q is not an in-window row", oldest)
	}
	t.Logf("purgeOld multi-batch: 'a' 12,050 -> 50, 'b' 100 -> 100")
}
