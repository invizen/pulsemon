package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestWarmStatsUNIONDedupAndOrder locks the warmStats fetch semantics the
// "use UNION ALL" review finding misdiagnosed, and proves its proposed fix is
// a regression. Ground truth (verified on Go 1.26 / modernc sqlite):
//
//   - The trailing "ORDER BY sensor_id, ts" sorts the WHOLE UNION result, so
//     each sensor's rows arrive ts-ascending (oldest first) — the order
//     probeSeries.append() relies on. "UNION reorders rows" is false.
//   - The two UNION branches OVERLAP BY DESIGN: branch A (last 60 probes per
//     sensor) and branch B (all probes in the 24h window) both contain every
//     probe within the last 24h. The deduping UNION collapses that overlap, so
//     each probe lands once. probeSeries has NO internal dedup (probe.go:80-102
//     just appends + evicts from the front), so switching to UNION ALL — the
//     review's "fix" — would feed a duplicate copy of the overlap into every
//     series, corrupting loss%, the 60-probe window, and the sparkline. The
//     UNION is load-bearing, not a bug.
//
// Seed: one sensor with probes split across the 24h boundary, ANCHORED TO THE
// WALL CLOCK (not testNowUnix) so the REAL warmStats() — which cuts its 24h
// window at time.Now() — actually sees both branches overlap:
//   - 30 recent probes  (within the last 24h)  -> in BOTH branches
//   - 40 old probes     (older than 24h)       -> last-60 branch only
//
// The real warmStats() then loads:
//   - branch A (last 60 per sensor) = 30 recent + 30 newest-old = 60 rows
//   - branch B (all in 24h)         = 30 recent
//   - the deduped UNION             = 60 unique (branch B's 30 are a subset)
//
// probeSeries has NO internal dedup, so if warmStats used UNION ALL the 30
// recent probes would each land twice -> 90 rows with 30 duplicate timestamps.
// Part (1) drives the REAL warmStats() and asserts the series is deduped +
// ascending (catches a production UNION->UNION ALL edit). Part (2) runs the
// EXACT production query text as UNION vs UNION ALL to show the 0-dup vs 60-dup
// difference directly.
func TestWarmStatsUNIONDedupAndOrder(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "warmstats-union.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	const id = "rich"
	const nRecent, nOld = 30, 40
	const keep = 60 // warmStats keeps the last 60 probes per sensor
	now := time.Now().UTC()
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES (?, ?, '127.0.0.1', 30, 1000, 25, 4, 3, 'active', 'up', ?)`,
		id, id, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}
	// 30 recent probes: 30s apart, newest ~now-30s (all within the last 24h).
	// A few deterministic losses (nil rtt_ms) to exercise the NULL path.
	for i := 0; i < nRecent; i++ {
		ts := now.Add(-time.Duration(nRecent-1-i) * 30 * time.Second).Format(time.RFC3339)
		var val interface{}
		if i%10 != 7 {
			val = 10 + float64(i%5)
		}
		if _, err := db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip) VALUES (?, ?, ?, '127.0.0.1')",
			id, ts, val); err != nil {
			t.Fatalf("insert recent probe %d: %v", i, err)
		}
	}
	// 40 old probes: 24h+ apart, oldest ~now-40*25h, newest ~now-25h (all
	// older than the 24h cutoff).
	for i := 0; i < nOld; i++ {
		ts := now.Add(-time.Duration(25*60+(nOld-1-i)*1440) * time.Minute).Format(time.RFC3339)
		if _, err := db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip) VALUES (?, ?, ?, '127.0.0.1')",
			id, ts, 20.0); err != nil {
			t.Fatalf("insert old probe %d: %v", i, err)
		}
	}

	// (1) The REAL warmStats(): the series must be deduplicated + ts-ascending.
	// warmStats only touches db + statsCache (+ statsMu), so a minimal worker
	// suffices. With UNION the 30 recent probes (in both branches) land once;
	// with UNION ALL they'd land twice -> duplicate ts in the series.
	pw := &ProbeWorker{db: db, statsCache: make(map[string]*probeSeries)}
	pw.warmStats()
	series, ok := pw.statsCache[id]
	if !ok {
		t.Fatalf("warmStats did not load sensor %q into statsCache", id)
	}
	snap := series.snapshot()
	if len(snap) != keep {
		t.Fatalf("warmStats series len = %d, want %d (last-60 window); a UNION->UNION ALL edit would grow this past %d with duplicates",
			len(snap), keep, keep)
	}
	seen := make(map[int64]bool, len(snap))
	for i, e := range snap {
		if seen[e.ts] {
			t.Fatalf("warmStats series has duplicate ts %d at index %d — the two UNION branches overlapped and were not deduped (UNION ALL regression)", e.ts, i)
		}
		seen[e.ts] = true
		if i > 0 && e.ts < snap[i-1].ts {
			t.Fatalf("warmStats series not ts-ascending at index %d (%d < %d) — ORDER BY over the UNION is not sorting",
				i, e.ts, snap[i-1].ts)
		}
	}

	// (2) The EXACT production query (verbatim from probe.go:411-419), run as
	//     UNION (current) vs UNION ALL (the review's "fix"): the overlap between
	//     the two branches dedups to 0 under UNION and to 60 dups under UNION
	//     ALL. This is the evidence that the "fix" injects duplicates.
	ids := []string{id}
	ph := make([]string, len(ids))
	for i := range ph {
		ph[i] = "?"
	}
	joined := strings.Join(ph, ",")
	// Anchor the 24h cutoff to the same wall clock so branch B is populated.
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	args := []any{id, id, cutoff.Format(time.RFC3339)}
	run := func(union string) (rows, dups int, ascending bool) {
		ascending = true
		q := `SELECT sensor_id, ts, rtt_ms FROM (
			SELECT sensor_id, ts, rtt_ms,
			       ROW_NUMBER() OVER (PARTITION BY sensor_id ORDER BY ts DESC) AS rn
			FROM probes WHERE sensor_id IN (` + joined + `)
		) WHERE rn <= 60
		` + union + `
		SELECT sensor_id, ts, rtt_ms FROM probes
		WHERE sensor_id IN (` + joined + `) AND ts >= ?
		ORDER BY sensor_id, ts`
		r, err := db.Query(q, args...)
		if err != nil {
			t.Fatalf("query (%s): %v", union, err)
		}
		defer r.Close()
		saw := make(map[int64]bool)
		var prev int64
		first := true
		for r.Next() {
			var sid string
			var ts time.Time
			var rtt *float64
			if err := r.Scan(&sid, &ts, &rtt); err != nil {
				t.Fatalf("scan: %v", err)
			}
			u := ts.UTC().Unix()
			rows++
			if saw[u] {
				dups++
			}
			saw[u] = true
			if !first && u < prev {
				ascending = false
			}
			prev, first = u, false
		}
		return
	}

	uRows, uDups, uAsc := run("UNION")
	if uRows != keep || uDups != 0 || !uAsc {
		t.Fatalf("UNION (current): rows=%d dups=%d ascending=%v, want rows=%d dups=0 ascending=true",
			uRows, uDups, uAsc, keep)
	}
	aRows, aDups, aAsc := run("UNION ALL")
	// UNION ALL = branch A (60) + branch B (30 recent) = 90 rows, of which the
	// 30 recent appear twice -> 30 dups.
	if aRows != keep+nRecent || aDups != nRecent {
		t.Fatalf("UNION ALL: rows=%d dups=%d, want rows=%d dups=%d — this is the duplication the review's 'fix' would introduce",
			aRows, aDups, keep+nRecent, nRecent)
	}
	if !aAsc {
		// UNION ALL is still ascending (ORDER BY applies to the whole result);
		// the regression is the DUPLICATES, not the order. Assert it so a future
		// change that also breaks ordering is caught here.
		t.Fatalf("UNION ALL unexpectedly not ascending — the finding claimed ordering was the problem; it is not, duplicates are")
	}
	t.Logf("current UNION: rows=%d dups=0 ascending=true | proposed UNION ALL: rows=%d dups=%d ascending=true (dedup is load-bearing)",
		uRows, aRows, aDups)
}

// TestWarmStatsCursorDrains pins the "ids.Close() can fail or leak" claim:
// warmStats opens the sensor-id cursor once and a probe-history cursor per
// chunk, each with a TOP-LEVEL defer (probe.go:366, 424) — not a bare close
// below a loop. After a multi-chunk run the pool fully drains and settles.
func TestWarmStatsCursorDrains(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "warmstats-drain.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	// 600 active sensors -> 600 id rows, so fetchChunk runs in 2 chunks
	// (inQueryChunk=500), exercising the per-chunk cursor-close path.
	for i := 0; i < 600; i++ {
		id := fmt.Sprintf("s%03d", i)
		if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
			VALUES (?, ?, '127.0.0.1', 30, 1000, 25, 4, 3, 'active', 'up', ?)`,
			id, id, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert sensor %d: %v", i, err)
		}
		for j := 0; j < 3; j++ {
			ts := time.Unix(testNowUnix-int64(j)*30, 0).UTC().Format(time.RFC3339)
			_, _ = db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip) VALUES (?, ?, ?, '127.0.0.1')",
				id, ts, 10.0)
		}
	}

	base := db.Stats().OpenConnections
	pw := &ProbeWorker{db: db, statsCache: make(map[string]*probeSeries)}
	pw.warmStats()
	if len(pw.statsCache) != 600 {
		t.Fatalf("statsCache has %d sensors, want 600 (all active)", len(pw.statsCache))
	}
	// A query after the run must complete promptly (no leaked connection
	// holding the pool hostage).
	done := make(chan error, 1)
	go func() { done <- db.QueryRow("SELECT COUNT(*) FROM sensors").Err() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("post-warmStats query: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("pool did not drain after warmStats (cursor leak); base=%d", base)
	}
	// Steady state: connections settle back near baseline.
	time.Sleep(200 * time.Millisecond)
	if settled := db.Stats().OpenConnections; settled > 5 {
		t.Errorf("pool did not settle: %d open after warmStats (base=%d)", settled, base)
	}
}
