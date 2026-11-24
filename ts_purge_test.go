package main

import (
	"context"
	"math/rand"
	"pulsemon/internal/store"
	"sort"
	"testing"
	"time"
)

// ---------------------------------------------------------------- timestamps
//
// TestFix_TS_FixedWidthLexicographicEqualsChronological pins the TSLayout
// string format that the EVENTS table (and every API ts string) still uses:
// fixed width, so lexicographic order == chronological order. The probes
// table moved to INTEGER epoch-ms in migration 14, but the events table
// stays TEXT by decision (docs/DECISIONS.md, probe-rows-int-schema), so
// this format pin remains live for the events write path.

func TestFix_TS_FixedWidthLexicographicEqualsChronological(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	base := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	var times []time.Time
	for i := 0; i < 2000; i++ {
		ns := rng.Int63n(int64(3 * time.Second))
		if i%5 == 0 {
			ns = (ns / int64(time.Second)) * int64(time.Second) // exact integer seconds
		}
		if i%7 == 0 {
			ns = (ns / int64(time.Millisecond)) * int64(time.Millisecond) // trailing zeros
		}
		times = append(times, base.Add(time.Duration(ns)))
	}
	strs := make([]string, len(times))
	for i, tm := range times {
		strs[i] = store.FormatTS(tm)
		if len(strs[i]) != len(store.FormatTS(base)) {
			t.Fatalf("variable width: %q", strs[i])
		}
		if back, err := time.Parse(time.RFC3339Nano, strs[i]); err != nil || !back.Equal(tm) {
			t.Fatalf("round trip %q: %v %v", strs[i], back, err)
		}
	}
	sortedT := append([]time.Time(nil), times...)
	sort.Slice(sortedT, func(i, j int) bool { return sortedT[i].Before(sortedT[j]) })
	sortedS := append([]string(nil), strs...)
	sort.Strings(sortedS)
	for i := range sortedT {
		if store.FormatTS(sortedT[i]) != sortedS[i] {
			t.Fatalf("string order != time order at %d: %s vs %s", i, store.FormatTS(sortedT[i]), sortedS[i])
		}
	}
	if s := store.Now(); len(s) != len(store.FormatTS(base)) {
		t.Fatalf("store.Now width %d", len(s))
	}
}

// TestPurgeOldDeletesOnlyRowsPast24hCutoff pins purgeOld's cutoff and
// tail-exemption arithmetic on the INTEGER layout (migration 14). The
// pre-migration version of this test seeded variable-width legacy STRING
// rows to prove the purge survived string comparison; with ts_ms that
// hazard class is gone, so the seed is plain epoch-ms rows.
func TestPurgeOldDeletesOnlyRowsPast24hCutoff(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "a", "a", "active")
	pw := NewProbeWorker(db)
	old := time.Now().Add(-25 * time.Hour)
	young := time.Now().Add(-23 * time.Hour)
	// Seed BEYOND the per-sensor 60-row tail exemption (finding #6): 65 old
	// + 2 young = 67 rows, so the sweep deletes exactly the 7 oldest. Hour
	// spacing keeps every old row unambiguously past the 24h cutoff.
	for i := 0; i < 63; i++ {
		fcProbe(t, db, "a", old.Add(-time.Duration(i)*time.Hour), 1.0)
	}
	fcProbe(t, db, "a", old.Add(-64*time.Hour), 1.0)
	fcProbe(t, db, "a", old.Add(-65*time.Hour), 1.0)
	fcProbe(t, db, "a", young, 1.0)
	// 30m inside the window: a row seeded at EXACTLY 24h is ambiguous — by
	// the time purgeOld computes its cutoff (ms later) it is past it, and
	// purging it is correct behavior, not a regression.
	fcProbe(t, db, "a", young.Add(-30*time.Minute), 1.0)

	pw.purgeOld(context.Background())

	cutoff := time.Now().Add(-24 * time.Hour).UnixMilli()
	var n, oldLeft int
	db.QueryRow(`SELECT COUNT(*) FROM probes`).Scan(&n)
	db.QueryRow(`SELECT COUNT(*) FROM probes WHERE ts_ms < ?`, cutoff).Scan(&oldLeft)
	if n != 60 {
		t.Fatalf("%d rows left, want 60 (24h window + 60-row tail exemption)", n)
	}
	if oldLeft != 58 {
		t.Errorf("%d old rows left, want 58 (the 58 newest old rows are inside the tail)", oldLeft)
	}
}
