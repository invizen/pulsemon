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

func TestFix_TS_PurgeDeletesOnlyOldRowsIncludingLegacyFormat(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "a", "a", "active")
	pw := NewProbeWorker(db)
	old := time.Now().Add(-25 * time.Hour)
	young := time.Now().Add(-23 * time.Hour)
	// Seed BEYOND the per-sensor 60-row tail exemption (finding #6): 65 old
	// + 2 young = 67 rows, so the sweep deletes exactly the 7 oldest. Hour
	// spacing keeps every old row unambiguously past the 24h cutoff. The
	// two legacy variable-width OLD rows are seeded as the oldest, so the
	// deleted set provably includes them (the point of this test: legacy
	// rows are purged by string comparison despite the variable width).
	for i := 0; i < 63; i++ {
		fcProbe(t, db, "a", old.Add(-time.Duration(i)*time.Hour), 1.0)
	}
	legacyOld1 := old.Add(-64 * time.Hour).UTC().Format(time.RFC3339)
	legacyOld2 := old.Add(-65 * time.Hour).UTC().Format(time.RFC3339Nano)
	db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES ('a', ?, 1)`, legacyOld1)
	db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES ('a', ?, 1)`, legacyOld2)
	fcProbe(t, db, "a", young, 1.0)
	// legacy variable-width young row (integer-second form, like pre-
	// FormatTS writers: trailing zeros trimmed, so it cannot collide with
	// the nanosecond-precision fcProbe rows in the ts IN/= lookups)
	legacyYoung := young.Truncate(time.Second).UTC().Format(time.RFC3339Nano)
	db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES ('a', ?, 1)`, legacyYoung)

	pw.purgeOld(context.Background())

	cutoff := store.FormatTS(time.Now().Add(-24 * time.Hour))
	var n, oldLeft, legacyOldLeft, legacyYoungLeft int
	db.QueryRow(`SELECT COUNT(*) FROM probes`).Scan(&n)
	db.QueryRow(`SELECT COUNT(*) FROM probes WHERE ts < ?`, cutoff).Scan(&oldLeft)
	db.QueryRow(`SELECT COUNT(*) FROM probes WHERE ts IN (?, ?)`, legacyOld1, legacyOld2).Scan(&legacyOldLeft)
	db.QueryRow(`SELECT COUNT(*) FROM probes WHERE ts = ?`, legacyYoung).Scan(&legacyYoungLeft)
	if n != 60 {
		t.Fatalf("%d rows left, want 60 (24h window + 60-row tail exemption)", n)
	}
	if oldLeft != 58 {
		t.Errorf("%d old rows left, want 58 (the 58 newest old rows are inside the tail)", oldLeft)
	}
	if legacyOldLeft != 0 {
		t.Errorf("%d legacy-format OLD rows left, want 0 (purge must delete variable-width legacy rows)", legacyOldLeft)
	}
	if legacyYoungLeft != 1 {
		t.Errorf("legacy-format young row missing (want 1, got %d)", legacyYoungLeft)
	}
}
