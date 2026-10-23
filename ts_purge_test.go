package main

import (
	"math/rand"
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
		strs[i] = fmtTS(tm)
		if len(strs[i]) != len(fmtTS(base)) {
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
		if fmtTS(sortedT[i]) != sortedS[i] {
			t.Fatalf("string order != time order at %d: %s vs %s", i, fmtTS(sortedT[i]), sortedS[i])
		}
	}
	if s := tsNow(); len(s) != len(fmtTS(base)) {
		t.Fatalf("tsNow width %d", len(s))
	}
}

func TestFix_TS_PurgeDeletesOnlyOldRowsIncludingLegacyFormat(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "a", "a", "active")
	pw := NewProbeWorker(db)
	old := time.Now().Add(-25 * time.Hour)
	young := time.Now().Add(-23 * time.Hour)
	fcProbe(t, db, "a", old, 1.0)
	fcProbe(t, db, "a", young, 1.0)
	// legacy variable-width rows written by older versions
	db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES ('a', ?, 1)`, old.UTC().Format(time.RFC3339Nano))
	db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES ('a', ?, 1)`, young.UTC().Format(time.RFC3339Nano))
	pw.purgeOld()
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM probes`).Scan(&n)
	if n != 2 {
		t.Fatalf("%d rows left, want exactly the 2 young ones", n)
	}
}
