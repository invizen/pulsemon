package main

import (
	"context"
	"math"
	"sort"
	"testing"
)

// F19 regression pins: the incremental 24h counters (probeSeries.total24/
// lost24) are maintained in append() anchored at the NEWEST probe's ts, but
// statsFor reads them for a nowUnix that can be HOURS after that newest
// probe — a paused sensor, an hourly sensor between ticks, a process that
// just warmed from the DB. computeSensorStats documents that the counters
// "must count the entries with ts >= nowUnix-86400"; pre-fix, statsFor
// passed the newest-anchored values through, so a sensor paused for 30h
// reported the 24h uptime from 30h ago while graphPoints("24h") (anchored
// at time.Now()) showed a different window entirely. The fix decays the
// counters to nowUnix at read time (local copies, read-only under RLock).
//
// These pins compare statsFor's Uptime24h against the window the contract
// promises: entries with ts >= nowUnix-86400, manual rows excluded.

// decayWorker builds a ProbeWorker whose cache already holds the given
// series, so statsFor reads it exactly like production does.
func decayWorker(t *testing.T, id string, s probeSeries) *ProbeWorker {
	t.Helper()
	return &ProbeWorker{
		sensors:    make(map[string]*ProbeState),
		loops:      make(map[string]context.CancelFunc),
		db:         nil,
		statsCache: map[string]*probeSeries{id: &s},
	}
}

// TestStatsForDecays24hUptimeToNow: a 5s-interval sensor with a full 24h of
// history (17,280 entries spanning exactly [newest-24h, newest-5s] — raw
// 1h tier + 1,380 minute buckets) whose OLDEST 6h are all losses. The
// newest-anchored counters say 75.0% uptime no matter what; the
// now-anchored window says:
//
//   - now = newest (steady state): 75.0% — all 24h in the window
//   - now = newest + 20h: the oldest 4h left the window; only the 100%-up
//     tail remains → 100.0%
//   - now = newest + 30h: EVERY probe is >24h old → no 24h data at all →
//     0 (no uptime), matching an empty graphPoints("24h")
//
// Pre-fix, all three reads returned 75.0% (the stale anchor). The final
// check pins the read-only contract: a decayed read must not mutate the
// series (an in-place "optimization" would corrupt the steady-state read
// that follows — and race with appends under RLock).
func TestStatsForDecays24hUptimeToNow(t *testing.T) {
	const n = 17280              // 24h at 5s
	const lossCutoff = 18 * 3600 // entries older than 18h are losses
	var s probeSeries
	for i := 0; i < n; i++ {
		ts := testNowUnix - int64(n-i)*5
		rtt := float32(10)
		if testNowUnix-ts > lossCutoff {
			rtt = float32(math.NaN())
		}
		s.append(probeEntry{ts: ts, rtt: rtt})
	}
	// Sanity: the newest-anchored counters agree with the loss pattern
	// (4,320 losses in the oldest 6h, all 17,280 inside the newest-anchored
	// 24h window — the boundary is inclusive).
	if s.total24 != n || s.lost24 != 4320 {
		t.Fatalf("fixture counters = %d/%d, want %d/4320", s.total24, s.lost24, n)
	}
	pw := decayWorker(t, "paused", s)

	cases := []struct {
		name string
		now  int64
		want float64
	}{
		{"steady state", testNowUnix, 75.0},
		{"paused 20h", testNowUnix + 20*3600, 100.0},
		{"paused 30h", testNowUnix + 30*3600, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := pw.statsFor("paused", tc.now)
			if st == nil {
				t.Fatal("statsFor: nil, want stats (the series is non-empty)")
			}
			if st.Uptime24h != tc.want {
				t.Fatalf("Uptime24h = %v, want %v (window [now-24h, now], not [newest-24h, newest])", st.Uptime24h, tc.want)
			}
		})
	}

	// Read-only contract: the decayed reads above ran far in the future;
	// the series must still read steady-state exactly as before.
	st := pw.statsFor("paused", testNowUnix)
	if st == nil || st.Uptime24h != 75.0 {
		t.Fatalf("steady-state read after decayed reads: %+v, want Uptime24h 75.0 (decayed reads must not mutate the series)", st)
	}
}

// TestStatsForDecaysSlowSensorDrift: an hourly sensor (60-entry last-60
// tail, no buckets) read 30 minutes after its newest probe. The
// newest-anchored window counts 25 entries (ages 0..24h, inclusive) with
// one loss at exactly age 24h → 96.0%; the now-anchored window
// [now-24h, now] with now = newest+30m excludes that age-24h entry →
// 24 entries, no losses → 100.0%. Pre-fix: 96.0% (stale by one interval).
func TestStatsForDecaysSlowSensorDrift(t *testing.T) {
	var s probeSeries
	for i := 0; i < 60; i++ {
		ts := testNowUnix - int64(59-i)*3600
		rtt := float32(10)
		if 59-i == 24 { // the entry at exactly age 24h: a loss
			rtt = float32(math.NaN())
		}
		s.append(probeEntry{ts: ts, rtt: rtt})
	}
	if s.total24 != 25 || s.lost24 != 1 {
		t.Fatalf("fixture counters = %d/%d, want 25/1", s.total24, s.lost24)
	}
	pw := decayWorker(t, "hourly", s)

	st := pw.statsFor("hourly", testNowUnix+1800)
	if st == nil {
		t.Fatal("statsFor: nil, want stats")
	}
	if st.Uptime24h != 100.0 {
		t.Fatalf("Uptime24h = %v, want 100.0 (the age-24h loss left the now-anchored window 30m later)", st.Uptime24h)
	}
}

// TestStatsForDecaySkipsManualRows: manual (Pulse Now) rows live in the raw
// tier but were never counted, so the decay walk must skip them —
// subtracting one would under-count the window. (Manual rows can only be in
// the series at all while inside the raw retention window — max(1h, last
// 60) — because folds drop them; so the fixture puts them in the newest
// hour and pushes `now` past newest+23h to drag the decay band down over
// them.) A 24h 5s sensor: all up except a 10% loss pattern in the newest
// 30 minutes (36 of 360), plus 54 manual rows in the newest 57 minutes.
// At now = newest + 23.5h the now-anchored window is exactly the newest
// 30 minutes: 360 entries, 36 losses → 90.0%. The 54 manual rows sit in
// the decay band; if the walk subtracted them, the denominator would
// shrink to 306 → 88.24%. (Pre-fix, no decay at all, reads 99.79%.)
func TestStatsForDecaySkipsManualRows(t *testing.T) {
	const n = 17280
	type entry = probeEntry
	es := make([]entry, 0, n+64)
	for i := 0; i < n; i++ {
		ts := testNowUnix - int64(n-i)*5
		rtt := float32(10)
		if i >= n-360 && (i-(n-360))%10 == 7 { // newest 30m: 10% losses
			rtt = float32(math.NaN())
		}
		es = append(es, entry{ts: ts, rtt: rtt})
	}
	// 54 manual rows, ts = newest-1830-j*30 → [newest-3420, newest-1830]:
	// inside the 1h raw retention (they survive in the series) and strictly
	// below the decay cutoff newest-1800 (they sit in the band).
	for j := 0; j < 54; j++ {
		es = append(es, entry{ts: testNowUnix - 1830 - int64(j)*30, rtt: 55, manual: true})
	}
	sort.Slice(es, func(a, b int) bool { return es[a].ts < es[b].ts })

	var s probeSeries
	for _, e := range es {
		s.append(e)
	}
	if s.total24 != n || s.lost24 != 36 {
		t.Fatalf("fixture counters = %d/%d, want %d/36", s.total24, s.lost24, n)
	}
	pw := decayWorker(t, "manual", s)

	st := pw.statsFor("manual", testNowUnix+23*3600+1800)
	if st == nil {
		t.Fatal("statsFor: nil, want stats")
	}
	if st.Uptime24h != 90.0 {
		t.Fatalf("Uptime24h = %v, want 90.0 (manual rows in the decay band must be skipped)", st.Uptime24h)
	}
}
