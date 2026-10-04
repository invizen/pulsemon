package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// testNowUnix is a fixed reference time (epoch seconds) so the differential
// test compares the DB aggregation and the in-memory path against the SAME
// "now" instead of racing the wall clock. Divisible by 60 keeps the sparkline
// bucket math on clean minute boundaries.
const testNowUnix int64 = 1750000380

// closeEnough is the float tolerance for comparing an in-memory aggregate to
// its SQL counterpart (they should be bit-identical, but float summation order
// can differ by a rounding ulp, so give it a hair of slack).
func closeEnough(a, b float64) bool { return absF(a-b) < 1e-6 }

func absF(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

// seedStatsSensor inserts a sensor with a rich, deterministic probe history:
// a 120-probe "recent" block spanning the last 1h (30s apart, known RTT
// pattern, 12 losses) plus a 10-probe "old" block ~12h back (all successful).
// This exercises every stats field: the 60-probe window (last 60 recent), the
// 1h window (all 120 recent), the 24h window (all 130), and the sparkline.
func seedStatsSensor(t *testing.T, db *DB, id string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES (?, ?, '127.0.0.1', 30, 1000, 25, 4, 3, 'active', 'up', ?)`,
		id, id, now); err != nil {
		t.Fatalf("insert sensor %s: %v", id, err)
	}
	// Recent block: 120 probes, newest at testNowUnix, 30s apart.
	for i := 0; i < 120; i++ {
		ts := time.Unix(testNowUnix-int64(119-i)*30, 0).UTC().Format(time.RFC3339)
		var val interface{}
		if i%10 != 7 { // 12 losses at i=7,17,...,117
			val = 10 + float64(i%5) // RTT 10..14ms, deterministic
		}
		if _, err := db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip) VALUES (?, ?, ?, '127.0.0.1')", id, ts, val); err != nil {
			t.Fatalf("insert recent probe %s#%d: %v", id, i, err)
		}
	}
	// Old block: 10 probes ~12h back, 10min apart, all successful RTT 100.
	for i := 0; i < 10; i++ {
		ts := time.Unix(testNowUnix-43200-int64(i)*600, 0).UTC().Format(time.RFC3339)
		if _, err := db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip) VALUES (?, ?, ?, '127.0.0.1')", id, ts, 100.0); err != nil {
			t.Fatalf("insert old probe %s#%d: %v", id, i, err)
		}
	}
}

// readSeries mirrors the in-memory warm-up: the sensor's probe history as an
// oldest-first []probeEntry, loaded from the DB (last 60 per sensor UNION the
// 24h window — the exact set the live series holds).
func readSeries(t *testing.T, db *DB, id string) []probeEntry {
	t.Helper()
	rows, err := db.Query(`SELECT sensor_id, ts, rtt_ms FROM (
		SELECT sensor_id, ts, rtt_ms,
		       ROW_NUMBER() OVER (PARTITION BY sensor_id ORDER BY ts DESC) AS rn
		FROM probes WHERE sensor_id IN (?)
	) WHERE rn <= 60
	UNION
	SELECT sensor_id, ts, rtt_ms FROM probes WHERE sensor_id IN (?) AND ts >= ?
	ORDER BY sensor_id, ts`,
		id, id, time.Unix(testNowUnix-retentionSeconds, 0).UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("readSeries query: %v", err)
	}
	defer rows.Close()
	var out []probeEntry
	for rows.Next() {
		var sid string
		var ts time.Time
		var rtt *float64
		if err := rows.Scan(&sid, &ts, &rtt); err != nil {
			t.Fatalf("readSeries scan: %v", err)
		}
		out = append(out, probeEntry{ts: ts.UTC().Unix(), rtt: rtt})
	}
	return out
}

// sqlStats is the REFERENCE aggregation: the four pre-v0.1.18 queries
// (60-probe window, 1h loss/avg, 24h uptime, 1h sparkline) run against the DB,
// with the time windows anchored to testNowUnix (epoch-based, the same window
// semantics the in-memory path uses). This is the independent computation the
// in-memory path must reproduce field-for-field.
func sqlStats(t *testing.T, db *DB, id string) *SensorStats {
	t.Helper()
	var st SensorStats

	// (1) 60-probe window: total, lost, recent(30, newest first), rtt stats.
	const q1 = `SELECT rtt_ms, COUNT(*) OVER (), SUM(CASE WHEN rtt_ms IS NULL THEN 1 ELSE 0 END) OVER (),
		ROW_NUMBER() OVER (ORDER BY ts DESC)
		FROM (SELECT rtt_ms, ts FROM probes WHERE sensor_id = ? ORDER BY ts DESC LIMIT 60)`
	var min, max, sum float64
	have := false
	r1, err := db.Query(q1, id)
	if err != nil {
		t.Fatalf("q1: %v", err)
	}
	for r1.Next() {
		var rtt *float64
		var rn int64
		if err := r1.Scan(&rtt, &st.Total, &st.LostCount, &rn); err != nil {
			t.Fatalf("q1 scan: %v", err)
		}
		if rn <= 30 {
			st.Recent = append(st.Recent, rtt)
		}
		if rtt != nil {
			v := *rtt
			if !have {
				min, max, have = v, v, true
			} else {
				if v < min {
					min = v
				}
				if v > max {
					max = v
				}
			}
			sum += v
			if st.RTTLast == nil {
				l := v
				st.RTTLast = &l
			}
		}
	}
	r1.Close()
	if st.Total > 0 {
		st.LossPct = float64(st.LostCount) / float64(st.Total) * 100
	}
	if have {
		mn, mx, avg := min, max, sum/float64(st.Total-st.LostCount)
		st.RTTMin, st.RTTMax, st.RTTAvg = &mn, &mx, &avg
	}

	// (2) Past-hour loss % + avg RTT (epoch cutoff = testNowUnix - 3600).
	var h1, l1 int
	var h1avg *float64
	hcutoff := time.Unix(testNowUnix-3600, 0).UTC().Format(time.RFC3339)
	if err := db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(rtt_ms IS NULL), 0), AVG(rtt_ms)
		FROM probes WHERE sensor_id = ? AND ts >= ?`, id, hcutoff).Scan(&h1, &l1, &h1avg); err != nil {
		t.Fatalf("q2: %v", err)
	}
	if h1 > 0 {
		st.HourLossPct = float64(l1) / float64(h1) * 100
		st.HourRTTAvg = h1avg
	}

	// (3) 24h uptime (epoch cutoff = testNowUnix - 86400).
	var d24, l24 int
	dcutoff := time.Unix(testNowUnix-retentionSeconds, 0).UTC().Format(time.RFC3339)
	if err := db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(rtt_ms IS NULL), 0)
		FROM probes WHERE sensor_id = ? AND ts >= ?`, id, dcutoff).Scan(&d24, &l24); err != nil {
		t.Fatalf("q3: %v", err)
	}
	if d24 > 0 {
		st.Uptime24h = float64(d24-l24) / float64(d24) * 100
	}

	// (4) Past-1-hour sparkline: 60 one-minute buckets, min RTT per bucket.
	nd := -2.0
	st.Hour = make([]*float64, 60)
	for i := range st.Hour {
		st.Hour[i] = &nd
	}
	r4, err := db.Query(`SELECT (strftime('%s', ts) / 60) * 60 AS bucket, MIN(rtt_ms)
		FROM probes WHERE sensor_id = ? AND ts >= ? GROUP BY bucket`, id, hcutoff)
	if err != nil {
		t.Fatalf("q4: %v", err)
	}
	nowMin := testNowUnix / 60 * 60
	for r4.Next() {
		var bucket int64
		var minRTT *float64
		if err := r4.Scan(&bucket, &minRTT); err != nil {
			t.Fatalf("q4 scan: %v", err)
		}
		pos := 59 - int((nowMin-bucket)/60)
		if pos < 0 || pos > 59 {
			continue
		}
		st.Hour[pos] = minRTT
	}
	r4.Close()

	if st.Total == 0 {
		return nil
	}
	return &st
}

// compareStats asserts two SensorStats are field-for-field equal (within the
// float tolerance). The -2 sentinel and nil are distinct in the sparkline and
// are compared as such.
func compareStats(t *testing.T, label string, got, want *SensorStats) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("%s: nil mismatch (got %v, want %v)", label, got != nil, want != nil)
	}
	if got == nil {
		return
	}
	if got.Total != want.Total {
		t.Errorf("%s: Total = %d, want %d", label, got.Total, want.Total)
	}
	if got.LostCount != want.LostCount {
		t.Errorf("%s: LostCount = %d, want %d", label, got.LostCount, want.LostCount)
	}
	if !closeEnough(got.LossPct, want.LossPct) {
		t.Errorf("%s: LossPct = %v, want %v", label, got.LossPct, want.LossPct)
	}
	ptrEq := func(name string, a, b *float64) {
		if (a == nil) != (b == nil) {
			t.Errorf("%s: %s nil mismatch", label, name)
			return
		}
		if a != nil && !closeEnough(*a, *b) {
			t.Errorf("%s: %s = %v, want %v", label, name, *a, *b)
		}
	}
	ptrEq("RTTLast", got.RTTLast, want.RTTLast)
	ptrEq("RTTMin", got.RTTMin, want.RTTMin)
	ptrEq("RTTAvg", got.RTTAvg, want.RTTAvg)
	ptrEq("RTTMax", got.RTTMax, want.RTTMax)
	ptrEq("HourRTTAvg", got.HourRTTAvg, want.HourRTTAvg)
	if !closeEnough(got.HourLossPct, want.HourLossPct) {
		t.Errorf("%s: HourLossPct = %v, want %v", label, got.HourLossPct, want.HourLossPct)
	}
	if !closeEnough(got.Uptime24h, want.Uptime24h) {
		t.Errorf("%s: Uptime24h = %v, want %v", label, got.Uptime24h, want.Uptime24h)
	}
	// Recent: newest-first, first 30.
	if len(got.Recent) != len(want.Recent) {
		t.Errorf("%s: Recent len = %d, want %d", label, len(got.Recent), len(want.Recent))
	}
	for i := range want.Recent {
		if (got.Recent[i] == nil) != (want.Recent[i] == nil) {
			t.Errorf("%s: Recent[%d] nil mismatch", label, i)
			continue
		}
		if got.Recent[i] != nil && !closeEnough(*got.Recent[i], *want.Recent[i]) {
			t.Errorf("%s: Recent[%d] = %v, want %v", label, i, *got.Recent[i], *want.Recent[i])
		}
	}
	// Hour sparkline: 60 buckets; -2 sentinel and nil are distinct.
	if len(got.Hour) != len(want.Hour) {
		t.Fatalf("%s: Hour len = %d, want %d", label, len(got.Hour), len(want.Hour))
	}
	for i := range want.Hour {
		gv, gw := got.Hour[i], want.Hour[i]
		if (gv == nil) != (gw == nil) {
			t.Errorf("%s: Hour[%d] nil mismatch", label, i)
			continue
		}
		if gv == nil {
			continue
		}
		if !closeEnough(*gv, *gw) {
			t.Errorf("%s: Hour[%d] = %v, want %v", label, i, *gv, *gw)
		}
	}
}

// TestComputeSensorStatsMatchesSQL is the differential test at the heart of
// v0.1.18: on identical probe data, the in-memory computeSensorStats must
// reproduce the four-query DB aggregation field-for-field. If the cache ever
// diverges from the DB, this fails.
func TestComputeSensorStatsMatchesSQL(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "stats.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	seedStatsSensor(t, db, "rich")

	// sparse: a young sensor — 5 probes in the last ~90s (mostly no-data
	// sparkline minutes; exercises the -2 sentinel path).
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('sparse', 'sparse', '127.0.0.1', 30, 1000, 25, 4, 3, 'active', 'up', ?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert sparse sensor: %v", err)
	}
	for i := 0; i < 5; i++ {
		ts := time.Unix(testNowUnix-int64(90-15*i), 0).UTC().Format(time.RFC3339)
		var val interface{}
		if i%2 == 0 {
			val = float64(20 + i)
		}
		if _, err := db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip) VALUES (?, ?, ?, '127.0.0.1')", "sparse", ts, val); err != nil {
			t.Fatalf("insert sparse: %v", err)
		}
	}

	// all-lost-hour: 12 lost probes in the last hour, plus 20 successful ones
	// ~10h back. HourRTTAvg must be nil (all-hour lost, not NaN) and 24h
	// uptime must reflect the 20 good probes, not the 1h window.
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('all-lost-hour', 'all-lost-hour', '127.0.0.1', 30, 1000, 25, 4, 3, 'active', 'up', ?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert all-lost sensor: %v", err)
	}
	for i := 0; i < 12; i++ {
		ts := time.Unix(testNowUnix-int64(1800-120*i), 0).UTC().Format(time.RFC3339)
		if _, err := db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip) VALUES (?, ?, NULL, '127.0.0.1')", "all-lost-hour", ts); err != nil {
			t.Fatalf("insert all-lost recent: %v", err)
		}
	}
	for i := 0; i < 20; i++ {
		ts := time.Unix(testNowUnix-36000-int64(i)*180, 0).UTC().Format(time.RFC3339)
		if _, err := db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip) VALUES (?, ?, ?, '127.0.0.1')", "all-lost-hour", ts, 55.0); err != nil {
			t.Fatalf("insert all-lost old: %v", err)
		}
	}

	for _, id := range []string{"rich", "sparse", "all-lost-hour"} {
		t.Run(id, func(t *testing.T) {
			want := sqlStats(t, db, id)
			got := computeSensorStats(readSeries(t, db, id), testNowUnix)
			compareStats(t, id, got, want)
		})
	}
}

// TestGetStatsRoundTrip feeds the cache via recordProbe (the live write path)
// and checks GetStats returns what the DB aggregation says — proving the
// append-then-read path (not just the warm-up read) is correct.
func TestGetStatsRoundTrip(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "rt.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	seedStatsSensor(t, db, "rt")

	pw := &ProbeWorker{
		sensors:    make(map[string]*ProbeState),
		loops:      make(map[string]context.CancelFunc),
		db:         db,
		statsCache: make(map[string]*probeSeries),
	}
	for _, e := range readSeries(t, db, "rt") {
		pw.recordProbe("rt", e)
	}
	// statsFor (not GetStats) so the time windows anchor to the test's fixed
	// testNowUnix, matching the DB reference — GetStats would anchor to the
	// wall clock (2026) while the synthetic data is at testNowUnix (2025).
	got := pw.statsFor("rt", testNowUnix)
	want := sqlStats(t, db, "rt")
	compareStats(t, "roundtrip", got, want)
}

// TestSeriesEviction locks the retention rule: the series holds exactly the
// union of the last 60 probes and the 24h window.
func TestSeriesEviction(t *testing.T) {
	// Fast sensor, 1s apart: 100 entries all within 24h, so the 24h window
	// (100) dominates the last-60 (60) — all 100 kept.
	var fast probeSeries
	for i := 0; i < 100; i++ {
		fast.append(probeEntry{ts: testNowUnix - int64(100-i), rtt: f64(10)})
	}
	if got := fast.len(); got != 100 {
		t.Errorf("fast: len = %d, want 100 (all within 24h)", got)
	}

	// Slow sensor, 1h apart: 61 entries spanning 61h. The last-60 window
	// dominates; the oldest (>24h, beyond the last 60) is evicted -> 60 kept.
	var slow probeSeries
	for i := 0; i < 61; i++ {
		slow.append(probeEntry{ts: testNowUnix - int64(61-1-i)*3600, rtt: f64(10)})
	}
	if got := slow.len(); got != 60 {
		t.Errorf("slow: len = %d, want 60 (last-60 window dominates)", got)
	}
	// The oldest surviving entry is exactly 59h old (the newest 60 probes).
	if got := slow.data[slow.start].ts; got != testNowUnix-int64(59)*3600 {
		t.Errorf("slow: oldest kept ts = %d, want %d", got, testNowUnix-59*3600)
	}
}

// TestClearHistoryInvalidatesCache confirms ResetStatsFor empties one sensor's
// series (the clear-history endpoint relies on this) without touching others.
func TestClearHistoryInvalidatesCache(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "clr.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	seedStatsSensor(t, db, "a")
	seedStatsSensor(t, db, "b")

	pw := &ProbeWorker{
		sensors:    make(map[string]*ProbeState),
		loops:      make(map[string]context.CancelFunc),
		db:         db,
		statsCache: make(map[string]*probeSeries),
	}
	for _, e := range readSeries(t, db, "a") {
		pw.recordProbe("a", e)
	}
	for _, e := range readSeries(t, db, "b") {
		pw.recordProbe("b", e)
	}
	if pw.GetStats("a") == nil || pw.GetStats("b") == nil {
		t.Fatal("both sensors should have stats before clear")
	}
	pw.ResetStatsFor("a")
	if pw.GetStats("a") != nil {
		t.Error("ResetStatsFor(a): stats still present, want nil")
	}
	if pw.GetStats("b") == nil {
		t.Error("ResetStatsFor(a): sensor b's stats were wiped too")
	}
}
