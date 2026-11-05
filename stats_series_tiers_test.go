package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"pulsemon/internal/store"
)

// TestSeriesMemoryBounded locks the finding-#8 memory bound: a fast-interval
// sensor's series holds max(1h, last-60) RAW entries plus per-minute buckets,
// NOT a full 24h of raw probes (17,280 entries @ 5s ≈ 276 KB, up to ~2× with
// slice slack). The raw tier must cap at the 1h window and the older 23h must
// fold into ≤1440 minute buckets, with every entry accounted for in exactly
// one tier (no loss, no double-count).
func TestSeriesMemoryBounded(t *testing.T) {
	var s probeSeries
	const n = 17280 // 24h @ 5s
	for i := 0; i < n; i++ {
		s.append(probeEntry{ts: testNowUnix - int64(n-1-i)*5, rtt: float32(10 + i%40)})
	}
	// Raw tier: bounded at the 1h window (721 entries @ 5s, the boundary
	// second is inclusive), not the full 24h.
	if got := s.len(); got > 721 {
		t.Errorf("raw len = %d, want <= 721 (1h @ 5s, inclusive); the raw tier must not hold a full 24h of probes (finding #8)", got)
	}
	// The older 23h folds into per-minute buckets (≤ 1440 for a 24h window).
	if got := len(s.buckets) - s.bucketStart; got > 1440 {
		t.Errorf("live buckets = %d, want <= 1440 (24h of minutes)", got)
	}
	// All 17,280 entries are within 24h, so the counters cover them all.
	if s.total24 != n {
		t.Errorf("total24 = %d, want %d (a full 24h of 5s probes is all within the window)", s.total24, n)
	}
	// Every entry is in exactly one tier: raw (within 24h) + bucket totals.
	rawCount := 0
	for i := s.raw24Start; i < len(s.raw); i++ {
		rawCount++
	}
	bucketCount := 0
	for i := s.bucketStart; i < len(s.buckets); i++ {
		bucketCount += int(s.buckets[i].total)
	}
	if rawCount+bucketCount != n {
		t.Errorf("raw(%d) + buckets(%d) = %d, want %d (every entry in exactly one tier)", rawCount, bucketCount, rawCount+bucketCount, n)
	}
}

// TestGraph24hFromMemoryMatchesSQL locks the finding-#8 graph path: the
// in-memory 24h graph (minute buckets folded into 15-min buckets, plus the raw
// hour) must reproduce the SQL aggregate bucket-for-bucket — the same totals,
// the same per-bucket total/lost/avg/max — so the per-request SQL aggregate can
// be retired without changing what the inspector draws.
func TestGraph24hFromMemoryMatchesSQL(t *testing.T) {
	db := newTestDB(t)
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('g','g','127.0.0.1','icmp',5,1000,25,4,3,'active','up',?)`, store.FormatTS(time.Now())); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	const n = 16560 // 23h @ 5s — the 24h window's start sits an hour inside
	// the data, so wall-clock drift between insert / warm / request can't
	// exclude the oldest bucket (which would desync the in-memory and SQL
	// totals at the boundary).
	for i := 0; i < n; i++ {
		ts := now.Add(-time.Duration(n-1-i) * 5 * time.Second)
		var val interface{}
		if i%40 == 0 {
			val = nil // ~2.5% losses
		} else {
			val = 10 + float64(i%40)
		}
		if _, err := db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES (?, ?, ?)", "g", store.FormatTS(ts), val); err != nil {
			t.Fatal(err)
		}
	}
	pw := NewProbeWorker(db)
	pw.warmStats(context.Background())
	srv := NewServer(db, pw)
	w := httptest.NewRecorder()
	srv.Mux().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/sensors/g/graph?range=24h", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("graph 24h: status %d, body %s", w.Code, w.Body.String())
	}
	var resp struct {
		Total  int          `json:"total"`
		Points []GraphPoint `json:"points"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("graph 24h parse: %v", err)
	}

	// SQL reference: the 15-min aggregate the old path returned.
	rows, err := db.Query(`SELECT (strftime('%s', ts) / 900) * 900 AS bucket, COUNT(*),
		COALESCE(SUM(rtt_ms IS NULL), 0), AVG(rtt_ms), MAX(rtt_ms)
		FROM probes WHERE sensor_id = 'g' AND manual = 0
			AND CAST(strftime('%s', ts) AS INTEGER) >= CAST(strftime('%s', datetime('now', '-24 hours')) AS INTEGER)
		GROUP BY bucket ORDER BY bucket`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type ref struct {
		total, lost int
		avg, max    *float64
	}
	refs := map[int64]ref{}
	refTotal := 0
	for rows.Next() {
		var b int64
		var total, lost int
		var avg, max *float64
		if err := rows.Scan(&b, &total, &lost, &avg, &max); err != nil {
			t.Fatal(err)
		}
		refs[b] = ref{total, lost, avg, max}
		refTotal += total
	}
	if resp.Total != refTotal {
		t.Errorf("in-memory total = %d, want %d (SQL) — the fold must lose no probes", resp.Total, refTotal)
	}
	if len(resp.Points) != len(refs) {
		t.Errorf("in-memory buckets = %d, want %d (SQL)", len(resp.Points), len(refs))
	}
	for _, p := range resp.Points {
		r, ok := refs[p.T]
		if !ok {
			t.Errorf("in-memory bucket %d not in SQL reference", p.T)
			continue
		}
		if p.Total != r.total || p.Lost != r.lost {
			t.Errorf("bucket %d: total/lost = %d/%d, want %d/%d", p.T, p.Total, p.Lost, r.total, r.lost)
		}
		if r.avg != nil && p.Avg != nil && absF(*p.Avg-*r.avg) > 0.01 {
			t.Errorf("bucket %d: avg = %v, want %v", p.T, *p.Avg, *r.avg)
		}
		if r.max != nil && p.Max != nil && absF(*p.Max-*r.max) > 0.01 {
			t.Errorf("bucket %d: max = %v, want %v", p.T, *p.Max, *r.max)
		}
	}
}
