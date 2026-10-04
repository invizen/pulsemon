package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// TestGraphTimeWindowRegression locks the epoch-based window fix for the
// inspector's 1h/24h graphs. Before the fix the filter was
// `ts >= datetime('now', ?)` — a STRING comparison of the stored RFC3339
// timestamp ('2026-10-04T20:47:28.5Z') against datetime's space-separated
// output ('2026-10-04 18:47:28'). For probes on the same calendar day the
// comparison reaches position 10 where 'T' (0x54) > ' ' (0x20), so EVERY
// same-day probe sorts after the cutoff — the "1h" graph silently returned
// the entire same-day history, ignoring the hour entirely.
//
// The test inserts probes at known offsets and asserts the API totals equal
// the count computed with real epoch arithmetic in Go (deterministic, no
// magic constants). A correct implementation always matches; the broken
// string filter over-counts the 1h window whenever the out-of-window probe
// shares the same calendar day as now (most of the day).
func TestGraphTimeWindowRegression(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "graph.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	id := "graph-sensor"
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES (?, ?, '127.0.0.1', 15, 1000, 25, 4, 3, 'active', 'up', ?)`,
		id, id, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}

	// Two probes at distinct ages, both comfortably within 24h.
	offsets := []time.Duration{
		20 * time.Minute,  // inside the 1h window
		100 * time.Minute, // outside the 1h window, inside 24h
	}
	now := time.Now().UTC()
	within1h, within24h := 0, 0
	for i, off := range offsets {
		ts := now.Add(-off)
		if now.Sub(ts) <= time.Hour {
			within1h++
		}
		if now.Sub(ts) <= 24*time.Hour {
			within24h++
		}
		if _, err := db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip) VALUES (?, ?, ?, '127.0.0.1')",
			id, ts.Format(time.RFC3339Nano), float64(10+i)); err != nil {
			t.Fatalf("insert probe: %v", err)
		}
	}
	if within1h != 1 || within24h != 2 {
		t.Fatalf("test setup: expected within1h=1 within24h=2, got %d/%d", within1h, within24h)
	}

	srv := NewServer(db, NewProbeWorker(db))
	mux := srv.Mux()

	graphTotal := func(rng string) (int, float64) {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/sensors/"+id+"/graph?range="+rng, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("graph %s: status %d, body %s", rng, w.Code, w.Body.String())
		}
		var g map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &g); err != nil {
			t.Fatalf("graph %s parse: %v", rng, err)
		}
		total, _ := toInt(g["total"])
		uptime, _ := g["uptime_pct"].(float64)
		return total, uptime
	}

	total1h, up1h := graphTotal("1h")
	if total1h != within1h {
		t.Errorf("graph 1h total = %d, want %d (broken string-comparison filter over-counts same-day rows)", total1h, within1h)
	}
	if up1h != 100 {
		t.Errorf("graph 1h uptime = %v, want 100 (no losses)", up1h)
	}

	total24, _ := graphTotal("24h")
	if total24 != within24h {
		t.Errorf("graph 24h total = %d, want %d (both probes are within 24h — guards against over-filtering)", total24, within24h)
	}
}

func toInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	}
	return 0, false
}
