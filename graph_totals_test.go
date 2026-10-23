package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFix_g6_GraphTotalsMatchBuckets(t *testing.T) {
	// Setup DB
	d := newTestDB(t)
	// Go through the real mux so the {id} path value is populated.
	mux := NewServer(d, NewProbeWorker(d)).Mux()

	sensorID := "test-sensor"
	_, err := d.Exec("INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		sensorID, "Test Sensor", "127.0.0.1", "icmp", 60, 1000, 10, 30, 2.0, "up", "up", time.Now())
	if err != nil {
		t.Fatalf("exec: %v", err)
	}

	// Insert probes
	now := time.Now()
	// 10 probes, 2 lost
	for i := 0; i < 10; i++ {
		rtt := 50.0
		isLost := false
		if i%5 == 0 { // i = 0 and 5 -> exactly 2 lost
			rtt = 0
			isLost = true
		}
		// The seekable ts >= bound in handleSensorGraph presumes the
		// single-writer fmtTS format (Z-suffix, db.go tsLayout) — seed with
		// it, not RFC3339Nano, which on a UTC host renders "+00:00" and
		// sorts lexicographically BELOW the bound.
		ts := fmtTS(now.Add(time.Duration(-i) * time.Minute))
		var rttVal interface{}
		if isLost {
			rttVal = nil
		} else {
			rttVal = rtt
		}
		_, err := d.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES (?, ?, ?)", sensorID, ts, rttVal)
		if err != nil {
			t.Fatalf("exec: %v", err)
		}
	}

	// Test 1h range
	req := httptest.NewRequest(http.MethodGet, "/api/sensors/"+sensorID+"/graph?range=1h", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", w.Code, http.StatusOK)
	}

	var resp struct {
		Total     int          `json:"total"`
		LostTotal int          `json:"lost_total"`
		Points    []GraphPoint `json:"points"`
	}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if resp.Total != 10 {
		t.Errorf("Total: got %d, want 10", resp.Total)
	}
	if resp.LostTotal != 2 {
		t.Errorf("LostTotal: got %d, want 2", resp.LostTotal)
	}

	// Sum totals from points
	sumTotal := 0
	sumLost := 0
	for _, p := range resp.Points {
		sumTotal += p.Total
		sumLost += p.Lost
	}
	if sumTotal != 10 {
		t.Errorf("Sum of bucket totals must match grand total: got %d, want 10", sumTotal)
	}
	if sumLost != 2 {
		t.Errorf("Sum of bucket lost must match grand lost_total: got %d, want 2", sumLost)
	}
}
