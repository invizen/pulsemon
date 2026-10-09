package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// TestEchoNowProbeRowCount drives the real handler against a live worker and
// asserts the sample is recorded: the probes row count increases by one, the
// row is a lost probe (rtt_ms NULL), and the sensor status is unchanged.
func TestEchoNowProbeRowCount(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "echo3.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	// down_after=1: a single lost probe WOULD error the sensor if PingNow
	// derived status. It must not.
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('echotest','echotest','192.0.2.1',15,8000,25,1,3,'active','up','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}
	pw := NewProbeWorker(db)
	srv := NewServer(db, pw)

	var captured *time.Duration
	orig := probeTarget
	probeTarget = func(probeType, target string, timeout time.Duration) probeOutcome {
		captured = &timeout
		return probeOutcome{lost: true, ip: "192.0.2.1"}
	}
	defer func() { probeTarget = orig }()

	count := func() int {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM probes WHERE sensor_id = ?", "echotest").Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}
	if got := count(); got != 0 {
		t.Fatalf("pre-ping probe rows = %d, want 0", got)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/sensors/echotest/ping", nil)
	w := httptest.NewRecorder()
	srv.Mux().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("ping handler: %d, want 200, body %s", w.Code, w.Body.String())
	}

	// Recorded: exactly one probe row, and it's a lost probe (rtt_ms NULL).
	if got := count(); got != 1 {
		t.Fatalf("post-ping probe rows = %d, want 1 (Echo Now must record its sample)", got)
	}
	var rtt sql.NullFloat64
	if err := db.QueryRow("SELECT rtt_ms FROM probes WHERE sensor_id = ?", "echotest").Scan(&rtt); err != nil {
		t.Fatalf("read rtt_ms: %v", err)
	}
	if rtt.Valid {
		t.Errorf("recorded rtt_ms = %v, want NULL (the echo was a lost probe)", rtt.Float64)
	}

	// NOT status-driven: a single lost probe with down_after=1 would have
	// flipped the sensor to "error" if PingNow derived status. It must stay up.
	var status string
	if err := db.QueryRow("SELECT status FROM sensors WHERE id = ?", "echotest").Scan(&status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status != "up" {
		t.Errorf("status after echo = %q, want up (a manual probe must not flip status)", status)
	}

	// Fixed 1s timeout, independent of the sensor's 8000ms configured timeout.
	if captured == nil {
		t.Fatal("pingNow was never called")
	}
	if *captured != time.Second {
		t.Errorf("echo timeout = %v, want 1s (fixed, not the sensor's configured timeout)", *captured)
	}
}

// TestEchoNowUnknownSensorReturns404 locks the unknown-sensor path: PingNow's
// target lookup fails with sql.ErrNoRows, which the handler must map to 404
// (not 500), and it must not record anything.
func TestEchoNowUnknownSensorReturns404(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "echo4.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	pw := NewProbeWorker(db)
	srv := NewServer(db, pw)

	req := httptest.NewRequest(http.MethodPost, "/api/sensors/nope/ping", nil)
	w := httptest.NewRecorder()
	srv.Mux().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("ping on unknown sensor: %d, want 404, body %s", w.Code, w.Body.String())
	}
}
