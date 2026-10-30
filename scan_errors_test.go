package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"pulsemon/internal/store"
	"strings"
	"testing"
)

// TestFix_ScanErrorsLoggedNotSilent pins the per-row scan-error contract
// (external review finding: handleSensorHistory, handleSensorGraph and
// handleEvents silently `continue`d on rows.Scan failure while fetchSensors
// logs — a corrupt row would produce a 200 with a truncated list and zero
// visibility in the service log).
//
// Trigger: a probe/event row with an INTEGER ts. The ts columns are TEXT
// (RFC3339Nano) and both handlers scan into time.Time, so an int64 value
// fails the scan deterministically. The graph's WHERE clause
// (strftime('%s', ts) >= cutoff) drops NULL-bucket rows before they reach
// the scan loop, so a data-level corrupt row cannot reach the graph scan —
// that log line is the schema-level defensive one; the identical pattern is
// pinned here via history and events.
func TestFix_ScanErrorsLoggedNotSilent(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))

	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('scan-s1', 'scan-s1', '127.0.0.1', 'icmp', 60, 1000, 25, 2, 3, 'active', 'up', ?)`, store.Now()); err != nil {
		t.Fatal(err)
	}
	// One good row (valid RFC3339 ts) plus one corrupt row (INTEGER ts).
	if _, err := db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES ('scan-s1', ?, 1.0)`, store.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES ('scan-s1', 12345, 2.0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO events (sensor_id, ts, from_status, to_status, note) VALUES ('scan-s1', ?, 'up', 'error', 'good')`, store.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO events (sensor_id, ts, from_status, to_status, note) VALUES ('scan-s1', 99999, 'up', 'error', 'bad')`); err != nil {
		t.Fatal(err)
	}

	// Capture the service log for the duration of the test.
	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(prev) })

	// 1. history: the corrupt row is skipped WITH a log line; the good row
	// is still served (200, not 500 — one corrupt row must not break the
	// endpoint, and the skip must be visible in the service log).
	var hist struct {
		Count  int `json:"count"`
		Probes []struct {
			TS string `json:"ts"`
		} `json:"probes"`
	}
	req := httptest.NewRequest("GET", "/api/sensors/scan-s1/history", nil)
	rr := httptest.NewRecorder()
	srv.Mux().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("history with one corrupt row: %d, want 200", rr.Code)
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &hist); err != nil {
		t.Fatal(err)
	}
	if hist.Count != 1 {
		t.Errorf("history: %d rows served, want 1 (corrupt row skipped, good row kept)", hist.Count)
	}
	if !strings.Contains(logBuf.String(), "skipping corrupt probe row for scan-s1") {
		t.Error("corrupt probe row was dropped silently — no trace in the service log")
	}

	// 2. graph: 200 with the good row's bucket (corrupt row is filtered by
	// the WHERE before the scan — see the comment above).
	req = httptest.NewRequest("GET", "/api/sensors/scan-s1/graph?range=24h", nil)
	rr = httptest.NewRecorder()
	srv.Mux().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("graph with one corrupt row: %d, want 200", rr.Code)
	}

	// 3. events: the corrupt row is skipped WITH a log line; the good event
	// is still served.
	var evts []struct {
		TS   string `json:"ts"`
		Note string `json:"note"`
	}
	req = httptest.NewRequest("GET", "/api/events", nil)
	rr = httptest.NewRecorder()
	srv.Mux().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("events with one corrupt row: %d, want 200", rr.Code)
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &evts); err != nil {
		t.Fatal(err)
	}
	if len(evts) != 1 || evts[0].Note != "good" {
		t.Errorf("events: %+v, want exactly the good row", evts)
	}
	if !strings.Contains(logBuf.String(), "skipping corrupt event row") {
		t.Error("corrupt event row was dropped silently — no trace in the service log")
	}
}
