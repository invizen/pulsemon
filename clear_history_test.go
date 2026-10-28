package main

import (
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// seedFailingHTTPSensor builds a DB + worker + server with one HTTP sensor
// that has history, a failed probe row, and STALE ProbeState (as a failing
// sensor would have just before its history is cleared): lastStatus=error,
// fastRetry on, lastHTTPStatus=503, lastCertExpiry set, plus a cached series
// entry so the reset has something to wipe.
func seedFailingHTTPSensor(t *testing.T, id, name string) (*DB, *ProbeWorker, *Server) {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), id+"-clear.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES (?, ?, 'http://127.0.0.1:1/', 15, 8000, 25, 1, 3, 'active', 'error', '2026-01-01T00:00:00Z')`, id, name); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip, http_status)
		VALUES (?, ?, NULL, '127.0.0.1', 503)`, id, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed probe: %v", err)
	}
	pw := NewProbeWorker(db)
	srv := NewServer(db, pw)

	code := 503
	expiry := time.Now().Add(24 * time.Hour)
	pw.mu.Lock()
	pw.sensors[id] = &ProbeState{
		id:             id,
		lastStatus:     "error",
		fastRetry:      true,
		lastHTTPStatus: &code,
		lastCertExpiry: &expiry,
	}
	pw.mu.Unlock()
	pw.recordProbe(id, probeEntry{ts: time.Now().Unix() - 60, rtt: float32(math.NaN())})
	return db, pw, srv
}

func probeStateOf(t *testing.T, pw *ProbeWorker, id string) ProbeState {
	t.Helper()
	pw.mu.Lock()
	defer pw.mu.Unlock()
	ps, ok := pw.sensors[id]
	if !ok {
		t.Fatalf("no ProbeState for %s", id)
	}
	return *ps
}

// TestClearHistoryResetsProbeState locks the finding-11 fix: clearing one
// sensor's history must wipe its in-memory ProbeState (lastStatus,
// fastRetry, lastHTTPStatus, lastCertExpiry) as well as its cached series.
// The old code wiped only the series, so a cleared failing HTTP sensor kept
// serving a stale "HTTP 503" badge on an "up" sensor and its fastRetry
// cadence until the next probe tick. Fails on the old code.
func TestClearHistoryResetsProbeState(t *testing.T) {
	_, pw, srv := seedFailingHTTPSensor(t, "clr1", "clr1")

	req := httptest.NewRequest(http.MethodDelete, "/api/sensors/clr1/history", nil)
	w := httptest.NewRecorder()
	srv.Mux().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("clear history: %d, want 200, body %s", w.Code, w.Body.String())
	}

	ps := probeStateOf(t, pw, "clr1")
	if ps.lastStatus != "" {
		t.Errorf("lastStatus = %q, want \"\" (cleared)", ps.lastStatus)
	}
	if ps.fastRetry {
		t.Error("fastRetry = true, want false (cleared)")
	}
	if ps.lastHTTPStatus != nil {
		t.Errorf("lastHTTPStatus = %d, want nil (cleared)", *ps.lastHTTPStatus)
	}
	if ps.lastCertExpiry != nil {
		t.Errorf("lastCertExpiry = %v, want nil (cleared)", ps.lastCertExpiry)
	}
	if st, ce := pw.LastHTTPStatus("clr1"); st != nil || ce != nil {
		t.Errorf("LastHTTPStatus = (%v, %v), want (nil, nil)", st, ce)
	}
	if s := pw.GetStats("clr1"); s != nil {
		t.Errorf("GetStats = %+v, want nil (cache cleared)", s)
	}
}

// TestClearAllHistoryResetsProbeState is the bulk variant: DELETE /api/history
// must reset the ProbeState of EVERY sensor, not just their cached series.
func TestClearAllHistoryResetsProbeState(t *testing.T) {
	_, pw, srv := seedFailingHTTPSensor(t, "clr2", "clr2")
	// A second sensor with its own stale state.
	code := 503
	pw.mu.Lock()
	pw.sensors["clr2b"] = &ProbeState{id: "clr2b", lastStatus: "error", fastRetry: true, lastHTTPStatus: &code}
	pw.mu.Unlock()
	pw.recordProbe("clr2b", probeEntry{ts: time.Now().Unix() - 30, rtt: float32(math.NaN())})

	req := httptest.NewRequest(http.MethodDelete, "/api/history", nil)
	w := httptest.NewRecorder()
	srv.Mux().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("clear all history: %d, want 200, body %s", w.Code, w.Body.String())
	}
	for _, id := range []string{"clr2", "clr2b"} {
		ps := probeStateOf(t, pw, id)
		if ps.lastStatus != "" || ps.fastRetry || ps.lastHTTPStatus != nil || ps.lastCertExpiry != nil {
			t.Errorf("%s: ProbeState not fully cleared: %+v", id, ps)
		}
		if s := pw.GetStats(id); s != nil {
			t.Errorf("%s: GetStats = %+v, want nil (cache cleared)", id, s)
		}
	}
}

// TestClearHistoryAtomicOnFailure pins the clear-history failure contract
// as of the review-2026-10-24 batching fix. The DB is deliberately missing
// the events and alert_state tables, so the clear fails mid-way — the
// handler must return 500 and the SMALL state-consistency steps (status
// reset, alert_state) must NOT have run: they still commit atomically as
// one transaction AFTER the large deletes. The probes/events deletes
// themselves are batched autocommits (bounded WAL write-lock hold) and are
// therefore already committed when events fails — acceptable BY DESIGN
// because the operation is a WIPE: a retry deletes the remainder, so
// partial completion converges instead of half-clearing. (Pre-batching,
// this test pinned full rollback of the probes delete; pre-fix-11 code
// silently ignored the errors and returned 200 — the original bug.)
// The status-untouched assertion below is what still fails if someone
// re-splits the small steps back into autocommit-with-ignored-errors.
func TestClearHistoryAtomicOnFailure(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "clr3.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	// NO InitSchema: only the tables the clear can succeed on exist.
	// The users table IS created (empty): with zero accounts the auth
	// gate stands down, so this test exercises the clear-history
	// contract, not the admin gate (a missing users table makes
	// auth.Enabled() fail-closed and the route 401s before the handler).
	if _, err := db.Exec(`CREATE TABLE users (username TEXT PRIMARY KEY, is_admin INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatalf("create users: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE sensors (id TEXT PRIMARY KEY, name TEXT, status TEXT)`); err != nil {
		t.Fatalf("create sensors: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE probes (id INTEGER PRIMARY KEY, sensor_id TEXT, ts TEXT, rtt_ms REAL)`); err != nil {
		t.Fatalf("create probes: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sensors (id, name, status) VALUES ('clr3', 'clr3', 'error')`); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES ('clr3', '2026-01-01T00:00:00Z', NULL)`); err != nil {
		t.Fatalf("seed probe: %v", err)
	}
	srv := NewServer(db, NewProbeWorker(db))

	req := httptest.NewRequest(http.MethodDelete, "/api/sensors/clr3/history", nil)
	w := httptest.NewRecorder()
	srv.Mux().ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("clear with missing events table: %d, want 500 (mid-transaction failure), body %s", w.Code, w.Body.String())
	}

	// The batched probes wipe is autocommitted BEFORE the events step runs
	// (bounded write lock); a retry of the DELETE endpoint converges the
	// rest. What must NOT have happened: the small atomic tail.
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM probes WHERE sensor_id = ?", "clr3").Scan(&n); err != nil {
		t.Fatalf("count probes: %v", err)
	}
	if n != 0 {
		t.Errorf("probe rows = %d, want 0 (batched large deletes commit ahead of the atomic small steps by design — retry converges)", n)
	}
	var status string
	if err := db.QueryRow("SELECT status FROM sensors WHERE id = ?", "clr3").Scan(&status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status != "error" {
		t.Errorf("status = %q, want error (the failed clear must roll back the status reset)", status)
	}
}
