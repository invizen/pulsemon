package main

import (
	"context"
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
	probeTarget = func(ctx context.Context, probeType, target string, timeout time.Duration) probeOutcome {
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

// TestEchoNowCooldownThrottles locks the m5 fix: a second manual pulse within
// pulseNowCooldown is refused with 429 and NOT recorded, so an unthrottled
// loop of "Pulse Now" clicks can't starve the probe queue.
func TestEchoNowCooldownThrottles(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "echo5.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('echocd','echocd','192.0.2.1',15,8000,25,1,3,'active','up','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}
	pw := NewProbeWorker(db)
	srv := NewServer(db, pw)

	orig := probeTarget
	probeTarget = func(ctx context.Context, probeType, target string, timeout time.Duration) probeOutcome {
		return probeOutcome{lost: true, ip: "192.0.2.1"}
	}
	defer func() { probeTarget = orig }()

	// First pulse: 200.
	req := httptest.NewRequest(http.MethodPost, "/api/sensors/echocd/ping", nil)
	w := httptest.NewRecorder()
	srv.Mux().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first pulse: %d, want 200, body %s", w.Code, w.Body.String())
	}

	// Immediate second pulse: within the 2s cooldown → 429.
	req2 := httptest.NewRequest(http.MethodPost, "/api/sensors/echocd/ping", nil)
	w2 := httptest.NewRecorder()
	srv.Mux().ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("second pulse (within cooldown): %d, want 429, body %s", w2.Code, w2.Body.String())
	}

	// Only ONE probe row recorded — the throttled pulse must not record.
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM probes WHERE sensor_id = ?", "echocd").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("probe rows = %d, want 1 (the throttled pulse must not record)", n)
	}
}

// TestPingNowCacheUsesPostProbeTimestamp locks the finding-10 fix: the
// stats-cache entry for a manual pulse must carry the SAME post-probe
// instant as the DB row (the lockstep doProbe maintains), not the pre-probe
// cooldown timestamp. The stubbed probe sleeps >1s, so the pre- and
// post-probe instants ALWAYS land in different Unix seconds — with the old
// code (now.Unix(), captured before the probe) this assertion fails
// deterministically. The stale instant broke probeSeries's oldest-first
// ordering (a scheduled probe completing mid-pulse appended before an
// older entry) and could put the cached entry in a different 1-minute
// sparkline bucket than the SQLite row.
func TestPingNowCacheUsesPostProbeTimestamp(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "echo6.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('echots','echots','http://127.0.0.1:1/',15,8000,25,1,3,'active','up','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}
	pw := NewProbeWorker(db)

	orig := probeTarget
	probeTarget = func(ctx context.Context, probeType, target string, timeout time.Duration) probeOutcome {
		time.Sleep(1200 * time.Millisecond) // >1s: pre/post-probe instants are always different Unix seconds
		return probeOutcome{lost: true}
	}
	defer func() { probeTarget = orig }()

	if _, err := pw.PingNow(context.Background(), "echots"); err != nil {
		t.Fatalf("PingNow: %v", err)
	}

	// The DB row's ts (post-probe instant, RFC3339Nano).
	var tsStr string
	if err := db.QueryRow("SELECT ts FROM probes WHERE sensor_id = ?", "echots").Scan(&tsStr); err != nil {
		t.Fatalf("read ts: %v", err)
	}
	dbTs, err := time.Parse(time.RFC3339Nano, tsStr)
	if err != nil {
		t.Fatalf("parse ts: %v", err)
	}

	// The stats-cache entry's ts — must be the SAME instant.
	pw.statsMu.Lock()
	s := pw.statsCache["echots"]
	var snap []probeEntry
	if s == nil {
		pw.statsMu.Unlock()
		t.Fatal("no stats-cache entry recorded for the manual pulse")
	}
	snap = s.snapshot()
	pw.statsMu.Unlock()
	last := snap[len(snap)-1]

	if last.ts != dbTs.Unix() {
		t.Errorf("cache entry ts = %d, want %d (the DB row's post-probe instant; the pre-probe timestamp breaks oldest-first ordering and 1-minute bucketing)", last.ts, dbTs.Unix())
	}
}
