package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestFix_HandlerDBCallsHonorRequestContext pins the contract that HTTP
// handler DB calls carry the request context (external review finding:
// fetchSensors, handleSensorHistory, handleSensorGraph, handleEvents,
// handleSensorClearHistory, handleClearAllHistory and handleTags ran
// s.db.Query/QueryRow/Exec/Begin without ctx, unlike the PATCH path's
// ImmediateTx(r.Context())).
//
// The deterministic slice pinable here: a request whose context is already
// dead (client disconnected) must NOT have its DB statements executed —
// database/sql fails fast at the pool level for a canceled ctx (verified:
// BeginTx/ExecContext on a canceled ctx return in microseconds).
//
// Empirically verified against modernc.org/sqlite v1.29.1 (the driver this
// app uses): a statement ALREADY blocked inside the driver on the 15s
// busy_timeout is NOT interrupted by cancellation — the driver ignores the
// ctx during the lock wait and runs the full timeout. So the pool-level
// fast-fail at the call site is the guarantee the code can make, and this
// test pins exactly that (pre-fix: the ctx was ignored, the wipe committed
// with a 200 and the rows were gone).
func TestFix_HandlerDBCallsHonorRequestContext(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))

	// Seed a sensor + probe rows that the wipe handlers would delete.
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('ctx-s1', 'ctx-s1', '127.0.0.1', 'icmp', 60, 1000, 25, 2, 3, 'active', 'up', ?)`, tsNow()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES ('ctx-s1', ?, 1.0)`, tsNow()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // simulate a client that disconnected before the DB call ran

	// 1. handleClearAllHistory (write path): pre-fix Begin() + tx.Exec
	// ignore the ctx and the wipe commits (200, rows gone). Post-fix
	// BeginTx surfaces the ctx error immediately and the store is intact.
	req := httptest.NewRequest("DELETE", "/api/history", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	srv.handleClearAllHistory(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("clear-all with dead request ctx: %d, want 500 (the DB call must surface the ctx error)", rr.Code)
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM probes").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Error("clear-all with a dead request ctx executed the wipe — the ctx was ignored")
	}

	// 2. handleSensors GET (read path, fetchSensors): pre-fix Query() ignores
	// the ctx and returns the fleet (200). Post-fix QueryContext fails fast
	// → the nil sentinel → 500.
	req = httptest.NewRequest("GET", "/api/sensors", nil).WithContext(ctx)
	rr = httptest.NewRecorder()
	srv.handleSensors(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("sensors GET with dead request ctx: %d, want 500", rr.Code)
	}

	// Sanity: with a live ctx both paths work as before.
	req = httptest.NewRequest("DELETE", "/api/history", nil)
	rr = httptest.NewRecorder()
	srv.handleClearAllHistory(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("clear-all with live ctx: %d, want 200", rr.Code)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM probes").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("clear-all with live ctx: %d probe rows left, want 0", n)
	}
}
