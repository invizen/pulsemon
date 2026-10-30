package main

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"pulsemon/internal/store"
	"strings"
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
		VALUES ('ctx-s1', 'ctx-s1', '127.0.0.1', 'icmp', 60, 1000, 25, 2, 3, 'active', 'up', ?)`, store.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES ('ctx-s1', ?, 1.0)`, store.Now()); err != nil {
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

// TestFix_MaintenanceAndTagDeleteHonorRequestContext pins the 2026-10-30
// review #5: the last four ctx-less DB calls on the request path —
// ActiveSensorIDs, EnterMaintenanceWithFreshSnapshot, SetMaintenanceMode,
// DeleteTag — now carry the request context. Same pool-level fast-fail
// contract as TestFix_HandlerDBCallsHonorRequestContext: a dead ctx means
// the statement never runs.
//
// Handler-level (ActiveSensorIDs): on the maintenance-enable path it runs
// BEFORE any ctx-aware call, so a dead-ctx request reaches it directly.
// Pre-fix the query ran and the 500 surfaced at the settings tx ("begin
// settings update"); post-fix the 500 surfaces at the pre-check itself
// ("snapshot active sensors") — the label pin is precise.
//
// Method-level (the other three): each has a preceding ctx-aware call in
// its handler, so a fully-dead ctx 500s before reaching them — the gap is
// the narrow "client disconnects mid-handler" window. Calling the methods
// directly with a canceled ctx pins the same guarantee deterministically:
// error, store intact.
func TestFix_MaintenanceAndTagDeleteHonorRequestContext(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))

	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('ctx-m1', 'ctx-m1', '127.0.0.1', 'icmp', 60, 1000, 25, 2, 3, 'active', 'up', ?)`, store.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sensor_tags (sensor_id, tag) VALUES ('ctx-m1', 'ctxtag')`); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // simulate a client that disconnected

	// 1. Maintenance enable with a dead ctx: the pre-check
	// (ActiveSensorIDs) is the first ctx-aware call on this path — it must
	// fail fast with its own label, not run the query and 500 later.
	// respondInternal logs the operation label (the body is a generic
	// "internal error"), so the label pin is on the captured log line:
	// post-fix "snapshot active sensors", pre-fix "begin settings update".
	req := httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"maintenance_mode":true}`)).WithContext(ctx)
	rr := httptest.NewRecorder()
	var logBuf bytes.Buffer
	prevLog := log.Writer()
	log.SetOutput(&logBuf)
	srv.handleSettingsPut(rr, req)
	log.SetOutput(prevLog)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("maintenance enable with dead ctx: %d, want 500", rr.Code)
	} else if !strings.Contains(logBuf.String(), "snapshot active sensors") {
		t.Errorf("maintenance enable with dead ctx: 500 logged from %q — want the ActiveSensorIDs pre-check to fail first", logBuf.String())
	}
	if got := db.GetSetting("maintenance_mode"); got == "1" {
		t.Error("maintenance mode was set with a dead request ctx")
	}

	// 2-4. The three narrow-window methods, called directly with a
	// canceled ctx: each must fast-fail with the store intact.
	if _, err := db.DeleteTag(ctx, "ctxtag"); err == nil {
		t.Error("DeleteTag with a canceled ctx: want an error (statement never ran)")
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM sensor_tags WHERE tag = 'ctxtag'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Error("DeleteTag with a canceled ctx deleted the tag row")
	}
	if _, err := db.EnterMaintenanceWithFreshSnapshot(ctx); err == nil {
		t.Error("EnterMaintenanceWithFreshSnapshot with a canceled ctx: want an error")
	}
	if got := db.GetSetting("maintenance_mode"); got == "1" {
		t.Error("EnterMaintenanceWithFreshSnapshot with a canceled ctx set the mode flag")
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM sensors WHERE id = 'ctx-m1' AND state = 'paused'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("EnterMaintenanceWithFreshSnapshot with a canceled ctx paused sensors")
	}
	if err := db.SetMaintenanceMode(ctx, false, []string{"ctx-m1"}, ""); err == nil {
		t.Error("SetMaintenanceMode with a canceled ctx: want an error")
	}

	// Sanity: live ctx, the same operations work end-to-end — the ctx
	// threading must not have broken the happy path.
	req = httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"maintenance_mode":true}`))
	rr = httptest.NewRecorder()
	srv.handleSettingsPut(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("maintenance enable with live ctx: %d (%s), want 200", rr.Code, rr.Body.String())
	}
	if got := db.GetSetting("maintenance_mode"); got != "1" {
		t.Error("maintenance enable with live ctx did not set the mode flag")
	}
	if err := db.SetMaintenanceMode(context.Background(), false, []string{"ctx-m1"}, ""); err != nil {
		t.Errorf("SetMaintenanceMode with live ctx: %v", err)
	}
	if got := db.GetSetting("maintenance_mode"); got == "1" {
		t.Error("SetMaintenanceMode with live ctx did not clear the mode flag")
	}
	if _, err := db.DeleteTag(context.Background(), "ctxtag"); err != nil {
		t.Errorf("DeleteTag with live ctx: %v", err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM sensor_tags WHERE tag = 'ctxtag'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("DeleteTag with live ctx did not delete the tag row")
	}
}
