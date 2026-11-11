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

// TestSensorExistenceCheckDistinguishesErrors pins the 2026-11-03 finding:
// handleSensorHistory, handleSensorGraph and handleSensorClearHistory
// collapsed EVERY existence-check error (context canceled, SQLITE_BUSY,
// disk I/O) into a 404 "sensor not found", unlike handleSensorByID /
// handleSensorPing which map only sql.ErrNoRows to a 404 and everything
// else to a 500. A canceled client ctx (disconnected) must now surface as
// a 500 (a transient server error), while a genuinely-missing sensor (live
// ctx) stays a 404 — a locked DB must not read as "the sensor was deleted".
// The clone route joins the case list (review 2026-11-11): handleSensorClone's
// source-row read was the last site of this class left unconverted — its
// own later queries already answered transient failures with 500.
//
// The test routes through srv.Mux() (not the handler methods directly) so
// r.PathValue("id") is populated; the fresh test DB has no users, so auth
// is off and the requireAdmin-wrapped DELETE /history route stands down.
func TestSensorExistenceCheckDistinguishesErrors(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))

	// One real sensor (happy path); the missing-sensor cases use an id
	// that is never seeded.
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('exist-s1', 'exist-s1', '127.0.0.1', 'icmp', 60, 1000, 25, 2, 3, 'active', 'up', ?)`, store.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES ('exist-s1', ?, 1.0)`, store.Now()); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		method string
		path   string
	}{
		{"GET", "/api/sensors/{id}/history"},
		{"GET", "/api/sensors/{id}/graph?range=1h"},
		{"DELETE", "/api/sensors/{id}/history"},
		{"POST", "/api/sensors/{id}/clone"},
	}

	// 1. Dead request ctx (client disconnected before the DB call) → 500,
	// NOT 404. Pre-fix the collapsed existence check returned 404.
	deadCtx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, c := range cases {
		req := httptest.NewRequest(c.method, strings.ReplaceAll(c.path, "{id}", "exist-s1"), nil).WithContext(deadCtx)
		rr := httptest.NewRecorder()
		srv.Mux().ServeHTTP(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Errorf("%s %s with dead ctx: %d, want 500 (a canceled ctx is a transient server error, not 'sensor not found')", c.method, c.path, rr.Code)
		}
	}

	// 2. Genuinely-missing sensor (live ctx) → 404, NOT 500. The sensor
	// really is gone, so the 404 is correct — the fix must not over-correct
	// a real miss into a 500.
	for _, c := range cases {
		req := httptest.NewRequest(c.method, strings.ReplaceAll(c.path, "{id}", "no-such-sensor"), nil)
		rr := httptest.NewRecorder()
		srv.Mux().ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("%s %s for a missing sensor: %d, want 404 (the sensor really is gone, not a 500)", c.method, c.path, rr.Code)
		}
	}

	// 3. Existing sensor (live ctx) → 200 (happy path intact); the clone
	// route creates a resource, so its happy path is 201.
	for _, c := range cases {
		want := http.StatusOK
		if c.method == http.MethodPost {
			want = http.StatusCreated
		}
		req := httptest.NewRequest(c.method, strings.ReplaceAll(c.path, "{id}", "exist-s1"), nil)
		rr := httptest.NewRecorder()
		srv.Mux().ServeHTTP(rr, req)
		if rr.Code != want {
			t.Errorf("%s %s for an existing sensor: %d, want %d (%s)", c.method, c.path, rr.Code, want, rr.Body.String())
		}
	}
}

// TestFix_SettingsAndTagsReadsFailLoudly pins review 2026-11-11 #5: the
// last swallow-to-default reads on the request path — handleTags GET
// (AllTags), handleSensorByID GET (SensorTags), fetchSensors
// (SensorTagsFor) — now carry the request ctx AND surface DB errors, and
// handleSettingsGet fails loud (500) on a settings read failure instead
// of rendering a 200 of fabricated defaults. The settings shape is the
// dangerous one: the dashboard's alerts form seeds itself from
// GET /api/settings and PUTs those fields back on save, so a swallowed
// read failure (alert_scope "all", realert_min 30, maintenance off) can
// be written back as operator intent, overwriting the real settings.
//
// Deterministic injections (same pool-level fast-fail the 2026-10-30
// pins established): a canceled ctx fails AllTags/SensorTags/
// SensorTagsFor at the pool, and a closed store fails the settings reads
// with "database is closed". The closed-store check runs last so the
// other phases keep a live store.
func TestFix_SettingsAndTagsReadsFailLoudly(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))

	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('ctx-t1', 'ctx-t1', '127.0.0.1', 'icmp', 60, 1000, 25, 2, 3, 'active', 'up', ?)`, store.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sensor_tags (sensor_id, tag) VALUES ('ctx-t1', 'loudtag')`); err != nil {
		t.Fatal(err)
	}

	// Live ctx: 200s with real payloads.
	req := httptest.NewRequest("GET", "/api/tags", nil)
	rr := httptest.NewRecorder()
	srv.Mux().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "loudtag") {
		t.Fatalf("tags GET live ctx: %d %s, want 200 with loudtag", rr.Code, rr.Body.String())
	}
	req = httptest.NewRequest("GET", "/api/settings", nil)
	rr = httptest.NewRecorder()
	srv.Mux().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("settings GET live ctx: %d, want 200", rr.Code)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Dead ctx: the tag reads must fail fast with an error (method-level
	// pin covers the mid-handler window for the calls that a dead-ctx
	// request can no longer reach, per the 2026-10-30 #5 pattern).
	if _, err := db.AllTags(ctx); err == nil {
		t.Error("AllTags with canceled ctx returned no error — the ctx was ignored")
	}
	if _, err := db.SensorTags(ctx, "ctx-t1"); err == nil {
		t.Error("SensorTags with canceled ctx returned no error — the ctx was ignored")
	}
	if _, err := db.SensorTagsFor(ctx, []string{"ctx-t1"}); err == nil {
		t.Error("SensorTagsFor with canceled ctx returned no error — the ctx was ignored")
	}
	// Handler-level: AllTags is the FIRST DB call on this path, so a
	// dead-ctx GET reaches it directly and must answer 500, not 200 {}.
	req = httptest.NewRequest("GET", "/api/tags", nil).WithContext(ctx)
	rr = httptest.NewRecorder()
	srv.Mux().ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("tags GET with dead request ctx: %d, want 500 (the query result IS the payload; a failure must not render as an empty tag fleet)", rr.Code)
	}

	// Closed store: settings GET must 500 — pre-fix the GetSetting
	// swallows turned the failure into a 200 of concrete defaults the
	// alerts form would later PUT back over the real settings.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("GET", "/api/settings", nil)
	rr = httptest.NewRecorder()
	srv.Mux().ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("settings GET with a failing settings read: %d, want 500 (a read failure must not render as 200 of defaults: body=%s)", rr.Code, rr.Body.String())
	}
}
