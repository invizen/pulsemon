package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"pulsemon/internal/store"
	"testing"
	"time"
)

// seedSensorWithHistory builds a DB + worker + server with one active sensor
// carrying a full cascade footprint: probe rows (the large table), event
// rows, a tag, and an alert_state row — everything a long-running 5s sensor
// accumulates before it is deleted.
func seedSensorWithHistory(t *testing.T, id, name string) (*store.Store, *ProbeWorker, *Server) {
	t.Helper()
	db, err := store.NewStore(filepath.Join(t.TempDir(), id+"-del.db"))
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES (?, ?, '10.0.0.1', 5, 1000, 25, 1, 5, 'active', 'up', '2026-01-01T00:00:00Z')`, id, name); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}
	for i := 0; i < 50; i++ {
		if _, err := db.Exec(`INSERT INTO probes (sk, ts_ms, rtt_ms) VALUES ((SELECT sk FROM sensors WHERE id = ?), ?, ?)`,
			id, time.Now().Add(-time.Duration(i)*time.Minute).UTC().UnixMilli(), 1.5); err != nil {
			t.Fatalf("seed probe %d: %v", i, err)
		}
	}
	if _, err := db.Exec(`INSERT INTO events (sensor_id, ts, from_status, to_status, note)
		VALUES (?, '2026-01-01T00:00:00Z', 'up', 'down', 'up -> down')`, id); err != nil {
		t.Fatalf("seed event: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sensor_tags (sensor_id, tag) VALUES (?, 'edge')`, id); err != nil {
		t.Fatalf("seed tag: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO alert_state (sensor_id, status, last_ts) VALUES (?, 'up', '2026-01-01T00:00:00Z')`, id); err != nil {
		t.Fatalf("seed alert_state: %v", err)
	}
	pw := NewProbeWorker(db)
	srv := NewServer(db, pw)
	return db, pw, srv
}

// TestDeleteSensorRemovesCascade pins finding #5: deleting a sensor must
// remove its ENTIRE cascade footprint (probes, events, sensor_tags,
// alert_state) and stop its probe loop, not just the sensor row. The old code
// ran a single `DELETE FROM sensors` that cascaded the whole footprint in one
// statement, holding the WAL write lock across the entire sweep — the exact
// class deleteRowsBatched (clear-history, retention purge) exists to avoid.
func TestDeleteSensorRemovesCascade(t *testing.T) {
	db, pw, srv := seedSensorWithHistory(t, "del1", "del1")
	var del1sk int64
	if err := db.QueryRow(`SELECT sk FROM sensors WHERE id = 'del1'`).Scan(&del1sk); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/sensors/del1", nil)
	w := httptest.NewRecorder()
	srv.Mux().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete sensor: %d, want 204, body %s", w.Code, w.Body.String())
	}

	// Every cascade table is empty for the deleted sensor.
	for table, col := range map[string]string{
		"events":      "sensor_id",
		"sensor_tags": "sensor_id",
		"alert_state": "sensor_id",
	} {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE "+col+" = ?", "del1").Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s rows = %d, want 0 (cascade footprint must be removed)", table, n)
		}
	}
	var probes int
	if err := db.QueryRow(`SELECT COUNT(*) FROM probes WHERE sk = ?`, del1sk).Scan(&probes); err != nil {
		t.Fatalf("count probes: %v", err)
	}
	if probes != 0 {
		t.Errorf("probes rows = %d, want 0 (cascade footprint must be removed)", probes)
	}
	var sensors int
	if err := db.QueryRow("SELECT COUNT(*) FROM sensors WHERE id = ?", "del1").Scan(&sensors); err != nil {
		t.Fatalf("count sensors: %v", err)
	}
	if sensors != 0 {
		t.Errorf("sensor row = %d, want 0", sensors)
	}

	// The probe loop is stopped and its in-memory state dropped.
	pw.mu.Lock()
	_, loopStillThere := pw.loops["del1"]
	_, stateStillThere := pw.sensors["del1"]
	pw.mu.Unlock()
	if loopStillThere {
		t.Error("probe loop still registered after delete — Remove was not called")
	}
	if stateStillThere {
		t.Error("ProbeState still present after delete — Remove did not clear state")
	}
}

// TestDeleteSensorNotFound pins the 404 contract: deleting an id with no
// sensor row returns 404 and performs no deletes (the other sensors are
// untouched).
func TestDeleteSensorNotFound(t *testing.T) {
	db, _, srv := seedSensorWithHistory(t, "del2", "del2")

	req := httptest.NewRequest(http.MethodDelete, "/api/sensors/del2-missing", nil)
	w := httptest.NewRecorder()
	srv.Mux().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("delete missing sensor: %d, want 404, body %s", w.Code, w.Body.String())
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM sensors WHERE id = ?", "del2").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("del2 sensor row = %d, want 1 (untouched by the 404 delete)", n)
	}
}

// TestSyncSensorsIgnoresDeletingSensor pins the respawn guard: the DELETE
// handler marks the row 'deleting' before the cascade runs (a window of
// seconds for a 5s sensor), and a syncSensors pass landing in that window
// must NOT see the sensor — the old query (state IN ('active','paused'))
// saw it as active and RESPAWNED the loop Remove had just dropped, which
// then wrote new probes/alerts and logged FK errors once the row went away.
func TestSyncSensorsIgnoresDeletingSensor(t *testing.T) {
	db, pw, _ := seedSensorWithHistory(t, "del3", "del3")
	// A second sensor mid-delete: the row exists, state 'deleting' (the
	// DELETE handler's transient mark).
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('del3-dying', 'dying', '10.0.0.2', 5, 1000, 25, 1, 5, 'deleting', 'up', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert deleting sensor: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pw.syncSensors(ctx)

	pw.mu.Lock()
	_, liveLoop := pw.loops["del3"]
	_, liveState := pw.sensors["del3"]
	_, dyingLoop := pw.loops["del3-dying"]
	_, dyingState := pw.sensors["del3-dying"]
	pw.mu.Unlock()
	if !liveLoop || !liveState {
		t.Fatal("control: the active sensor did not spawn (loop/state missing)")
	}
	if dyingLoop {
		t.Error("a state='deleting' sensor got a loop respawned — syncSensors must not see it")
	}
	if dyingState {
		t.Error("a state='deleting' sensor got a ProbeState — syncSensors must not see it")
	}
}

// TestPingNowRejectsDeletingSensor pins the pulse side of the window: a
// "Pulse Now" fired while the delete cascade is running would write a
// manual probe row for a soon-to-be-orphaned sensor (and repopulate
// statsCache for a vanished one) — it must be refused, not recorded.
func TestPingNowRejectsDeletingSensor(t *testing.T) {
	db, pw, srv := seedSensorWithHistory(t, "del4", "del4")
	if _, err := db.Exec(`UPDATE sensors SET state = 'deleting' WHERE id = 'del4'`); err != nil {
		t.Fatalf("mark deleting: %v", err)
	}
	if _, err := pw.PingNow(context.Background(), "del4"); !errors.Is(err, errSensorDeleting) {
		t.Fatalf("PingNow on a deleting sensor: err = %v, want errSensorDeleting", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/sensors/del4/ping", nil)
	w := httptest.NewRecorder()
	srv.Mux().ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("POST ping on a deleting sensor: %d, want 409, body %s", w.Code, w.Body.String())
	}
	// No manual row may have been written.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM probes WHERE sk IN (SELECT sk FROM sensors WHERE id = 'del4') AND manual = 1`).Scan(&n); err != nil {
		t.Fatalf("count manual probes: %v", err)
	}
	if n != 0 {
		t.Errorf("manual probe rows = %d, want 0 (a refused pulse must not be recorded)", n)
	}
}

// TestVanishedSensorCleanupReleasesAllMaps pins the leak half: a sensor
// whose row disappears between sync passes (the tail of the delete-races-
// sync window) must have its ENTIRE in-memory footprint released — the old
// vanished pass dropped only loops+sensors and leaked statsCache (~57 KB),
// spawnedIDs, wasPaused, gens, lastPulse, alertOrderGates, and alertMem
// for the process lifetime.
func TestVanishedSensorCleanupReleasesAllMaps(t *testing.T) {
	db, pw, _ := seedSensorWithHistory(t, "del5", "del5")
	id := "del5"
	// Give the worker the full footprint of a long-running sensor.
	var cancelled bool
	_, lcancel := context.WithCancel(context.Background())
	pw.mu.Lock()
	pw.loops[id] = func() { cancelled = true; lcancel() }
	pw.sensors[id] = &ProbeState{id: id, kick: make(chan struct{}, 1)}
	pw.spawnedIDs[id] = true
	pw.wasPaused[id] = true
	pw.gens[id] = 3
	pw.lastPulse[id] = time.Now()
	pw.mu.Unlock()
	pw.statsMu.Lock()
	pw.statsCache[id] = &probeSeries{}
	pw.statsMu.Unlock()
	pw.alertMu.Lock()
	pw.alertOrderGates[id] = make(chan func(), 1)
	pw.alertMu.Unlock()
	pw.alertMemMu.Lock()
	pw.alertMem[id] = alertMemEntry{status: "up"}
	pw.alertMemMu.Unlock()

	// The sensor's row vanishes (the DELETE handler's final step), then a
	// sync pass runs.
	if _, err := db.Exec(`DELETE FROM sensors WHERE id = ?`, id); err != nil {
		t.Fatalf("delete row: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pw.syncSensors(ctx)

	if !cancelled {
		t.Error("the vanished sensor's loop cancel was not called")
	}
	pw.mu.Lock()
	leaks := []string{}
	if _, ok := pw.loops[id]; ok {
		leaks = append(leaks, "loops")
	}
	if _, ok := pw.sensors[id]; ok {
		leaks = append(leaks, "sensors")
	}
	if _, ok := pw.spawnedIDs[id]; ok {
		leaks = append(leaks, "spawnedIDs")
	}
	if _, ok := pw.wasPaused[id]; ok {
		leaks = append(leaks, "wasPaused")
	}
	if _, ok := pw.gens[id]; ok {
		leaks = append(leaks, "gens")
	}
	if _, ok := pw.lastPulse[id]; ok {
		leaks = append(leaks, "lastPulse")
	}
	pw.mu.Unlock()
	pw.statsMu.Lock()
	_, statsLeak := pw.statsCache[id]
	pw.statsMu.Unlock()
	if statsLeak {
		leaks = append(leaks, "statsCache")
	}
	pw.alertMu.Lock()
	_, gateLeak := pw.alertOrderGates[id]
	pw.alertMu.Unlock()
	if gateLeak {
		leaks = append(leaks, "alertOrderGates")
	}
	pw.alertMemMu.Lock()
	_, memLeak := pw.alertMem[id]
	pw.alertMemMu.Unlock()
	if memLeak {
		leaks = append(leaks, "alertMem")
	}
	if len(leaks) > 0 {
		t.Fatalf("vanished sensor leaked: %v (the full cleanup must run on the vanished pass)", leaks)
	}
}

// TestDeleteSensorRestoresStateOnBatchedDeleteFailure pins the
// compensation: a cascade failure AFTER the 'deleting' mark must restore
// the pre-delete state, or the surviving sensor is stranded in 'deleting'
// — no loop (Remove already ran), invisible to syncSensors, pulses
// rejected, hidden from the dashboard — with no path back. The restored
// sensor must also come back to life on the next sync pass.
func TestDeleteSensorRestoresStateOnBatchedDeleteFailure(t *testing.T) {
	db, pw, srv := seedSensorWithHistory(t, "del6", "del6")
	orig := deleteRowsBatched
	var sawState string
	deleteRowsBatched = func(ctx context.Context, db *store.Store, table, where string, args []any) (int64, error) {
		// The seam runs INSIDE the delete window (after the 'deleting'
		// mark, before the row goes away) — capture the state the window
		// presents to concurrent readers like syncSensors.
		_ = db.QueryRow(`SELECT state FROM sensors WHERE id = 'del6'`).Scan(&sawState)
		return 0, errors.New("injected cascade failure")
	}
	defer func() { deleteRowsBatched = orig }()

	req := httptest.NewRequest(http.MethodDelete, "/api/sensors/del6", nil)
	w := httptest.NewRecorder()
	srv.Mux().ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("delete with a failing cascade: %d, want 500, body %s", w.Code, w.Body.String())
	}
	if sawState != "deleting" {
		t.Fatalf("state mid-window (as seen by the cascade) = %q, want 'deleting' — the mark must land before the cascade runs", sawState)
	}
	var state string
	if err := db.QueryRow(`SELECT state FROM sensors WHERE id = 'del6'`).Scan(&state); err != nil {
		t.Fatalf("read state: %v", err)
	}
	if state != "active" {
		t.Fatalf("state after a failed delete = %q, want 'active' (a stranded 'deleting' sensor has no loop and no path back)", state)
	}
	// The sensor must come back to life: the next sync pass respawns the
	// loop (Remove dropped it when the delete started).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pw.syncSensors(ctx)
	pw.mu.Lock()
	_, respawned := pw.loops["del6"]
	pw.mu.Unlock()
	if !respawned {
		t.Error("the restored sensor was not respawned by syncSensors after a failed delete")
	}
}
