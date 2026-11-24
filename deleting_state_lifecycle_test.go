package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"pulsemon/internal/store"
)

// TestDeleteCompletesWhenClientGoesAwayMidCascade pins the client-detach
// half of the stuck-'deleting' fix: a client that leaves mid-cascade (tab
// closed, navigation away) cancels r.Context(), and the cascade must still
// run to completion on a client-detached context. The old code ran the
// batched deletes on r.Context(), so the next batch failed with
// context.Canceled, the restore failed on the same dead context, and the
// row sat in 'deleting' forever — hidden from the dashboard, its name
// still UNIQUE-held (re-creation 409s), no probe loop, Pulse Now 409.
func TestDeleteCompletesWhenClientGoesAwayMidCascade(t *testing.T) {
	db, _, srv := seedSensorWithHistory(t, "gone1", "gone1")
	reqCtx, clientCancel := context.WithCancel(context.Background())
	orig := deleteRowsBatched
	deleteRowsBatched = func(ctx context.Context, db *store.Store, table, where string, args []any) (int64, error) {
		// The client leaves exactly here — mid-cascade, after the
		// 'deleting' mark. Then the REAL batched delete runs on whatever
		// context the handler chose: client-detached (the fix) vs the
		// request's now-cancelled context (the old shape, where this
		// first ExecContext dies with context.Canceled).
		clientCancel()
		return orig(ctx, db, table, where, args)
	}
	defer func() { deleteRowsBatched = orig }()

	req := httptest.NewRequest(http.MethodDelete, "/api/sensors/gone1", nil).WithContext(reqCtx)
	w := httptest.NewRecorder()
	srv.Mux().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete with a client departure mid-cascade: %d, want 204, body %s", w.Code, w.Body.String())
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensors WHERE id = 'gone1'`).Scan(&n); err != nil {
		t.Fatalf("count sensors: %v", err)
	}
	if n != 0 {
		t.Fatalf("sensor row = %d, want 0 — the cascade must outlive the client (a stranded 'deleting' row holds its name and hides the sensor with no path back)", n)
	}
	for table, col := range map[string]string{
		"probes":      "sensor_id",
		"events":      "sensor_id",
		"sensor_tags": "sensor_id",
		"alert_state": "sensor_id",
	} {
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table + ` WHERE ` + col + ` = 'gone1'`).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s rows = %d, want 0 (the cascade must finish after the client is gone)", table, n)
		}
	}
}

// TestDeleteRestoreStateSurvivesCanceledRequest pins the rollback half:
// with the client gone AND a genuine cascade failure, the compensating
// restore must still land. The old restoreState ran on r.Context(), so it
// failed at once on the cancelled context and stranded the row in
// 'deleting' — the exact shape TestDeleteSensorRestoresStateOnBatchedDeleteFailure
// does not cover (its injected error fires while the request context is
// still live).
func TestDeleteRestoreStateSurvivesCanceledRequest(t *testing.T) {
	db, pw, srv := seedSensorWithHistory(t, "gone2", "gone2")
	reqCtx, clientCancel := context.WithCancel(context.Background())
	orig := deleteRowsBatched
	deleteRowsBatched = func(ctx context.Context, db *store.Store, table, where string, args []any) (int64, error) {
		// Client departs mid-cascade, and the cascade genuinely fails
		// (disk full, I/O) — both at once.
		clientCancel()
		return 0, errors.New("injected cascade failure")
	}
	defer func() { deleteRowsBatched = orig }()

	req := httptest.NewRequest(http.MethodDelete, "/api/sensors/gone2", nil).WithContext(reqCtx)
	w := httptest.NewRecorder()
	srv.Mux().ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("delete with a failing cascade: %d, want 500, body %s", w.Code, w.Body.String())
	}
	var state string
	if err := db.QueryRow(`SELECT state FROM sensors WHERE id = 'gone2'`).Scan(&state); err != nil {
		t.Fatalf("read state: %v", err)
	}
	if state != "active" {
		t.Fatalf("state after a failed delete with the client gone = %q, want 'active' (the restore must run on a context that outlives the request)", state)
	}
	// The restored sensor comes back to life on the next sync pass
	// (Remove dropped its loop when the delete started).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pw.syncSensors(ctx)
	pw.mu.Lock()
	_, respawned := pw.loops["gone2"]
	pw.mu.Unlock()
	if !respawned {
		t.Error("the restored sensor was not respawned by syncSensors")
	}
}

// TestRunCompletesInterruptedDeletesAtBoot pins the boot half: a process
// death mid-cascade (crash, kill, shutdown-drain expiry) leaves
// state='deleting' rows that nothing else touches — no loop, hidden from
// the dashboard, name UNIQUE-held, purgeOld's tail exemption keeps their
// probe tail forever. Run must finish those deletions at startup, before
// any probing begins.
func TestRunCompletesInterruptedDeletesAtBoot(t *testing.T) {
	db := fcDB(t)
	// The interrupted delete: the row in the handler's transient
	// 'deleting' mark, with its full cascade footprint.
	fcSensor(t, db, "dying1", "dying1", "deleting")
	fcProbe(t, db, "dying1", time.Now().Add(-time.Hour), 1.5)
	if _, err := db.Exec(`INSERT INTO events (sensor_id, ts, from_status, to_status, note) VALUES ('dying1', ?, 'up', 'down', 'up -> down')`, store.FormatTS(time.Now().Add(-time.Hour))); err != nil {
		t.Fatalf("seed event: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sensor_tags (sensor_id, tag) VALUES ('dying1', 'edge')`); err != nil {
		t.Fatalf("seed tag: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO alert_state (sensor_id, status, last_ts) VALUES ('dying1', 'up', ?)`, store.FormatTS(time.Now())); err != nil {
		t.Fatalf("seed alert_state: %v", err)
	}
	// Positive control: a sensor that is NOT mid-delete must survive boot,
	// row and probe history intact.
	fcSensor(t, db, "live1", "live1", "paused")
	fcProbe(t, db, "live1", time.Now().Add(-time.Hour), 2.5)

	pw := NewProbeWorker(db)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pw.Run(ctx)
		close(done)
	}()
	// The cleanup runs synchronously before Run's select loop.
	time.Sleep(300 * time.Millisecond)
	cancel()
	<-done

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensors WHERE id = 'dying1'`).Scan(&n); err != nil {
		t.Fatalf("count dying1: %v", err)
	}
	if n != 0 {
		t.Errorf("interrupted-delete row = %d, want 0 — boot must finish the deletion (its name stays UNIQUE-held and the row is otherwise unmanageable)", n)
	}
	for table, col := range map[string]string{
		"probes":      "sensor_id",
		"events":      "sensor_id",
		"sensor_tags": "sensor_id",
		"alert_state": "sensor_id",
	} {
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table + ` WHERE ` + col + ` = 'dying1'`).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s rows for the interrupted delete = %d, want 0 (the FK cascade must clean the footprint)", table, n)
		}
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensors WHERE id = 'live1'`).Scan(&n); err != nil {
		t.Fatalf("count live1: %v", err)
	}
	if n != 1 {
		t.Errorf("live1 sensor row = %d, want 1 (boot cleanup must touch only 'deleting' rows)", n)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM probes WHERE sensor_id = 'live1'`).Scan(&n); err != nil {
		t.Fatalf("count live1 probes: %v", err)
	}
	if n != 1 {
		t.Errorf("live1 probe rows = %d, want 1 (boot cleanup must touch only 'deleting' rows)", n)
	}
}

// TestPatchDeletingSensorIsNotFound pins the PATCH side: a row marked
// 'deleting' is mid-cascade — a PATCH must not match it, or the sensor is
// revived halfway through its delete ({"state":"active"} in particular)
// and the cascade then tears down a row someone just re-activated.
// Missing and mid-delete are both 404.
func TestPatchDeletingSensorIsNotFound(t *testing.T) {
	db, _, srv := seedSensorWithHistory(t, "dying2", "dying2")
	if _, err := db.Exec(`UPDATE sensors SET state = 'deleting' WHERE id = 'dying2'`); err != nil {
		t.Fatalf("mark deleting: %v", err)
	}

	t.Run("state-revive-refused", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPatch, "/api/sensors/dying2", strings.NewReader(`{"state":"active"}`))
		w := httptest.NewRecorder()
		srv.Mux().ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("PATCH state on a deleting sensor: %d, want 404, body %s", w.Code, w.Body.String())
		}
		var state string
		if err := db.QueryRow(`SELECT state FROM sensors WHERE id = 'dying2'`).Scan(&state); err != nil {
			t.Fatalf("read state: %v", err)
		}
		if state != "deleting" {
			t.Errorf("state after a refused PATCH = %q, want 'deleting' (a PATCH must not revive a sensor mid-delete)", state)
		}
	})

	t.Run("name-patch-refused", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPatch, "/api/sensors/dying2", strings.NewReader(`{"name":"renamed"}`))
		w := httptest.NewRecorder()
		srv.Mux().ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("PATCH name on a deleting sensor: %d, want 404, body %s", w.Code, w.Body.String())
		}
		var name string
		if err := db.QueryRow(`SELECT name FROM sensors WHERE id = 'dying2'`).Scan(&name); err != nil {
			t.Fatalf("read name: %v", err)
		}
		if name != "dying2" {
			t.Errorf("name after a refused PATCH = %q, want 'dying2' (untouched)", name)
		}
	})

	// Positive control: a non-deleting sensor still PATCHes fine — the
	// 404 must apply to deleting rows only.
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('live2', 'live2', '10.0.0.9', 5, 1000, 25, 1, 5, 'paused', 'up', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert live2: %v", err)
	}
	req := httptest.NewRequest(http.MethodPatch, "/api/sensors/live2", strings.NewReader(`{"state":"active"}`))
	w := httptest.NewRecorder()
	srv.Mux().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("PATCH state on a paused sensor: %d, want 200, body %s", w.Code, w.Body.String())
	}
	var state string
	if err := db.QueryRow(`SELECT state FROM sensors WHERE id = 'live2'`).Scan(&state); err != nil {
		t.Fatalf("read live2 state: %v", err)
	}
	if state != "active" {
		t.Errorf("live2 state = %q, want 'active' (the 404 must apply to deleting rows only)", state)
	}
}
