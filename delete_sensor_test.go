package main

import (
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
		if _, err := db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES (?, ?, ?)`,
			id, time.Now().Add(-time.Duration(i)*time.Minute).UTC().Format(time.RFC3339Nano), 1.5); err != nil {
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

	req := httptest.NewRequest(http.MethodDelete, "/api/sensors/del1", nil)
	w := httptest.NewRecorder()
	srv.Mux().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete sensor: %d, want 204, body %s", w.Code, w.Body.String())
	}

	// Every cascade table is empty for the deleted sensor.
	for table, col := range map[string]string{
		"probes":      "sensor_id",
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
