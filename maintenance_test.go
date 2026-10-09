package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// sensorState reads one sensor's state column straight from the DB.
func sensorState(t *testing.T, db *DB, id string) string {
	t.Helper()
	var state string
	if err := db.QueryRow("SELECT state FROM sensors WHERE id = ?", id).Scan(&state); err != nil {
		t.Fatalf("read state for %s: %v", id, err)
	}
	return state
}

// putMaint drives a real PUT /api/settings through the API.
func putMaint(t *testing.T, srv *Server, on bool) {
	t.Helper()
	putMaintStatus(t, srv, on, http.StatusOK)
}

// putMaintStatus drives a real PUT /api/settings and asserts a specific code.
func putMaintStatus(t *testing.T, srv *Server, on bool, want int) {
	t.Helper()
	val := "false"
	if on {
		val = "true"
	}
	req, _ := http.NewRequest(http.MethodPut, "/api/settings", bytes.NewBufferString(`{"maintenance_mode":`+val+`}`))
	rr := httptest.NewRecorder()
	srv.Mux().ServeHTTP(rr, req)
	if rr.Code != want {
		t.Fatalf("PUT maintenance=%v = %d, want %d: %s", on, rr.Code, want, rr.Body.String())
	}
}

func newMaintTestDB(t *testing.T, rows []string) *DB {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "maint.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	for _, r := range rows {
		if _, err := db.Exec(r); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	return db
}

const maintSeedActive = `INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at) VALUES ('a1', 'alpha', '192.0.2.1', 60, 1000, 25, 2, 3, 'active', 'up', '2026-01-01T00:00:00Z')`
const maintSeedPaused = `INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at) VALUES ('u1', 'gamma', '192.0.2.3', 60, 1000, 25, 2, 3, 'paused', 'up', '2026-01-01T00:00:00Z')`

// TestMaintenancePauseResume pins the rework: enable pauses every ACTIVE
// sensor and snapshots that set; disable reactivates exactly the snapshot.
// A user-paused sensor never leaves the paused state.
func TestMaintenancePauseResume(t *testing.T) {
	db := newMaintTestDB(t, []string{maintSeedActive, `INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at) VALUES ('a2', 'beta', '192.0.2.2', 60, 1000, 25, 2, 3, 'active', 'up', '2026-01-01T00:00:00Z')`, maintSeedPaused})
	pw := NewProbeWorker(db)
	srv := NewServer(db, pw)

	// Baseline: a1 + a2 active, u1 user-paused.
	if got := sensorState(t, db, "a1"); got != "active" {
		t.Fatalf("baseline a1 = %s", got)
	}

	// ENABLE: both active sensors pause, user-paused stays paused.
	putMaint(t, srv, true)
	if db.GetSetting("maintenance_mode") != "1" {
		t.Fatal("maintenance_mode != 1 after enable")
	}
	if db.GetSetting("maintenance_active_ids") == "" {
		t.Fatal("snapshot empty after enable")
	}
	for id, want := range map[string]string{"a1": "paused", "a2": "paused", "u1": "paused"} {
		if got := sensorState(t, db, id); got != want {
			t.Fatalf("after enable %s = %s, want %s", id, got, want)
		}
	}

	// DISABLE: snapshot reactivates a1 + a2; u1 stays paused; snapshot cleared.
	putMaint(t, srv, false)
	if db.GetSetting("maintenance_mode") != "0" {
		t.Fatal("maintenance_mode != 0 after disable")
	}
	if db.GetSetting("maintenance_active_ids") != "" {
		t.Fatal("snapshot not cleared after disable")
	}
	for id, want := range map[string]string{"a1": "active", "a2": "active", "u1": "paused"} {
		if got := sensorState(t, db, id); got != want {
			t.Fatalf("after disable %s = %s, want %s", id, got, want)
		}
	}
}

// TestMaintenanceIgnoresSensorsAddedDuringMaint pins that a sensor NOT in the
// snapshot (added while maintenance is on, starting paused like all new
// sensors) is left alone by resume — it stays paused even after the cycle.
func TestMaintenanceIgnoresSensorsAddedDuringMaint(t *testing.T) {
	db := newMaintTestDB(t, []string{maintSeedActive, maintSeedPaused})
	pw := NewProbeWorker(db)
	srv := NewServer(db, pw)

	putMaint(t, srv, true)

	// A sensor created while maintenance is on. New sensors start paused, and
	// it was not in the snapshot (taken at enable), so resume must not revive
	// it.
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at) VALUES ('n1', 'newbie', '192.0.2.4', 60, 1000, 25, 2, 3, 'paused', 'up', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("add during maintenance: %v", err)
	}

	putMaint(t, srv, false)

	if got := sensorState(t, db, "a1"); got != "active" {
		t.Fatalf("a1 = %s after disable, want active (in snapshot)", got)
	}
	if got := sensorState(t, db, "n1"); got != "paused" {
		t.Fatalf("n1 = %s after disable, want paused (not in snapshot)", got)
	}
}

// TestMaintenanceIdempotentDisable pins that disabling with an empty/missing
// snapshot (e.g. a stale DB from before the rework) doesn't error and leaves
// states alone.
func TestMaintenanceIdempotentDisable(t *testing.T) {
	db := newMaintTestDB(t, []string{maintSeedActive})
	pw := NewProbeWorker(db)
	srv := NewServer(db, pw)

	// No snapshot was ever written; just flip the flag off.
	if err := db.SetSetting("maintenance_mode", "1"); err != nil {
		t.Fatal(err)
	}
	putMaint(t, srv, false)
	if got := sensorState(t, db, "a1"); got != "active" {
		t.Fatalf("a1 = %s, want active (untouched)", got)
	}
	if db.GetSetting("maintenance_mode") != "0" {
		t.Fatal("flag not off")
	}
}

// TestMaintenanceEnableNoActiveSensors pins the guard: enabling maintenance
// when NOTHING is active must be rejected (400) — an empty snapshot means
// resume would have nothing to restore, a state that can't be cleanly undone.
func TestMaintenanceEnableNoActiveSensors(t *testing.T) {
	db := newMaintTestDB(t, []string{maintSeedPaused})
	pw := NewProbeWorker(db)
	srv := NewServer(db, pw)

	putMaintStatus(t, srv, true, http.StatusBadRequest)
	if db.GetSetting("maintenance_mode") == "1" {
		t.Fatal("maintenance flag set despite zero active sensors")
	}
	if got := sensorState(t, db, "u1"); got != "paused" {
		t.Fatalf("u1 = %s, want paused (untouched)", got)
	}
}
