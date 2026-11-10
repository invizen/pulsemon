package main

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"pulsemon/internal/store"
)

// TestSensorDeleteCascadesAlertState pins the schema-level half of
// review 2026-11-10 #3: probes, events, sensor_tags and alert_state all
// declare ON DELETE CASCADE, and store.NewStore enables
// foreign_keys(1) on every connection — so the single DELETE FROM
// sensors in handleSensorByID cleans up all child rows atomically and
// no orphan rows remain. If this fails, the "no orphan rows" invariant
// is broken.
func TestSensorDeleteCascadesAlertState(t *testing.T) {
	db := fcDB(t)
	const id = "s-cascade"
	fcSensor(t, db, id, "cascade", "active")
	fcProbe(t, db, id, time.Now().UTC(), 12.5)
	if _, err := db.Exec(`INSERT INTO events (sensor_id, ts, from_status, to_status) VALUES (?, ?, 'up', 'down')`, id, store.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sensor_tags (sensor_id, tag) VALUES (?, 't')`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO alert_state (sensor_id, status, last_ts) VALUES (?, 'error', ?)`, id, store.Now()); err != nil {
		t.Fatal(err)
	}
	res, err := db.Exec(`DELETE FROM sensors WHERE id = ?`, id)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("RowsAffected = %d, want 1", n)
	}
	for _, table := range []string{"probes", "events", "sensor_tags", "alert_state"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE sensor_id = ?`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("%s rows for deleted sensor = %d, want 0 (ON DELETE CASCADE)", table, n)
		}
	}
}

// TestSetAlertStateDeletedSensorNoResurrection pins the setAlertState
// guard (review 2026-11-10 #3): alert state is never re-created for a
// deleted sensor — even on a connection with FK enforcement OFF (bare
// sql.Open, no pragmas), where the old plain INSERT would have created
// the orphan row the guard now prevents. The guard is the SELECT inside
// the upsert itself, not the alert_state FK.
func TestSetAlertStateDeletedSensorNoResurrection(t *testing.T) {
	raw, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "raw.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	dbStore := &store.Store{DB: raw}
	if err := dbStore.InitSchema(); err != nil {
		t.Fatal(err)
	}
	pw := NewProbeWorker(dbStore)
	const id = "s-gone"
	if _, err := raw.Exec(`INSERT INTO sensors (id,name,target,type,interval_s,timeout_ms,loss_warn,down_after,spike_mult,state,status,created_at)
		VALUES (?,?,'10.0.0.2','icmp',60,1000,25,2,5,'active','up',?)`, id, "gone", store.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO alert_state (sensor_id, status, last_ts) VALUES (?, 'error', ?)`, id, store.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`DELETE FROM sensors WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
	// Precondition: with FK off the child row SURVIVES the delete —
	// this is exactly the state the old plain INSERT would have
	// resurrected on top of.
	var n int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM alert_state WHERE sensor_id = ?`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("precondition: alert_state rows = %d, want 1 (FK off: no cascade)", n)
	}
	// An in-flight alert for the deleted sensor must not touch state:
	// the surviving row keeps its OLD status (the old plain INSERT would
	// have hit ON CONFLICT and updated it).
	pw.setAlertState(id, "down", time.Now().UTC())
	var status string
	if err := raw.QueryRow(`SELECT status FROM alert_state WHERE sensor_id = ?`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "error" {
		t.Fatalf("deleted sensor status = %q, want %q (untouched)", status, "error")
	}
	if err := raw.QueryRow(`SELECT COUNT(*) FROM alert_state WHERE sensor_id = ?`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("alert_state rows after setAlertState(deleted) = %d, want 1 (no resurrection)", n)
	}
	// Positive control: for a live sensor the guarded upsert behaves
	// exactly like the old one — insert, then update on conflict.
	const live = "s-live"
	if _, err := raw.Exec(`INSERT INTO sensors (id,name,target,type,interval_s,timeout_ms,loss_warn,down_after,spike_mult,state,status,created_at)
		VALUES (?,?,'10.0.0.3','icmp',60,1000,25,2,5,'active','up',?)`, live, "live", store.Now()); err != nil {
		t.Fatal(err)
	}
	pw.setAlertState(live, "down", time.Now().UTC())
	pw.setAlertState(live, "error", time.Now().UTC())
	if err := raw.QueryRow(`SELECT status FROM alert_state WHERE sensor_id = ?`, live).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "error" {
		t.Fatalf("live sensor status = %q, want %q (upsert)", status, "error")
	}
	if err := raw.QueryRow(`SELECT COUNT(*) FROM alert_state WHERE sensor_id = ?`, live).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("live sensor alert_state rows = %d, want 1", n)
	}
}
