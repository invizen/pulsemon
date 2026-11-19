package main

import (
	"context"
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
	dbStore := store.NewStoreForTest(raw, raw)
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
	pw.setAlertState(context.Background(), id, "down", time.Now().UTC())
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
	pw.setAlertState(context.Background(), live, "down", time.Now().UTC())
	pw.setAlertState(context.Background(), live, "error", time.Now().UTC())
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

// TestSetAlertStateWriteFailureDoesNotStampMemory pins review 2026-11-17 M1:
// a FAILED alert_state upsert is logged and returns WITHOUT stamping the
// in-memory copy, so the durable row stays authoritative and the next tick's
// maybeRealert cache-misses, re-reads the stale row, sees the mismatch, and
// retries the write. The old `_, _ =` stamped memory on failure too: memory
// then said "stamped now" while the durable row stayed stale, and every
// restart re-read the stale row — silently resetting re-alert timing with
// nothing in the log.
func TestSetAlertStateWriteFailureDoesNotStampMemory(t *testing.T) {
	db := fcDB(t)
	const id = "s-writefail"
	fcSensor(t, db, id, "writefail", "active")
	pw := NewProbeWorker(db)

	// Positive control: a healthy write stamps both the durable row and the
	// in-memory copy.
	pw.setAlertState(context.Background(), id, "error", time.Now().UTC())
	pw.alertMemMu.Lock()
	_, inMem := pw.alertMem[id]
	pw.alertMemMu.Unlock()
	if !inMem {
		t.Fatal("healthy write: alertMem entry missing, want stamped")
	}

	// Close the store: every subsequent Exec fails (fcDB's cleanup close is
	// idempotent).
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// A failed upsert must NOT stamp memory: the pre-failure entry (the
	// durable row's mirror) stays, so the next tick re-reads and retries.
	pw.setAlertState(context.Background(), id, "up", time.Now().UTC())
	pw.alertMemMu.Lock()
	entry, ok := pw.alertMem[id]
	pw.alertMemMu.Unlock()
	if !ok {
		t.Fatal("alertMem entry vanished after failed write, want the pre-failure entry retained")
	}
	if entry.status != "error" {
		t.Fatalf("failed write stamped memory: status = %q, want %q (pre-failure value)", entry.status, "error")
	}
}
