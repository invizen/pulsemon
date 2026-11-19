package main

// Finding #11 (2026-11-19): setAlertState bypassed the capped probe-write
// handle and stamped alertMem for deleted sensors; maybeRealert left
// alertMem cold on cache miss (a SQLite SELECT per tick) and reset the
// re-alert clock on ANY db error, not just a missing row.

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"pulsemon/internal/store"
)

// TestSetAlertStateRoutesCappedProbeHandle: setAlertState is on the probe
// hot path (doProbe, maybeRealert), so its write must run on the capped
// probe-write handle (ProbeExecContext, busy_timeout =
// store.ProbeWriteTimeout), not the main pool (busy_timeout 15s) — a
// stalled writer must park the sensor loop for the cap, not 8s + 15s.
// Close ONLY the main pool: a write routed to the main pool fails, one on
// the probe handle succeeds.
func TestSetAlertStateRoutesCappedProbeHandle(t *testing.T) {
	dir := t.TempDir()
	db, err := store.NewStore(filepath.Join(dir, "probe-handle.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	const id = "s-probehdl"
	fcSensor(t, db, id, "probehdl", "active")
	pw := NewProbeWorker(db)

	// Close ONLY the main pool; the probe handle stays open.
	if err := db.DB.Close(); err != nil {
		t.Fatal(err)
	}

	pw.setAlertState(context.Background(), id, "error", time.Now().UTC())

	pw.alertMemMu.Lock()
	_, ok := pw.alertMem[id]
	pw.alertMemMu.Unlock()
	if !ok {
		t.Fatal("setAlertState did not stamp alertMem — the write must route the capped probe handle, not the (closed) main pool")
	}

	// The durable row landed (verified on a fresh raw connection to the
	// same file).
	raw, err := sql.Open("sqlite", filepath.Join(dir, "probe-handle.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var status string
	if err := raw.QueryRow(`SELECT status FROM alert_state WHERE sensor_id = ?`, id).Scan(&status); err != nil {
		t.Fatalf("no durable alert_state row after setAlertState: %v", err)
	}
	if status != "error" {
		t.Fatalf("durable status = %q, want %q", status, "error")
	}
}

// TestSetAlertStateDeletedSensorNoMemGhost: a guarded upsert that matches
// no sensor row (concurrent delete) writes nothing (RowsAffected = 0) and
// must NOT stamp the in-memory copy — pre-fix the stamp was
// unconditional, leaving a ghost alertMem entry for a deleted sensor.
func TestSetAlertStateDeletedSensorNoMemGhost(t *testing.T) {
	db := fcDB(t)
	pw := NewProbeWorker(db)
	const id = "s-ghost" // no sensor row

	pw.setAlertState(context.Background(), id, "error", time.Now().UTC())

	pw.alertMemMu.Lock()
	_, ok := pw.alertMem[id]
	pw.alertMemMu.Unlock()
	if ok {
		t.Fatal("ghost alertMem entry for a sensor with no sensors row (RowsAffected=0 must not stamp)")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM alert_state WHERE sensor_id = ?`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("alert_state rows for the missing sensor = %d, want 0", n)
	}

	// Positive control: a live sensor stamps both the durable row and
	// memory.
	fcSensor(t, db, "s-real", "real", "active")
	pw.setAlertState(context.Background(), "s-real", "error", time.Now().UTC())
	pw.alertMemMu.Lock()
	_, ok = pw.alertMem["s-real"]
	pw.alertMemMu.Unlock()
	if !ok {
		t.Fatal("live sensor: alertMem entry missing, want stamped")
	}
}

// TestMaybeRealertPopulatesAlertMemOnCacheMiss: with a COLD alertMem and a
// durable row (same status, ts inside the re-alert interval), the first
// tick performs one SELECT and STAMPS the in-memory copy, and steady
// ticks hit zero SELECTs. Pre-fix the early-return paths (alert-once-only,
// interval not elapsed) never wrote, so a cold process re-queried SQLite
// on every tick for the whole re-alert interval.
func TestMaybeRealertPopulatesAlertMemOnCacheMiss(t *testing.T) {
	db := fcDB(t)
	const id = "s-coldmem"
	fcSensor(t, db, id, "coldmem", "active")
	if _, err := db.Exec(`INSERT INTO alert_state (sensor_id, status, last_ts) VALUES (?, 'error', ?)`, id, store.Now()); err != nil {
		t.Fatal(err)
	}
	pw := NewProbeWorker(db)

	lookups := 0
	orig := alertStateSelect
	t.Cleanup(func() { alertStateSelect = orig })
	alertStateSelect = func(db *store.Store, id string) (string, string, error) {
		lookups++
		return orig(db, id)
	}

	c := sensorConfig{id: id, name: "coldmem"}
	pw.maybeRealert(context.Background(), c, "error", 0)
	if lookups != 1 {
		t.Fatalf("cold tick did %d lookups, want 1", lookups)
	}
	pw.alertMemMu.Lock()
	_, inMem := pw.alertMem[id]
	pw.alertMemMu.Unlock()
	if !inMem {
		t.Fatal("cold-cache read did not populate alertMem — steady ticks will re-query SQLite every tick")
	}
	before := lookups
	pw.maybeRealert(context.Background(), c, "error", 0)
	pw.maybeRealert(context.Background(), c, "error", 0)
	if lookups != before {
		t.Fatalf("steady ticks did %d alert_state lookups, want 0 (the cache never warmed)", lookups-before)
	}
}

// TestMaybeRealertTransientDBErrorDoesNotSeed: a TRANSIENT db error from
// the alert_state read (BUSY, I/O, deadline) must NOT seed alert_state
// with "now" — pre-fix every error was treated like a missing row and
// reset the re-alert clock, suppressing an imminent re-alert. Only
// sql.ErrNoRows (a genuinely missing row) seeds.
func TestMaybeRealertTransientDBErrorDoesNotSeed(t *testing.T) {
	db := fcDB(t)
	const id = "s-transient"
	fcSensor(t, db, id, "transient", "active")
	pw := NewProbeWorker(db)

	orig := alertStateSelect
	t.Cleanup(func() { alertStateSelect = orig })
	alertStateSelect = func(db *store.Store, id string) (string, string, error) {
		return "", "", errors.New("SQLITE_BUSY (transient)")
	}
	c := sensorConfig{id: id, name: "transient"}
	pw.maybeRealert(context.Background(), c, "error", 0)

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM alert_state WHERE sensor_id = ?`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("transient db error seeded alert_state (%d rows) — only a missing row may seed", n)
	}
	pw.alertMemMu.Lock()
	_, inMem := pw.alertMem[id]
	pw.alertMemMu.Unlock()
	if inMem {
		t.Fatal("transient db error stamped alertMem — the durable row must stay authoritative")
	}

	// Positive control: a genuine missing row (sql.ErrNoRows) DOES seed.
	alertStateSelect = orig
	pw.maybeRealert(context.Background(), c, "error", 0)
	if err := db.QueryRow(`SELECT COUNT(*) FROM alert_state WHERE sensor_id = ?`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("missing row did not seed alert_state (rows=%d, want 1)", n)
	}
}
