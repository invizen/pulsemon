package main

// Entering maintenance mode reads the active-sensor snapshot INSIDE the pause
// transaction (a pre-tx read let sensors activated in the gap keep probing).

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestEnterMaintenanceWithFreshSnapshot(t *testing.T) {
	d := newTestDB(t)
	ins := func(id, state string) {
		if _, err := d.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
			VALUES (?, ?, '127.0.0.1', 60, 1000, 25, 3, 3, ?, 'up', ?)`,
			id, id, state, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}
	ins("a1", "active")
	ins("a2", "active")
	ins("p1", "paused")

	ids, err := d.EnterMaintenanceWithFreshSnapshot(context.Background())
	if err != nil {
		t.Fatalf("EnterMaintenanceWithFreshSnapshot: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("paused ids = %v, want the 2 active sensors", ids)
	}
	var paused, stillActive int
	if err := d.QueryRow(`SELECT COUNT(*) FROM sensors WHERE state='paused'`).Scan(&paused); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT COUNT(*) FROM sensors WHERE state='active'`).Scan(&stillActive); err != nil {
		t.Fatal(err)
	}
	if paused != 3 || stillActive != 0 {
		t.Fatalf("states wrong: paused=%d active=%d (want 3/0; p1 was already paused)", paused, stillActive)
	}
	if mode := d.GetSetting("maintenance_mode"); mode != "1" {
		t.Fatalf("maintenance_mode = %q, want 1", mode)
	}
	var snap []string
	if err := json.Unmarshal([]byte(d.GetSetting("maintenance_active_ids")), &snap); err != nil {
		t.Fatalf("snapshot not valid JSON: %v (%q)", err, d.GetSetting("maintenance_active_ids"))
	}
	if len(snap) != 2 {
		t.Fatalf("snapshot = %v, want the 2 previously-active ids", snap)
	}
}

// Leaving maintenance is the mirror: the restore-set snapshot is read
// INSIDE the resume transaction. A snapshot that fails to decode is a
// HARD failure — mode stays ON, the snapshot stays on disk, sensors stay
// paused, and the operator can fix the value and retry. Pre-fix
// (2026-11-16 review M1) the handler read it with the swallow-to-""
// GetSetting and a failed read/decode resumed NOTHING while wiping the
// snapshot and the banner: every maintenance-paused sensor stranded
// forever with no record of the set.

func TestLeaveMaintenanceFromSnapshot(t *testing.T) {
	d := newTestDB(t)
	ins := func(id, state string) {
		if _, err := d.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
			VALUES (?, ?, '127.0.0.1', 60, 1000, 25, 3, 3, ?, 'up', ?)`,
			id, id, state, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}
	ins("a1", "active")
	ins("a2", "active")
	ins("p1", "paused")

	if _, err := d.EnterMaintenanceWithFreshSnapshot(context.Background()); err != nil {
		t.Fatalf("enter: %v", err)
	}
	resumed, err := d.LeaveMaintenanceFromSnapshot(context.Background())
	if err != nil {
		t.Fatalf("LeaveMaintenanceFromSnapshot: %v", err)
	}
	if len(resumed) != 2 {
		t.Fatalf("resumed ids = %v, want the 2 snapshotted sensors", resumed)
	}
	var active, paused int
	if err := d.QueryRow(`SELECT COUNT(*) FROM sensors WHERE state='active'`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT COUNT(*) FROM sensors WHERE state='paused'`).Scan(&paused); err != nil {
		t.Fatal(err)
	}
	if active != 2 || paused != 1 {
		t.Fatalf("states wrong: active=%d paused=%d (want 2/1; p1 was user-paused)", active, paused)
	}
	if mode := d.GetSetting("maintenance_mode"); mode != "0" {
		t.Fatalf("maintenance_mode = %q, want 0", mode)
	}
	if snap := d.GetSetting("maintenance_active_ids"); snap != "" {
		t.Fatalf("snapshot = %q after leave, want cleared", snap)
	}
}

func TestLeaveMaintenanceUndecodableSnapshotFailsLoud(t *testing.T) {
	d := newTestDB(t)
	if _, err := d.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('a1', 'alpha', '127.0.0.1', 60, 1000, 25, 3, 3, 'active', 'up', ?)`,
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := d.EnterMaintenanceWithFreshSnapshot(context.Background()); err != nil {
		t.Fatalf("enter: %v", err)
	}
	// Corrupt the snapshot the way a torn write / manual edit would.
	const garbage = `{"not":"a list of ids"`
	if err := d.SetSetting("maintenance_active_ids", garbage); err != nil {
		t.Fatal(err)
	}

	if _, err := d.LeaveMaintenanceFromSnapshot(context.Background()); err == nil {
		t.Fatal("leave with an undecodable snapshot: want an error, got nil (the silent-wipe regression is back)")
	}
	if mode := d.GetSetting("maintenance_mode"); mode != "1" {
		t.Errorf("maintenance_mode = %q after the failed leave, want 1 (mode must stay ON; the banner must NOT vanish)", mode)
	}
	if snap := d.GetSetting("maintenance_active_ids"); snap != garbage {
		t.Errorf("snapshot = %q after the failed leave, want %q intact for inspection", snap, garbage)
	}
	var state string
	if err := d.QueryRow(`SELECT state FROM sensors WHERE id='a1'`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "paused" {
		t.Errorf("a1 = %s after the failed leave, want paused (tx must roll back whole)", state)
	}
}

// A flag ON with NO snapshot row at all (a pre-rework DB) is not a
// failure: there is no restore set to lose, so leave resumes nothing and
// clears the flag cleanly. Only a PRESENT-but-undecodable value is fatal.
func TestLeaveMaintenanceMissingSnapshotIsNotAnError(t *testing.T) {
	d := newTestDB(t)
	if _, err := d.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('a1', 'alpha', '127.0.0.1', 60, 1000, 25, 3, 3, 'active', 'up', ?)`,
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := d.SetSetting("maintenance_mode", "1"); err != nil {
		t.Fatal(err)
	}

	resumed, err := d.LeaveMaintenanceFromSnapshot(context.Background())
	if err != nil {
		t.Fatalf("leave with no snapshot row: %v, want success", err)
	}
	if len(resumed) != 0 {
		t.Fatalf("resumed = %v, want nothing to resume", resumed)
	}
	if mode := d.GetSetting("maintenance_mode"); mode != "0" {
		t.Fatalf("maintenance_mode = %q, want 0", mode)
	}
	var state string
	if err := d.QueryRow(`SELECT state FROM sensors WHERE id='a1'`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "active" {
		t.Errorf("a1 = %s, want active (untouched)", state)
	}
}
