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
