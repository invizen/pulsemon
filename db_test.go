package main

import (
	"path/filepath"
	"testing"
)

// TestSensorTagsFor locks the batched tag fetch: one query returns every
// sensor's sorted tags, comma-containing tags survive intact (the reason
// this uses an IN-list instead of GROUP_CONCAT), and empty input is safe.
func TestSensorTagsFor(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "tags.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	// Use names as ids here for readability (schema allows any TEXT id).
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, state, status, created_at)
		VALUES ('a','a','127.0.0.1',5,1000,25,4,'active','up','2026-01-01T00:00:00Z'),
		           ('b','b','127.0.0.1',5,1000,25,4,'active','up','2026-01-01T00:00:00Z'),
		           ('c','c','127.0.0.1',5,1000,25,4,'active','up','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("seed sensors: %v", err)
	}
	if err := db.SetSensorTags("a", []string{"Linux Servers", "Core, Network"}); err != nil { // comma in tag
		t.Fatalf("tags a: %v", err)
	}
	if err := db.SetSensorTags("b", []string{"Zeta", "Alpha"}); err != nil { // out-of-order, tests sort
		t.Fatalf("tags b: %v", err)
	}
	// c intentionally has no tags.

	got := db.SensorTagsFor([]string{"a", "b", "c"})
	if len(got) != 2 {
		t.Fatalf("len(map) = %d, want 2 (untagged sensor absent)", len(got))
	}
	if want := []string{"Core, Network", "Linux Servers"}; !equalTags(got["a"], want) {
		t.Errorf("a = %v, want %v (comma tag must survive, sorted)", got["a"], want)
	}
	if want := []string{"Alpha", "Zeta"}; !equalTags(got["b"], want) {
		t.Errorf("b = %v, want %v (sorted)", got["b"], want)
	}

	// Empty input: no query, empty map.
	if m := db.SensorTagsFor(nil); len(m) != 0 {
		t.Errorf("nil input: got %v, want empty map", m)
	}
	// Unknown ids: empty map entries, no error.
	if m := db.SensorTagsFor([]string{"nope"}); len(m) != 0 {
		t.Errorf("unknown id: got %v, want empty map", m)
	}
}

func equalTags(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestStatusRenameMigration locks the one-time v0.1.13 migration: existing
// databases store "down"/"degraded" in sensors, events, and alert_state.
// After InitSchema, all must be renamed to "error"/"warning" so the first
// post-upgrade probe does not log a spurious transition or fire a one-time
// alert on every already-affected sensor.
func TestStatusRenameMigration(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "migration.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// Seed rows the way an OLD-version zenmon would have left them.
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, state, status, created_at)
		VALUES ('s1','s1','127.0.0.1',15,1000,25,4,'active','down','2026-01-01T00:00:00Z'),
		           ('s2','s2','127.0.0.1',15,1000,25,4,'active','degraded','2026-01-01T00:00:00Z'),
		           ('s3','s3','127.0.0.1',15,1000,25,4,'active','up','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("seed sensors: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO events (sensor_id, ts, from_status, to_status, note) VALUES
		('s1','2026-01-01T00:01:00Z','up','down','up -> down'),
		('s2','2026-01-01T00:02:00Z','up','degraded','up -> degraded')`); err != nil {
		t.Fatalf("seed events: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO alert_state (sensor_id, status, last_ts) VALUES
		('s1','down','2026-01-01T00:01:00Z'),('s2','degraded','2026-01-01T00:02:00Z')`); err != nil {
		t.Fatalf("seed alert_state: %v", err)
	}

	// Re-running InitSchema (as a fresh process start would) applies the rename.
	if err := db.InitSchema(); err != nil {
		t.Fatalf("re-InitSchema: %v", err)
	}

	check := func(table, col, id, want string) {
		t.Helper()
		var got string
		q := `SELECT ` + col + ` FROM ` + table + ` WHERE sensor_id = ?`
		if table == "sensors" {
			q = `SELECT status FROM sensors WHERE id = ?`
		}
		if err := db.QueryRow(q, id).Scan(&got); err != nil {
			t.Fatalf("query %s.%s for %s: %v", table, col, id, err)
		}
		if got != want {
			t.Errorf("%s.%s[%s] = %q, want %q", table, col, id, got, want)
		}
	}

	check("sensors", "status", "s1", "error")
	check("sensors", "status", "s2", "warning")
	check("sensors", "status", "s3", "up")

	var from, to string
	if err := db.QueryRow(`SELECT from_status, to_status FROM events WHERE sensor_id = 's1'`).Scan(&from, &to); err != nil {
		t.Fatalf("events s1: %v", err)
	}
	if from != "up" || to != "error" {
		t.Errorf("events s1 = %s -> %s, want up -> error", from, to)
	}
	if err := db.QueryRow(`SELECT from_status, to_status FROM events WHERE sensor_id = 's2'`).Scan(&from, &to); err != nil {
		t.Fatalf("events s2: %v", err)
	}
	if from != "up" || to != "warning" {
		t.Errorf("events s2 = %s -> %s, want up -> warning", from, to)
	}

	// Historical notes ("up -> degraded", "up -> down") get the same rename.
	var note1, note2 string
	if err := db.QueryRow(`SELECT note FROM events WHERE sensor_id = 's1'`).Scan(&note1); err != nil {
		t.Fatalf("events s1 note: %v", err)
	}
	if note1 != "up -> error" {
		t.Errorf("events s1 note = %q, want %q", note1, "up -> error")
	}
	if err := db.QueryRow(`SELECT note FROM events WHERE sensor_id = 's2'`).Scan(&note2); err != nil {
		t.Fatalf("events s2 note: %v", err)
	}
	if note2 != "up -> warning" {
		t.Errorf("events s2 note = %q, want %q", note2, "up -> warning")
	}

	check("alert_state", "status", "s1", "error")
	check("alert_state", "status", "s2", "warning")

	// Idempotency: a second pass must not error or double-translate.
	if err := db.InitSchema(); err != nil {
		t.Fatalf("second re-InitSchema: %v", err)
	}
	check("sensors", "status", "s1", "error")
	check("sensors", "status", "s2", "warning")
}
