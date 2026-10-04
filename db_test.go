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

// TestSetSensorTagsAtomic locks the transactional tag replacement: when an
// insert fails MID-LOOP (simulated with a BEFORE-INSERT trigger that
// RAISE(ABORT)s on one specific tag), the whole operation rolls back — the
// sensor keeps its ORIGINAL tags, never an empty or partial set. A torn set
// is the real-world harm: with alert_scope='tags' it silently changes which
// sensors alert. This test fails against the old delete-then-insert code
// (delete committed, partial/empty set left behind).
func TestSetSensorTagsAtomic(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "atomic.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, state, status, created_at)
		VALUES ("a","a","127.0.0.1",5,1000,25,4,'active','up','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("seed sensor: %v", err)
	}
	original := []string{"one", "two"}
	if err := db.SetSensorTags("a", original); err != nil {
		t.Fatalf("initial SetSensorTags: %v", err)
	}

	// Force a mid-loop failure: any insert of tag "bad" aborts.
	if _, err := db.Exec(`CREATE TRIGGER tagblock BEFORE INSERT ON sensor_tags
		FOR EACH ROW WHEN NEW.tag = 'bad'
		BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	defer db.Exec(`DROP TRIGGER IF EXISTS tagblock`)

	// Replace [one, two] with [three, bad, four]: "bad" is the 2nd insert,
	// so the delete and the "three" insert have already run when it fires.
	err = db.SetSensorTags("a", []string{"three", "bad", "four"})
	if err == nil {
		t.Fatal("SetSensorTags with failing insert: expected an error")
	}

	got := db.SensorTags("a")
	if !equalTags(got, original) {
		t.Errorf("after rolled-back replacement, tags = %v, want original %v (must not be empty or partial)", got, original)
	}

	// The trigger must NOT leak into later successful updates.
	if err := db.SetSensorTags("a", []string{"three", "four"}); err != nil {
		t.Fatalf("post-rollback SetSensorTags: %v", err)
	}
	if got := db.SensorTags("a"); !equalTags(got, []string{"four", "three"}) {
		t.Errorf("replacement tags = %v, want [four three] (sorted)", got)
	}
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

// TestStatusRenameMigrationIsNoOpWhenMigrated locks the WHERE-filter fix on
// the v0.1.13 status-rename migration. The old code ran
// `UPDATE ... SET col = CASE ... ELSE col END` with NO WHERE, so it matched
// EVERY row and — in SQLite — re-assigned+re-wrote each one even where the
// value was unchanged. On a fully-migrated DB that forced a full-table WAL
// write on every single boot, churning pages and blocking active probe writes
// (WAL has one writer). This test proves the fix: after a migration has
// already run, a re-InitSchema (a fresh process boot) must write ZERO rows.
//
// It uses SQLite's total_changes() counter (rows modified since connection
// open) as a delta around the re-InitSchema. Against the old unfiltered
// UPDATEs the delta is > 0 (every row rewritten); with the WHERE filter it
// is exactly 0.
func TestStatusRenameMigrationIsNoOpWhenMigrated(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "noop.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// Seed rows the way a pre-v0.1.13 install would have left them: legacy
	// statuses in all four tables plus a legacy note, so the FIRST re-run
	// below genuinely has work to do.
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

	changes := func() (int64, error) {
		var n int64
		return n, db.QueryRow(`SELECT total_changes()`).Scan(&n)
	}

	// FIRST re-run: the migration must actually do work (rename the legacy
	// rows). This guards that adding the WHERE didn't accidentally skip the
	// real migration.
	before, err := changes()
	if err != nil {
		t.Fatalf("total_changes: %v", err)
	}
	if err := db.InitSchema(); err != nil {
		t.Fatalf("migration InitSchema: %v", err)
	}
	after, err := changes()
	if err != nil {
		t.Fatalf("total_changes: %v", err)
	}
	if after <= before {
		t.Fatalf("migration re-run wrote %d rows, want > 0 (the rename must actually apply on first run)", after-before)
	}
	// Sanity: the rename did happen.
	var st1 string
	if err := db.QueryRow(`SELECT status FROM sensors WHERE id='s1'`).Scan(&st1); err != nil {
		t.Fatalf("s1 status: %v", err)
	}
	if st1 != "error" {
		t.Fatalf("after migration s1 = %q, want error", st1)
	}

	// SECOND re-run (a boot on an already-migrated DB): must write ZERO rows.
	// Old unfiltered code rewrites every row here (delta > 0) — this is the
	// regression the fix eliminates.
	before2, err := changes()
	if err != nil {
		t.Fatalf("total_changes: %v", err)
	}
	if err := db.InitSchema(); err != nil {
		t.Fatalf("second InitSchema: %v", err)
	}
	after2, err := changes()
	if err != nil {
		t.Fatalf("total_changes: %v", err)
	}
	if delta := after2 - before2; delta != 0 {
		t.Errorf("re-InitSchema on migrated DB wrote %d rows, want 0 (unfiltered UPDATEs rewrite the whole table every boot)", delta)
	}
}
