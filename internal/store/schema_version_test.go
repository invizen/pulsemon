package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := NewStore(filepath.Join(t.TempDir(), "schema.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return db
}

func getUserVersion(t *testing.T, db *Store) int {
	t.Helper()
	v, err := db.schemaVersion()
	if err != nil {
		t.Fatalf("schemaVersion: %v", err)
	}
	return v
}

// TestSchemaVersionStampedOnFresh: a fresh DB baselines at the current
// schema, replays every numbered migration as a guarded no-op, and lands
// stamped at the head. Re-running InitSchema is a pure skip.
func TestSchemaVersionStampedOnFresh(t *testing.T) {
	db := openTestStore(t)
	if v := getUserVersion(t, db); v != schemaVersionHead {
		t.Fatalf("fresh DB user_version = %d, want head %d (all migrations replayed + stamped)", v, schemaVersionHead)
	}
	if err := db.InitSchema(); err != nil {
		t.Fatalf("second InitSchema: %v", err)
	}
	if v := getUserVersion(t, db); v != schemaVersionHead {
		t.Fatalf("re-run user_version = %d, want %d (re-run must be a pure skip)", v, schemaVersionHead)
	}
}

// TestTagMigrationReplayFromZero drives migration 1 end-to-end on a
// stamped DB: re-add the legacy sensors.tag column with rows, reset
// user_version to 0 (the state of every pre-versioning DB), and re-run
// InitSchema. The copy+DROP must land atomically, the tags must be in
// sensor_tags, the tag column must be gone, and the version must return
// to the head. This is the replay-safety proof: replaying the whole
// numbered list over an already-migrated DB is a no-op EXCEPT where
// legacy shapes are (re-)introduced.
func TestTagMigrationReplayFromZero(t *testing.T) {
	db := openTestStore(t)
	if _, err := db.Exec(`ALTER TABLE sensors ADD COLUMN tag TEXT`); err != nil {
		t.Fatal(err)
	}
	now := Now()
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, state, status, created_at, tag)
		VALUES ('s1', 's1', '10.0.0.1', 30, 1000, 25, 2, 'active', 'up', ?, 'edge')`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 0`); err != nil {
		t.Fatal(err)
	}
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema replay: %v", err)
	}
	var tags int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensor_tags WHERE sensor_id='s1' AND tag='edge'`).Scan(&tags); err != nil || tags != 1 {
		t.Fatalf("tag row after replay: count=%d err=%v, want 1", tags, err)
	}
	var col int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sensors') WHERE name='tag'`).Scan(&col); err != nil || col != 0 {
		t.Fatalf("legacy tag column after replay: present=%d err=%v, want dropped", col, err)
	}
	if v := getUserVersion(t, db); v != schemaVersionHead {
		t.Fatalf("user_version after replay = %d, want head %d", v, schemaVersionHead)
	}
}

// TestMigrationAtomicRollback pins the framework guarantee the finding
// asked for: a step that fails AFTER it has written must roll its
// writes back AND leave user_version unstamped — the exact half-applied
// crash window the old non-transactional tag migration had (there, only
// INSERT OR IGNORE's dedup made the replay survivable; a step without
// that trick was a crash-loop).
func TestMigrationAtomicRollback(t *testing.T) {
	db := openTestStore(t)
	before := getUserVersion(t, db)
	boom := errors.New("injected failure")
	err := db.applyMigration(99, schemaMigration{
		name: "test/injected",
		run: func(db *Store, tx *sql.Tx) error {
			if _, err := tx.Exec(`INSERT INTO settings (setting_key, value) VALUES ('atomic_probe', 'x')`); err != nil {
				return err
			}
			return boom
		},
	})
	if err == nil {
		t.Fatal("applyMigration must propagate the step failure")
	}
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "schema migration 99") {
		t.Fatalf("error = %v, want wrapped injected failure naming the migration", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM settings WHERE setting_key='atomic_probe'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("step writes survived rollback: n=%d err=%v, want 0 (step + stamp must be atomic)", n, err)
	}
	if v := getUserVersion(t, db); v != before {
		t.Fatalf("user_version stamped for a rolled-back migration: %d != %d", v, before)
	}
}
