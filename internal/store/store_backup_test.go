package store

import (
	"path/filepath"
	"testing"
)

// Pre-update backup (windows-upgrade-safety, 2026-11-23): BackupTo must
// produce a consistent, SELF-CONTAINED snapshot (VACUUM INTO) that is
// valid while the source store is actively serving, and that does not
// drift from writes made AFTER the backup.

func TestStoreBackupToSnapshotIsConsistent(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "pulsemon.db")
	s, err := NewStore(src)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	// Three sensors, exactly as db_test.go seeds them.
	for _, name := range []string{"a", "b", "c"} {
		id := NewID()
		if _, err := s.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, state, status, created_at)
			VALUES (?, ?, ?, 60, 1000, 25, 2, 'paused', 'up', ?)`, id, name, "127.0.0.1", Now()); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	backup := filepath.Join(dir, "pulsemon.db.preupdate")
	if err := s.BackupTo(backup); err != nil {
		t.Fatalf("BackupTo: %v", err)
	}

	// A write AFTER the backup must not leak into the snapshot.
	id := NewID()
	if _, err := s.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, state, status, created_at)
		VALUES (?, ?, ?, 60, 1000, 25, 2, 'paused', 'up', ?)`, id, "late", "127.0.0.1", Now()); err != nil {
		t.Fatalf("late insert: %v", err)
	}
	live, err := s.SensorCount()
	if err != nil {
		t.Fatalf("live SensorCount: %v", err)
	}
	if live != 4 {
		t.Fatalf("live SensorCount = %d, want 4", live)
	}

	// The snapshot is a standalone DB (opens without the source) with the
	// pre-backup count.
	s.Close()
	b, err := NewStore(backup)
	if err != nil {
		t.Fatalf("NewStore(backup): %v", err)
	}
	defer b.Close()
	got, err := b.SensorCount()
	if err != nil {
		t.Fatalf("backup SensorCount: %v", err)
	}
	if got != 3 {
		t.Fatalf("backup SensorCount = %d, want 3 (snapshot must not include post-backup writes)", got)
	}
}
