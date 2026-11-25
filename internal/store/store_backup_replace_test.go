package store

import (
	"os"
	"path/filepath"
	"testing"
)

// CRITICAL-2 (2026-11-25): VACUUM INTO REFUSES an existing target file
// ("output file already exists"), so the second (or Nth) pre-update
// backup used to fail — leaving the FIRST, possibly months-old, snapshot
// on disk. BackupTo must write to a fresh sibling .tmp and rename it into
// place: every backup succeeds and the snapshot carries CURRENT data.

func TestStoreBackupToReplacesExistingSnapshot(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "pulsemon.db")
	s, err := NewStore(src)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer s.Close()
	if err := s.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	seed := func(name string) {
		t.Helper()
		id := NewID()
		if _, err := s.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, state, status, created_at)
			VALUES (?, ?, ?, 60, 1000, 25, 2, 'paused', 'up', ?)`, id, name, "127.0.0.1", Now()); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	backup := filepath.Join(dir, "pulsemon.db.preupdate")

	// Update #1: fresh dst (the shape that already worked).
	for _, name := range []string{"a", "b", "c"} {
		seed(name)
	}
	if err := s.BackupTo(backup); err != nil {
		t.Fatalf("first BackupTo: %v", err)
	}

	// Update #2: the dst EXISTS. The old code failed here with
	// "output file already exists" and left the 3-sensor snapshot.
	if _, err := s.Exec(`DELETE FROM sensors WHERE name = 'a'`); err != nil {
		t.Fatal(err)
	}
	if err := s.BackupTo(backup); err != nil {
		t.Fatalf("second BackupTo over an existing snapshot: %v (the CRITICAL-2 defect)", err)
	}

	// The snapshot must be the FRESH 2-sensor DB, not the stale 3.
	b, err := NewStore(backup)
	if err != nil {
		t.Fatalf("NewStore(backup): %v", err)
	}
	defer b.Close()
	got, err := b.SensorCount()
	if err != nil {
		t.Fatalf("backup SensorCount: %v", err)
	}
	if got != 2 {
		t.Fatalf("backup SensorCount = %d, want 2 (the replaced snapshot must carry the new state, not the stale one)", got)
	}

	// No .tmp orphan may survive a successful backup.
	if _, err := os.Stat(backup + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("a .tmp orphan survived the backup (stat err=%v)", err)
	}
}

// NewStoreReadOnly must open a VACUUM INTO snapshot in a mode that (a)
// reads, (b) REFUSES writes, and (c) creates no -wal/-shm sidecars (a
// read-write WAL open creates them beside the snapshot and can strand
// uncheckpointed frames if the process dies mid-open). The `file:` URI
// DSN form is load-bearing: the bare `path?mode=ro` DSN is opened
// READWRITE|CREATE by modernc.org/sqlite (probe-verified 2026-11-25), so
// this test is the guard against regressing to the bare form.
func TestStoreReadOnlyRefusesWritesAndSidecars(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "pulsemon.db")
	s, err := NewStore(src)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
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
	s.Close()

	ro, err := NewStoreReadOnly(backup)
	if err != nil {
		t.Fatalf("NewStoreReadOnly: %v", err)
	}
	defer ro.Close()
	got, err := ro.SensorCount()
	if err != nil {
		t.Fatalf("read-only SensorCount: %v", err)
	}
	if got != 3 {
		t.Fatalf("read-only SensorCount = %d, want 3", got)
	}
	if _, err := ro.Exec("CREATE TABLE ro_probe (id INTEGER)"); err == nil {
		t.Fatal("read-only store accepted a write — the safety copy is not protected")
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(backup + suffix); err == nil {
			t.Errorf("sidecar %s created by the read-only open (a WAL sidecar can strand uncheckpointed frames)", suffix)
		}
	}
}

// mode=ro must NOT create a missing file (a read-write open would).
func TestStoreReadOnlyMissingFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "no-such-snapshot.db")
	if _, err := NewStoreReadOnly(missing); err == nil {
		t.Fatal("NewStoreReadOnly of a missing file succeeded — mode=ro must not create files")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Errorf("NewStoreReadOnly created the missing file (stat err=%v)", err)
	}
}
