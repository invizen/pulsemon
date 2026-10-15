//go:build linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// M3: the data dir holds the SQLite DB with bcrypt hashes and the settings
// table with plaintext webhook/Telegram/SMTP secrets. The pre-fix defaults
// (MkdirAll 0o755, SQLite files 0644) left it world-readable. After
// hardenDataDir the dir must be 0700 and the DB/WAL files 0600.
func TestFix_M3_DataDirHardened(t *testing.T) {
	dir := t.TempDir()
	// Simulate a pre-existing world-readable data dir with a 0644 DB and
	// WAL sidecar files (the pre-fix state on an upgraded install).
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "pulsemon.db")
	for _, f := range []string{"pulsemon.db", "pulsemon.db-wal", "pulsemon.db-shm"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	hardenDataDir(dbPath)

	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0o700 {
		t.Errorf("data dir mode = %o, want 0700", got)
	}
	for _, f := range []string{"pulsemon.db", "pulsemon.db-wal", "pulsemon.db-shm"} {
		fst, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if got := fst.Mode().Perm(); got != 0o600 {
			t.Errorf("%s mode = %o, want 0600", f, got)
		}
	}
}

// A fresh DB has no -wal/-shm files (WAL not active): hardenDataDir must
// tighten what exists and not complain about what doesn't.
func TestFix_M3_DataDirNoWALFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pulsemon.db"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	hardenDataDir(filepath.Join(dir, "pulsemon.db"))

	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0o700 {
		t.Errorf("data dir mode = %o, want 0700", got)
	}
	fst, err := os.Stat(filepath.Join(dir, "pulsemon.db"))
	if err != nil {
		t.Fatal(err)
	}
	if got := fst.Mode().Perm(); got != 0o600 {
		t.Errorf("pulsemon.db mode = %o, want 0600", got)
	}
}

// M3b: ensureDataDir must harden the directory of the DB ACTUALLY in use.
// With PULSEMON_DB pointing at a non-default path (custom base name), the
// pre-fix code hardened /data and the literal pulsemon.db names — so the
// real DB dir stayed 0755 and its files 0644. Now the dir of
// dbPathFromEnv() is created 0700 and the actual DB + sidecars 0600.
func TestFix_M3b_HardensDirOfDBInUse(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "custom-name.db") // non-default base name
	t.Setenv("PULSEMON_DB", dbPath)

	// Pre-existing world-readable dir with 0644 DB + WAL sidecars.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// ensureDataDir sets a process-wide umask(077); restore the previous
	// value so later tests (which assert on file modes) are unaffected.
	prevUmask := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(prevUmask) })

	ensureDataDir()

	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0o700 {
		t.Errorf("dir of PULSEMON_DB mode = %o, want 0700", got)
	}
	for _, f := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		fst, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if got := fst.Mode().Perm(); got != 0o600 {
			t.Errorf("%s mode = %o, want 0600", f, got)
		}
	}
}
