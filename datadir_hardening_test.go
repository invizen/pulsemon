//go:build linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// M3 (as re-scoped by F15/N1, 2026-10-19 review): the data dir holds the
// SQLite DB with bcrypt hashes and the settings table with plaintext
// webhook/Telegram/SMTP secrets. A dir THIS process creates must land at
// 0700 and the DB/WAL files at 0600. (The pre-F15 variant of this test
// asserted that a PRE-EXISTING 0755 dir gets tightened to 0700 — that is
// exactly the footgun F15 removes: a shared parent must keep its mode.)
func TestFix_M3_DataDirHardened(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "datadir") // does not exist yet
	dbPath := filepath.Join(dir, "pulsemon.db")
	t.Setenv("PULSEMON_DB", dbPath)

	prevUmask := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(prevUmask) })

	if err := ensureDataDir(); err != nil {
		t.Fatal(err)
	}

	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0o700 {
		t.Errorf("created data dir mode = %o, want 0700", got)
	}
	// The DB is created by store.NewStore with the umask in effect; simulate it
	// here and verify the file-tightening pass.
	if err := os.WriteFile(dbPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	hardenDataDirFiles(dbPath)
	fst, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := fst.Mode().Perm(); got != 0o600 {
		t.Errorf("pulsemon.db mode = %o, want 0600", got)
	}
}

// F15/N1: a PRE-EXISTING parent dir keeps its mode. The pre-fix code
// tightened a shared /data (0755, other apps' files inside) to 0700,
// locking out the other tenants. ensureDataDir must now leave it alone
// while still tightening the DB files it owns.
func TestFix_M3_DataDirPreExistingParentKeepsMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "pulsemon.db")
	t.Setenv("PULSEMON_DB", dbPath)
	for _, f := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	prevUmask := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(prevUmask) })

	if err := ensureDataDir(); err != nil {
		t.Fatal(err)
	}

	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0o755 {
		t.Errorf("pre-existing parent mode = %o, want 0755 unchanged (F15)", got)
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

// A fresh DB has no -wal/-shm files (WAL not active): the file-tightening
// pass must tighten what exists and not complain about what doesn't.
func TestFix_M3_DataDirNoWALFiles(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pulsemon.db")
	if err := os.WriteFile(dbPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	hardenDataDirFiles(dbPath)

	fst, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := fst.Mode().Perm(); got != 0o600 {
		t.Errorf("pulsemon.db mode = %o, want 0600", got)
	}
}

// M3b (as re-scoped by F15/N1): with PULSEMON_DB pointing at a non-default
// path, ensureDataDir acts on the dir of the DB ACTUALLY in use. Pre-F15
// this test asserted the pre-existing dir gets tightened to 0700; the
// post-F15 contract is that it keeps its mode while the DB files are
// tightened to 0600.
func TestFix_M3b_HardensDirOfDBInUse(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "custom-name.db") // non-default base name
	t.Setenv("PULSEMON_DB", dbPath)

	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	prevUmask := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(prevUmask) })

	if err := ensureDataDir(); err != nil {
		t.Fatal(err)
	}

	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0o755 {
		t.Errorf("dir of PULSEMON_DB mode = %o, want 0755 unchanged (F15)", got)
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

// F15/N1: a relative PULSEMON_DB is refused with a clean error and nothing
// on disk is touched (in particular the CWD is not chmod'd).
func TestFix_M3c_RelativeDBRefused(t *testing.T) {
	cwd := t.TempDir()
	if err := os.Chmod(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PULSEMON_DB", "pulsemon.db")

	prevUmask := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(prevUmask) })

	err := ensureDataDir()
	if err == nil {
		t.Fatal("ensureDataDir with a relative PULSEMON_DB: want error, got nil")
	}
	st, _ := os.Stat(cwd)
	if got := st.Mode().Perm(); got != 0o755 {
		t.Errorf("CWD mode = %o, want 0755 unchanged", got)
	}
}
