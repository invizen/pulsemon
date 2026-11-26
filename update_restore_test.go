package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// These pins lock the restoreDatabaseFile contract (external review
// finding #3, 2026-11-24): the watchdog's data-loss restore must STREAM
// the backup to a same-directory temp file and rename it into place —
// never read the whole database into RAM, never truncate the live file
// in place. This path runs only after the watchdog has ALREADY proved
// data loss, so a power failure mid-restore must not be able to turn a
// recoverable situation (the .preupdate backup is intact) into a
// truncated live DB.

// fileIno returns the file's inode (0 if the platform hides it).
func fileIno(t *testing.T, path string) uint64 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return st.Sys().(*syscall.Stat_t).Ino
}

// writeTestFile writes content to path with 0600 and returns the inode.
func writeTestFile(t *testing.T, path string, content []byte) uint64 {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return fileIno(t, path)
}

// TestRestoreDatabaseFileAtomicSwap is the happy-path pin: the live file
// ends up byte-identical to the backup, the stale -wal/-shm are removed,
// no temp file is left behind, and — the atomicity mechanism itself —
// the live file's INODE CHANGES (a rename swap installs a new file; the
// old in-place rewrite kept the same inode, which is what made a power
// loss mid-write leave a truncated live DB).
func TestRestoreDatabaseFileAtomicSwap(t *testing.T) {
	dir := t.TempDir()
	backup := filepath.Join(dir, "pulsemon.db.preupdate")
	live := filepath.Join(dir, "pulsemon.db")

	backupData := make([]byte, 1<<20) // 1 MiB — a real DB is far bigger
	if _, err := rand.Read(backupData); err != nil {
		t.Fatalf("rand: %v", err)
	}
	oldData := bytes.Repeat([]byte("old-live-db-bytes\n"), 4096)
	writeTestFile(t, backup, backupData)
	oldIno := writeTestFile(t, live, oldData)
	if err := os.WriteFile(live+"-wal", []byte("stale-wal"), 0o600); err != nil {
		t.Fatalf("write wal: %v", err)
	}
	if err := os.WriteFile(live+"-shm", []byte("stale-shm"), 0o600); err != nil {
		t.Fatalf("write shm: %v", err)
	}

	if err := restoreDatabaseFile(backup, live); err != nil {
		t.Fatalf("restoreDatabaseFile: %v", err)
	}

	got, err := os.ReadFile(live)
	if err != nil {
		t.Fatalf("read live after restore: %v", err)
	}
	if !bytes.Equal(got, backupData) {
		t.Fatalf("live file after restore = %d bytes, want byte-identical to the %d-byte backup", len(got), len(backupData))
	}
	for _, stale := range []string{live + "-wal", live + "-shm"} {
		if _, err := os.Stat(stale); !os.IsNotExist(err) {
			t.Errorf("stale %s survived the restore (it would replay over the snapshot): %v", stale, err)
		}
	}
	st, err := os.Stat(live)
	if err != nil {
		t.Fatalf("stat live after restore: %v", err)
	}
	if st.Sys().(*syscall.Stat_t).Ino == oldIno {
		t.Error("live file kept its inode after restore — the swap is in-place, not a rename (a power loss mid-write would truncate the live DB)")
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Errorf("restored file mode = %o, want 0600 (the DB is owner-only data)", mode)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".pulsemon-restore-") {
			t.Errorf("temp file %s left behind by the restore", e.Name())
		}
	}
}

// TestRestoreDatabaseFileFailureLeavesLiveIntact is the atomicity pin:
// a restore that fails MID-COPY (here: the backup path is a directory —
// os.Open accepts it, the first read fails) must return an error with
// the live file byte- AND inode-identical to before. In the old
// ReadFile+WriteFile shape the live file was truncated in place before
// the copy completed, so any failure in the window left a truncated DB.
func TestRestoreDatabaseFileFailureLeavesLiveIntact(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "pulsemon.db")
	liveData := bytes.Repeat([]byte("precious-live-data\n"), 8192)
	oldIno := writeTestFile(t, live, liveData)

	// A directory as the "backup": Open succeeds, the copy fails on the
	// first read — the failure lands inside the copy, after any temp
	// file has been created.
	if err := restoreDatabaseFile(dir, live); err == nil {
		t.Fatal("restore from a directory backup succeeded — the copy failure must surface")
	}

	got, err := os.ReadFile(live)
	if err != nil {
		t.Fatalf("live file unreadable after a failed restore: %v", err)
	}
	if !bytes.Equal(got, liveData) {
		t.Fatalf("live file after a FAILED restore = %d bytes, want the untouched %d bytes (a failed restore must not touch the live DB)", len(got), len(liveData))
	}
	st, err := os.Stat(live)
	if err != nil {
		t.Fatalf("stat live: %v", err)
	}
	if st.Sys().(*syscall.Stat_t).Ino != oldIno {
		t.Error("live file's inode changed during a FAILED restore — it was replaced even though the copy failed")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".pulsemon-restore-") {
			t.Errorf("temp file %s leaked from a failed restore", e.Name())
		}
	}
}

// TestRestoreDatabaseFileNoBulkRead is the source-level audit (precedent:
// TestAPIRoutesAllSessionWrapped): the function must stream (Open +
// CreateTemp + Rename) and must not read the backup wholesale — an
// os.ReadFile of a hundreds-of-MB database is the memory regression this
// fix removes, and it is the shape that pairs with in-place truncation.
func TestRestoreDatabaseFileNoBulkRead(t *testing.T) {
	src, err := os.ReadFile("update_watchdog.go") // restoreDatabaseFile moved there in the NIT-33 split
	if err != nil {
		t.Fatalf("read update_watchdog.go: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "func restoreDatabaseFile(")
	if start < 0 {
		t.Fatal("restoreDatabaseFile not found in update_watchdog.go")
	}
	end := strings.Index(body[start:], "\n}")
	if end < 0 {
		t.Fatal("restoreDatabaseFile body not found")
	}
	fn := body[start : start+end]
	if strings.Contains(fn, "os.ReadFile") {
		t.Error("restoreDatabaseFile reads the backup wholesale (os.ReadFile) — a hundreds-of-MB restore loads the whole DB into RAM")
	}
	for _, want := range []string{"os.CreateTemp", "os.Rename", "io.Copy"} {
		if !strings.Contains(fn, want) {
			t.Errorf("restoreDatabaseFile is missing %s — the stream-to-temp + rename swap is what makes the restore atomic", want)
		}
	}
	if !strings.Contains(fn, "Sync()") {
		t.Error("restoreDatabaseFile does not fsync the temp file before the rename — a power loss after the rename's metadata write but before the data hits disk would install a zero-length DB")
	}
}
