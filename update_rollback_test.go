package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// --- M4: self-update rollback (the auth-off 403 was deferred, see docs/DEFERRED.md) ---------------------------

func fixWriteFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

// TestFix_M4_InstallKeepsPrev pins the M4(a) fix: installBinary must keep
// the previous binary at <exe>.prev (old bytes, mode preserved), and a
// second install must overwrite the stale .prev instead of failing.
func TestFix_M4_InstallKeepsPrev(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "pulsemon")
	oldBytes := []byte("OLD-BINARY")
	newBytes := []byte("NEW-BINARY")
	fixWriteFile(t, exe, oldBytes, 0o755)
	src1 := filepath.Join(dir, "new1")
	fixWriteFile(t, src1, newBytes, 0o755)

	if err := installBinary(src1, exe); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); !bytes.Equal(b, newBytes) {
		t.Errorf("exe after install = %q, want the new bytes", b)
	}
	prev := exe + ".prev"
	if b, err := os.ReadFile(prev); err != nil {
		t.Fatalf("no %s after install: %v", prev, err)
	} else if !bytes.Equal(b, oldBytes) {
		t.Errorf(".prev after install = %q, want the OLD bytes", b)
	}
	if st, err := os.Stat(prev); err == nil && st.Mode().Perm() != 0o755 {
		t.Errorf(".prev mode = %o, want 0755 (preserved from the original)", st.Mode().Perm())
	}

	// A second install overwrites the stale .prev with the first new bytes.
	src2 := filepath.Join(dir, "new2")
	newerBytes := []byte("NEWER-BINARY")
	fixWriteFile(t, src2, newerBytes, 0o755)
	if err := installBinary(src2, exe); err != nil {
		t.Fatalf("second install (stale .prev present): %v", err)
	}
	if b, _ := os.ReadFile(prev); !bytes.Equal(b, newBytes) {
		t.Errorf(".prev after second install = %q, want the first new bytes", b)
	}
}

// TestFix_M4_RollbackRestores pins the M4(b) helper: rollbackBinary swaps
// the .prev back over the exe (atomic rename) and consumes the .prev; with
// no .prev present it fails cleanly.
func TestFix_M4_RollbackRestores(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "pulsemon")
	oldBytes := []byte("OLD-BINARY")
	newBytes := []byte("NEW-BINARY")
	fixWriteFile(t, exe, oldBytes, 0o755)
	src := filepath.Join(dir, "new")
	fixWriteFile(t, src, newBytes, 0o755)

	if err := installBinary(src, exe); err != nil {
		t.Fatal(err)
	}
	if err := rollbackBinary(exe); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); !bytes.Equal(b, oldBytes) {
		t.Errorf("exe after rollback = %q, want the OLD bytes", b)
	}
	if _, err := os.Stat(exe + ".prev"); !os.IsNotExist(err) {
		t.Errorf(".prev should be gone after rollback (stat err = %v)", err)
	}
	if err := rollbackBinary(exe); err == nil {
		t.Error("rollback with no .prev must fail, got nil")
	}
}
