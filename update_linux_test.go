//go:build linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// fdCount counts open file descriptors in the current process (Linux).
func fdCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot read /proc/self/fd: %v", err)
	}
	return len(entries)
}

// TestInstallBinaryRootOwnedPreserved pins the ownership-restoration fix:
// when the destination was root-owned, the install must leave it root-owned.
// The previous "uid != 0 || gid != 0" guard skipped the chown for exactly
// this case, so a non-root updater (with CAP_CHOWN) updating a root-installed
// binary left it owned by the updater. The test makes dst root-owned first
// (skipping when chown(0,0) isn't allowed — e.g. plain non-root without the
// capability) and requires it to still be root-owned after install.
func TestInstallBinaryRootOwnedPreserved(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("payload\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("old\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dst, 0, 0); err != nil {
		t.Skip("cannot chown dst to root; run as root or with CAP_CHOWN to exercise the root-owned path")
	}
	if err := installBinary(src, dst, ""); err != nil {
		t.Fatalf("installBinary: %v", err)
	}
	after, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	stAfter, ok := after.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("no Stat_t sysinfo after install")
	}
	if stAfter.Uid != 0 || stAfter.Gid != 0 {
		t.Fatalf("root-owned binary not preserved: after=%d:%d, want 0:0", stAfter.Uid, stAfter.Gid)
	}
}

// TestInstallBinaryNoFDLeak pins the descriptor leak: the old mustOpen path
// left the source's *os.File unclosed on every install, so repeated installs
// accumulated open fds (reclaimed only by GC). Fifty installs must not grow
// the fd table by more than a small margin.
func TestInstallBinaryNoFDLeak(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("payload\n"), 0644); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(dst, []byte("old\n"), 0644)

	before := fdCount(t)
	for i := 0; i < 50; i++ {
		if err := installBinary(src, dst, ""); err != nil {
			t.Fatalf("install %d: %v", i, err)
		}
	}
	after := fdCount(t)
	if delta := after - before; delta > 5 {
		t.Fatalf("fd count grew by %d across 50 installs (leak): before=%d after=%d", delta, before, after)
	}
}
