//go:build windows

package main

import (
	"fmt"
	"os"
)

// binaryOwner is a no-op on Windows: there is no POSIX uid/gid to preserve
// across a binary swap, and the installed binary's ACL is managed by the
// installer / the SCM, not by the self-update.
func binaryOwner(dst string) (uid, gid uint32, ok bool) {
	return 0, 0, false
}

// swapBinary replaces the running .exe with tmpName. On Windows the running
// exe is LOCKED — you cannot rename over or delete it — but you CAN rename it
// aside. So: (1) move the running pulsemon.exe to pulsemon.exe.old (the
// process keeps running from the renamed inode), (2) move the new tmp file
// into place as pulsemon.exe, (3) best-effort delete the .old. The .old is
// still locked by the running process so the delete usually fails; it is
// removed on the NEXT start by cleanupStaleBinary.
func swapBinary(tmpName, dst string) error {
	old := dst + ".old"
	_ = os.Remove(old) // clear a stale .old from a prior update, if it's unlocked
	if err := os.Rename(dst, old); err != nil {
		return fmt.Errorf("rename running binary aside: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		// Best-effort: put the old binary back so we're not left with none.
		_ = os.Rename(old, dst)
		return fmt.Errorf("install new binary: %w", err)
	}
	_ = os.Remove(old) // usually fails (locked by the running process)
	return nil
}

// cleanupStaleBinary removes a leftover <exe>.old from a prior self-update.
// The previous process held a lock on it, so it couldn't be deleted then; now
// that a fresh process is running, the old file is unlocked and can go.
func cleanupStaleBinary() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	_ = os.Remove(exe + ".old")
}
