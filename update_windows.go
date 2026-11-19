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

// backupBinary keeps the running .exe at prev (the M4 rollback artifact)
// before swapBinary. On Windows a RENAME, not a hardlink: NTFS permits
// hardlinking a RUNNING exe, so os.Link(dst, prev) SUCCEEDS — leaving dst
// mapped by the running process — and swapBinary's rename of the new
// binary OVER the locked dst then fails with ERROR_ACCESS_DENIED, killing
// every Windows live update. Renaming the running exe aside is the one
// move Windows allows on a locked .exe, and it leaves the dst name free
// for the swap. A stale .prev (unlocked now that its process has exited)
// is removed first, since the rename fails on an occupied name.
func backupBinary(dst, prev string) error {
	_ = os.Remove(prev)
	if rerr := os.Rename(dst, prev); rerr != nil && !os.IsNotExist(rerr) {
		return fmt.Errorf("save previous binary as %s: %w", prev, rerr)
	}
	return nil
}

// swapBinary replaces the running .exe with tmpName. On Windows the running
// exe is LOCKED — you cannot rename over or delete it — but you CAN rename
// it aside. installBinary has ALREADY moved the running exe aside to
// <dst>.prev (the M4 rollback artifact) before calling this, so the only
// step left is moving the new tmp file into place. The .prev stays put
// (locked by the running process until it exits) so `pulsemon update
// rollback` can restore it later.
func swapBinary(tmpName, dst string) error {
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("install new binary: %w", err)
	}
	return nil
}

// cleanupStaleBinary removes a leftover <exe>.old from a prior self-update.
// The previous process held a lock on it, so it couldn't be deleted then; now
// that a fresh process is running, the old file is unlocked and can go.
// (.old is the LEGACY swap scheme — the current code keeps .prev — this
// cleanup stays so installs upgraded across that change shed the leftover.)
func cleanupStaleBinary() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	_ = os.Remove(exe + ".old")
}
