//go:build linux

package main

import (
	"fmt"
	"os"
	"syscall"
)

// binaryOwner returns the uid/gid of the file at dst (used by installBinary to
// restore ownership after a rename swap — a root-installed binary must stay
// root-owned). ok is false if the file can't be stat'd or the platform has no
// notion of file ownership to preserve.
func binaryOwner(dst string) (uid, gid uint32, ok bool) {
	fi, err := os.Stat(dst)
	if err != nil || fi.Sys() == nil {
		return 0, 0, false
	}
	if st, isStat := fi.Sys().(*syscall.Stat_t); isStat {
		return st.Uid, st.Gid, true
	}
	return 0, 0, false
}

// backupBinary keeps the running binary at prev (the M4 rollback artifact)
// before swapBinary. On Linux a HARDLINK, not a rename: the old
// "rename dst→prev, then rename tmp→dst" left a window in which dst did
// NOT exist — a power loss between the two renames booted an install with
// NO binary. Linking makes .prev a second name for the old inode: dst
// never disappears at any point, and the swap atomically replaces the dst
// name with the new inode. A stale .prev is removed first (Link fails on
// an occupied name; removing .prev cannot lose the running binary).
// Filesystems without hardlink support fall back to the rename — no worse
// than before the fix. Windows cannot use this scheme (a hardlink to a
// running .exe succeeds and leaves dst locked for the swap) — see
// backupBinary in update_windows.go.
func backupBinary(dst, prev string) error {
	_ = os.Remove(prev)
	if err := os.Link(dst, prev); err == nil {
		return nil
	}
	if rerr := os.Rename(dst, prev); rerr != nil && !os.IsNotExist(rerr) {
		return fmt.Errorf("save previous binary as %s: %w", prev, rerr)
	}
	return nil
}

// swapBinary atomically replaces dst with tmpName. On Linux the running
// process holds the old inode, so a single rename over dst is atomic and safe
// (no "text file busy").
func swapBinary(tmpName, dst string) error {
	return os.Rename(tmpName, dst)
}

// cleanupStaleBinary is a no-op on Linux: the atomic rename leaves no residue.
func cleanupStaleBinary() {}
