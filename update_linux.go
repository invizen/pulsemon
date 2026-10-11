//go:build linux

package main

import (
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

// swapBinary atomically replaces dst with tmpName. On Linux the running
// process holds the old inode, so a single rename over dst is atomic and safe
// (no "text file busy").
func swapBinary(tmpName, dst string) error {
	return os.Rename(tmpName, dst)
}

// cleanupStaleBinary is a no-op on Linux: the atomic rename leaves no residue.
func cleanupStaleBinary() {}
