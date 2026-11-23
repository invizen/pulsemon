//go:build !windows

package main

import "os"

// rollbackBinaryFile restores <prev> over <dst>. On Linux a plain rename
// works even while the service runs (the running process keeps its mapped
// inode; the name now points at the restored binary).
func rollbackBinaryFile(prev, dst string) error {
	return os.Rename(prev, dst)
}
