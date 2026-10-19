//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// tryFlock is the Windows analog of the Unix flock (F19): an exclusive
// non-blocking byte-range lock via LockFileEx. Returns (false, nil) when
// another process holds the lock, (false, err) on a real failure. Like
// flock, a LockFileEx lock is released when the handle closes (process
// exit included), so a crash leaves no stale lock.
func tryFlock(f *os.File) (bool, error) {
	var ov windows.Overlapped
	err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &ov)
	if err == windows.ERROR_LOCK_VIOLATION {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
