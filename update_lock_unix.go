//go:build !windows

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// tryFlock takes an exclusive NON-BLOCKING flock on f (F19). Returns
// (false, nil) when another process holds the lock, (false, err) on a real
// failure. flock is the natural cross-process lock on Unix: it is tied to
// the open file description, so it releases automatically on close or
// crash — no stale-lock cleanup needed.
func tryFlock(f *os.File) (bool, error) {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == unix.EWOULDBLOCK {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
