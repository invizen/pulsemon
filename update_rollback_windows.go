//go:build windows

package main

import "os"

// rollbackBinaryFile restores <prev> over <dst>. On Windows the running
// service LOCKS <dst> — a rename over a loaded image fails with
// ERROR_USER_MAPPED_FILE — so stop the service FIRST (best-effort: it may
// already be stopped, e.g. the new binary never came up). The performRestart
// call that follows the rename in runWatchdog brings the service back with
// the restored binary.
func rollbackBinaryFile(prev, dst string) error {
	if err := stopWindowsServiceFn(); err != nil {
		// A stop failure means <dst> may still be locked; the rename below
		// will fail loudly, and the watchdog reports it.
		return err
	}
	return os.Rename(prev, dst)
}
