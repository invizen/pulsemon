//go:build windows

package main

import (
	"fmt"
	"os"
)

// rollbackBinaryFile restores <prev> over <dst>. On Windows the running
// service LOCKS <dst> — a rename over a loaded image fails with
// ERROR_USER_MAPPED_FILE — so stop the service FIRST. The stop is
// BEST-EFFORT: the VSA (the watchdog's token) does not hold
// SERVICE_STOP (integrity-enforced — see update_windows.go), so from the
// in-service watchdog the stop is access-denied. Proceed to the rename
// anyway: a crash-looping service releases its image lock between SCM
// recovery restart attempts, so the rename succeeds in the common
// broken-binary case (the service is not running). Only the rename's
// own failure is fatal.
func rollbackBinaryFile(prev, dst string) error {
	if err := stopWindowsServiceFn(); err != nil {
		uWarn("watchdog: stop before rollback denied (expected from the VSA; proceeding — the rename is the real check): " + err.Error())
	}
	if err := os.Rename(prev, dst); err != nil {
		return fmt.Errorf("restore %s over %s (the service may still be holding it): %w", prev, dst, err)
	}
	return nil
}
