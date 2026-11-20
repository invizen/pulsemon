//go:build linux

package main

// Finding 23 (runRestartCommand ordering): the `pulsemon restart` subcommand
// ran the BLOCKING restartSystemdService() before checking isSystemdManaged().
// For a systemd-managed process that is a self-restart — systemctl would
// target this very process and hang on its stop phase. The fix checks
// isSystemdManaged() FIRST and takes the detached-helper branch. These pins
// lock the ordering (and the platform autoRestarts contract) via the two new
// side-effect seams.

import (
	"errors"
	"testing"
)

// TestAutoRestartsLinux locks the finding-23 platform contract: on Linux,
// requestRestart actually performs a restart (systemd helper / container
// SIGTERM / bare re-exec), so the TLS settings response may report
// "restarting": true. (On Windows this returns false — the service can't
// re-exec itself — and is pinned by the Windows build.)
func TestAutoRestartsLinux(t *testing.T) {
	if !autoRestarts() {
		t.Fatal("autoRestarts() on linux = false, want true")
	}
}

// TestRunRestartCommandSystemdManagedTakesHelperBranch locks the finding-23
// reorder: when WE are the systemd service process, runRestartCommand must
// take the detached-helper branch FIRST and never reach the blocking
// self-restart. Pre-fix the blocking restartSystemdService() ran before the
// isSystemdManaged() check, so a systemd-managed process called systemctl on
// itself.
func TestRunRestartCommandSystemdManagedTakesHelperBranch(t *testing.T) {
	t.Setenv("SYSTEMD_EXEC_PID", "12345")

	helperCalled := false
	blockingCalled := false
	origHelper := startRestartHelperFn
	origBlocking := restartSystemdServiceFn
	startRestartHelperFn = func() error { helperCalled = true; return nil }
	restartSystemdServiceFn = func() error { blockingCalled = true; return nil }
	t.Cleanup(func() {
		startRestartHelperFn = origHelper
		restartSystemdServiceFn = origBlocking
	})

	if got := runRestartCommand(); got != dExit0 {
		t.Fatalf("runRestartCommand (systemd-managed) = %v, want dExit0", got)
	}
	if !helperCalled {
		t.Fatal("systemd-managed path did not take the detached-helper branch")
	}
	if blockingCalled {
		t.Fatal("systemd-managed path reached the blocking self-restart (the regression)")
	}
}

// TestRunRestartCommandExternalCallerBlocks locks the complementary path: an
// EXTERNAL caller (console, the detached helper) is NOT systemd-managed, so
// the blocking systemctl restart is the correct (and only) action.
func TestRunRestartCommandExternalCallerBlocks(t *testing.T) {
	t.Setenv("SYSTEMD_EXEC_PID", "")

	helperCalled := false
	blockingCalled := false
	origHelper := startRestartHelperFn
	origBlocking := restartSystemdServiceFn
	startRestartHelperFn = func() error { helperCalled = true; return nil }
	restartSystemdServiceFn = func() error { blockingCalled = true; return nil }
	t.Cleanup(func() {
		startRestartHelperFn = origHelper
		restartSystemdServiceFn = origBlocking
	})

	if got := runRestartCommand(); got != dExit0 {
		t.Fatalf("runRestartCommand (external) = %v, want dExit0", got)
	}
	if !blockingCalled {
		t.Fatal("external caller did not take the blocking systemctl branch")
	}
	if helperCalled {
		t.Fatal("external caller took the helper branch (it is not systemd-managed)")
	}
}

// TestRunRestartCommandHelperFailureReports locks that a helper spawn
// failure is reported (non-zero exit) rather than silently falling through
// to the blocking self-restart.
func TestRunRestartCommandHelperFailureReports(t *testing.T) {
	t.Setenv("SYSTEMD_EXEC_PID", "12345")

	blockingCalled := false
	origHelper := startRestartHelperFn
	origBlocking := restartSystemdServiceFn
	startRestartHelperFn = func() error { return errors.New("spawn failed") }
	restartSystemdServiceFn = func() error { blockingCalled = true; return nil }
	t.Cleanup(func() {
		startRestartHelperFn = origHelper
		restartSystemdServiceFn = origBlocking
	})

	if got := runRestartCommand(); got != dExit1 {
		t.Fatalf("runRestartCommand (helper failure) = %v, want dExit1", got)
	}
	if blockingCalled {
		t.Fatal("helper failure fell through to the blocking self-restart")
	}
}
