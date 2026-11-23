//go:build windows

package main

import (
	"testing"

	"golang.org/x/sys/windows/svc"
)

// These pins exercise the Windows restart seams. They COMPILE on the Linux
// gate box (GOOS=windows go vet) and RUN on the Windows QA box — the box
// suite cannot drive a live SCM from a test, so every seam is stubbed.

// TestRunRestartCommandNativeSCM pins the `pulsemon restart` subcommand:
// it drives the SCM through the seam (no powershell) with the service name
// const, and maps the outcome to the dispatch kinds.
func TestRunRestartCommandNativeSCM(t *testing.T) {
	old := restartServiceFn
	var got bool
	restartServiceFn = func() error { got = true; return nil }
	defer func() { restartServiceFn = old }()
	if k := runRestartCommand(); k != dExit0 {
		t.Fatalf("runRestartCommand() = %v, want dExit0", k)
	}
	if !got {
		t.Error("runRestartCommand must call the SCM restart seam")
	}
}

func TestRunRestartCommandFailure(t *testing.T) {
	old := restartServiceFn
	restartServiceFn = func() error { return errForTest }
	defer func() { restartServiceFn = old }()
	if k := runRestartCommand(); k != dExit1 {
		t.Fatalf("runRestartCommand() = %v on failure, want dExit1", k)
	}
}

// TestDetectRestartWindows pins the detector: a RUNNING service reports
// "windows-service", anything else (stopped, query failure) reports "" —
// the "no live service, install-and-hint" answer.
func TestDetectRestartWindows(t *testing.T) {
	old := scmStateFn
	defer func() { scmStateFn = old }()

	scmStateFn = func() (svc.State, error) { return svc.Running, nil }
	if d := detectRestartWindows(); d != "windows-service" {
		t.Errorf("running service: detectRestartWindows() = %q, want \"windows-service\"", d)
	}
	scmStateFn = func() (svc.State, error) { return svc.Stopped, nil }
	if d := detectRestartWindows(); d != "" {
		t.Errorf("stopped service: detectRestartWindows() = %q, want \"\"", d)
	}
	scmStateFn = func() (svc.State, error) { return 0, errForTest }
	if d := detectRestartWindows(); d != "" {
		t.Errorf("query failure: detectRestartWindows() = %q, want \"\"", d)
	}
}

// TestPerformRestartWindowsServiceBranch pins the in-service branch: when
// the caller IS the service, the restart is delegated to the SCM recovery
// action (the VSA cannot start its own service — integrity-enforced), so
// the branch runs selfRestartViaRecoveryFn (clean drain + failure-exit).
// The real selfRestartViaRecoveryFn os.Exits; the stub records the call.
func TestPerformRestartWindowsServiceBranch(t *testing.T) {
	oldSvc, oldRecovery, oldSelf := isWindowsService, recoveryActionConfiguredFn, selfRestartViaRecoveryFn
	isWindowsService = func() bool { return true }
	defer func() {
		isWindowsService, recoveryActionConfiguredFn, selfRestartViaRecoveryFn = oldSvc, oldRecovery, oldSelf
	}()

	var selfCalled bool
	selfRestartViaRecoveryFn = func() error { selfCalled = true; return nil }
	if err := performRestartWindows("windows-service"); err != nil {
		t.Fatalf("performRestartWindows: %v", err)
	}
	if !selfCalled {
		t.Error("the in-service branch must delegate to selfRestartViaRecoveryFn (the SCM recovery action does the starting)")
	}

	// External branch sanity in the same harness: not the service → the
	// synchronous stop→start, never the recovery self-restart.
	isWindowsService = func() bool { return false }
	oldRestart := restartWindowsServiceFn
	var restarted bool
	restartWindowsServiceFn = func() error { restarted = true; return nil }
	defer func() { restartWindowsServiceFn = oldRestart }()
	if err := performRestartWindows("windows-service"); err != nil {
		t.Fatalf("performRestartWindows (external): %v", err)
	}
	if !restarted {
		t.Error("external branch must perform the synchronous stop→start")
	}
}

// TestSelfRestartRefusesWithoutRecovery pins the pre-flight: the in-service
// self-restart REFUSES when the service's recovery action is not configured
// — an update on such a machine would exit with no one to bring the
// service back (the monitor stays stopped).
func TestSelfRestartRefusesWithoutRecovery(t *testing.T) {
	oldRecovery, oldStop := recoveryActionConfiguredFn, serviceStopCh
	recoveryActionConfiguredFn = func() bool { return false }
	serviceStopCh = make(chan struct{})
	defer func() {
		recoveryActionConfiguredFn, serviceStopCh = oldRecovery, oldStop
	}()
	if err := selfRestartViaRecoveryFn(); err == nil {
		t.Error("selfRestartViaRecoveryFn must refuse (with an error, NOT an exit) when the recovery action is not configured")
	}
}
