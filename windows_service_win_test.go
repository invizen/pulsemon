//go:build windows

package main

import (
	"strings"
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

// TestPerformRestartWindowsExternalOnly pins the post-2026-11-24 contract
// (windows-update-staged): performRestartWindows is the EXTERNAL path only
// (an elevated console process — High-integrity tokens pass the SCM check)
// and always performs the synchronous stop→start. The in-service branch
// (self-restart via the SCM recovery action) is gone: the VSA cannot
// restart its own service (mandatory-integrity), and the in-dashboard
// update stages the binary instead of restarting (apiAutoRestart = false).
func TestPerformRestartWindowsExternalOnly(t *testing.T) {
	oldRestart := restartWindowsServiceFn
	var restarted bool
	restartWindowsServiceFn = func() error { restarted = true; return nil }
	defer func() { restartWindowsServiceFn = oldRestart }()
	if err := performRestartWindows("windows-service"); err != nil {
		t.Fatalf("performRestartWindows: %v", err)
	}
	if !restarted {
		t.Error("performRestartWindows must perform the synchronous stop→start (the only remaining Windows restart path)")
	}
}

// TestWindowsUpdateStagedSeams pins the in-dashboard contract at the
// runtime seams: the Windows service cannot auto-restart from inside
// itself (the VSA's integrity wall), so the API must stage the binary and
// hand the operator the restart — apiAutoRestart is false and the hint
// names the Pulsemon service with its restart paths.
func TestWindowsUpdateStagedSeams(t *testing.T) {
	if apiAutoRestart {
		t.Error("apiAutoRestart must be false on Windows: the service's VSA cannot restart its own service (mandatory-integrity), so the in-dashboard update stages the binary")
	}
	if !strings.Contains(restartServiceHint, "Pulsemon") {
		t.Errorf("restartServiceHint must name the Pulsemon service: %q", restartServiceHint)
	}
}
