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
	old := serviceStateFn
	defer func() { serviceStateFn = old }()

	serviceStateFn = func() (svc.State, error) { return svc.Running, nil }
	if d := detectRestartWindows(); d != "windows-service" {
		t.Errorf("running service: detectRestartWindows() = %q, want \"windows-service\"", d)
	}
	serviceStateFn = func() (svc.State, error) { return svc.Stopped, nil }
	if d := detectRestartWindows(); d != "" {
		t.Errorf("stopped service: detectRestartWindows() = %q, want \"\"", d)
	}
	serviceStateFn = func() (svc.State, error) { return 0, errForTest }
	if d := detectRestartWindows(); d != "" {
		t.Errorf("query failure: detectRestartWindows() = %q, want \"\"", d)
	}
}

// TestPerformRestartWindowsServiceBranch pins the self-restart branch: when
// the caller IS the service, the helper is spawned from the new binary
// BEFORE the self-stop is issued (the helper is the only thing that can
// start the service back).
func TestPerformRestartWindowsServiceBranch(t *testing.T) {
	oldSvc, oldSpawn, oldStop, oldBin := isWindowsService, spawnRestartHelper, selfStopFn, serviceBinPathFn
	isWindowsService = func() bool { return true }
	serviceBinPathFn = func() (string, error) { return `C:\Program Files\Pulsemon\pulsemon.exe`, nil }
	var seq []string
	var spawnedExe string
	spawnRestartHelper = func(exePath string) error { spawnedExe = exePath; seq = append(seq, "spawn"); return nil }
	selfStopFn = func() error { seq = append(seq, "stop"); return nil }
	defer func() {
		isWindowsService, spawnRestartHelper, selfStopFn, serviceBinPathFn = oldSvc, oldSpawn, oldStop, oldBin
	}()

	if err := performRestartWindows("windows-service"); err != nil {
		t.Fatalf("performRestartWindows: %v", err)
	}
	if len(seq) != 2 || seq[0] != "spawn" || seq[1] != "stop" {
		t.Errorf("call order = %v, want [spawn stop] (the helper must be running before the service stops)", seq)
	}
	if spawnedExe != `C:\Program Files\Pulsemon\pulsemon.exe` {
		t.Errorf("helper spawned from %q, want the SCM binPath (the new in-place binary)", spawnedExe)
	}
}

// TestPerformRestartWindowsExternalBranch pins the external branch: a
// process that is NOT the service (console `update --restart`, rollback
// watchdog) gets the synchronous stop→start — no helper, no self-stop.
func TestPerformRestartWindowsExternalBranch(t *testing.T) {
	oldSvc, oldRestart, oldSpawn, oldStop := isWindowsService, restartWindowsServiceFn, spawnRestartHelper, selfStopFn
	isWindowsService = func() bool { return false }
	var restarted, spawned, stopped bool
	restartWindowsServiceFn = func() error { restarted = true; return nil }
	spawnRestartHelper = func(string) error { spawned = true; return nil }
	selfStopFn = func() error { stopped = true; return nil }
	defer func() {
		isWindowsService, restartWindowsServiceFn, spawnRestartHelper, selfStopFn = oldSvc, oldRestart, oldSpawn, oldStop
	}()

	if err := performRestartWindows("windows-service"); err != nil {
		t.Fatalf("performRestartWindows: %v", err)
	}
	if !restarted {
		t.Error("external branch must perform the synchronous stop→start")
	}
	if spawned {
		t.Error("external branch must NOT spawn the restart helper (the caller survives)")
	}
	if stopped {
		t.Error("external branch must NOT issue the self-stop")
	}
}
