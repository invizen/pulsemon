//go:build windows

package main

import (
	"fmt"
	"os"
)

// isContainer is always false on Windows: pulsemon runs as a native service
// (or a console process), never as the entrypoint of a Linux container.
func isContainer() bool { return false }

// isSystemdManaged is always false on Windows: there is no systemd.
func isSystemdManaged() bool { return false }

// autoRestarts reports whether requestRestart on this platform actually
// performs a restart. On Windows it never does (listener/TLS config changes
// keep the safe-hint behavior — a config change must not take the monitor
// down on its own), so the TLS settings response reports
// "restarting": false rather than falsely claiming a restart is underway.
func autoRestarts() bool { return false }

// requestRestart makes a listener config change take effect. On Windows the
// process is a service managed by the SCM, so it cannot re-exec itself the
// way the Linux bare-process path does. The config change is already saved;
// it needs a fresh process to bind the new listener. The operator restarts
// with `pulsemon restart` (native SCM stop/start — see runRestartCommand).
func requestRestart() restartOutcome {
	return restartOutcome{
		restarted: false,
		hint:      "the change is saved — restart the pulsemon service to apply it (services.msc → Pulsemon → Restart, or: pulsemon restart)",
	}
}

// restartServiceFn performs a full stop→start of the pulsemon service. Var
// so the windows test can stub it: a unit test must NEVER restart the
// host's real service. The real implementation (restartWindowsServiceFn in
// update_windows.go) drives the native SCM — no PowerShell child process.
var restartServiceFn = restartWindowsServiceFn

// runRestartCommand is the manual `pulsemon restart` subcommand. On Windows
// this is an EXTERNAL caller (a console, not the service process), so it can
// block on a synchronous stop→start through the SCM. The caller needs admin
// (the service account's own rights also work) — the same elevation the old
// `powershell -Command "Restart-Service"` path required.
func runRestartCommand() dispatchKind {
	if err := restartServiceFn(); err != nil {
		fmt.Fprintf(os.Stderr, "pulsemon: could not restart the %s service: %v (requires admin; is the service installed?)\n", serviceName, err)
		return dExit1
	}
	fmt.Println("pulsemon: service restarted")
	return dExit0
}
