//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
)

// isContainer is always false on Windows: pulsemon runs as a native service
// (or a console process), never as the entrypoint of a Linux container.
func isContainer() bool { return false }

// isSystemdManaged is always false on Windows: there is no systemd.
func isSystemdManaged() bool { return false }

// requestRestart makes a listener config change take effect. On Windows the
// process is a service managed by the SCM, so it cannot re-exec itself the
// way the Linux bare-process path does. The first-cut behavior is to tell
// the operator to restart the service — the config change is already saved,
// it just needs a fresh process to bind the new listener. (A detached
// `Restart-Service` helper is a possible follow-up, but a self-triggered
// service restart that can't be tested headlessly is a worse failure mode
// than a clear, safe hint.)
func requestRestart() restartOutcome {
	return restartOutcome{
		restarted: false,
		hint:      "the change is saved — restart the pulsemon service to apply it (services.msc → pulsemon → Restart, or: Restart-Service pulsemon)",
	}
}

// runRestartCommand is the manual `pulsemon restart` subcommand. On Windows
// this is an EXTERNAL caller (a console, not the service process), so it can
// block on restarting the service via the SCM. `Restart-Service` stops and
// starts the service; it is the PowerShell equivalent of `systemctl restart`.
func runRestartCommand() dispatchKind {
	cmd := exec.Command("powershell", "-NoProfile", "-Command", "Restart-Service -Name pulsemon -ErrorAction Stop")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err == nil {
		fmt.Println("pulsemon: service restarted")
		return dExit0
	}
	fmt.Fprintln(os.Stderr, "pulsemon: could not restart the pulsemon service (is it installed and running? try: Restart-Service pulsemon)")
	return dExit1
}
