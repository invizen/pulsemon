package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// handleRestart is the post-install restart decision, factored out of
// runUpdate so it can be tested in isolation without touching installBinary.
// That matters: installBinary renames the new binary over exe, and under
// `go test` exe is the cached test binary (/tmp/go-build.../pulsemon.test) —
// so the restart tests call handleRestart directly and never enter the
// install path (no fake payload ever lands on the test binary). Returns the
// exit code for this stage; runUpdate returns it.
func handleRestart(exe string, restart bool) int {
	// Container: the binary in the running image is unchanged; a rebuild is
	// required, not a restart.
	if exe == "/pulsemon" {
		if restart {
			uWarn("--restart ignored: container detected — the binary in the image is unchanged; rebuild with `docker compose up -d --build` (pulling the new release) to update.")
		} else {
			uWarn("container detected — the binary inside the image is unchanged; rebuild with `docker compose up -d --build` (pulling the new release) to update.")
		}
		return 0
	}

	// Default (no --restart): install-and-hint. Tell the operator how to
	// restart based on how the process is running — never auto-restart,
	// because the fleet is mixed and a bad new version must not take the
	// monitor down on its own.
	if !restart {
		if _, err := os.Stat("/run/systemd/system"); err == nil {
			uInfo("restart with: systemctl --user restart pulsemon   (system-wide install: sudo systemctl restart pulsemon)")
		} else {
			uWarn("restart the pulsemon process to pick up the new binary.")
		}
		return 0
	}

	// --restart: only auto-restart when we can confidently detect a live
	// systemd pulsemon service; otherwise fall back to the hint (never guess
	// a restart on a mixed fleet).
	d := detectRestart()
	if d == "" {
		if _, err := os.Stat("/run/systemd/system"); err == nil {
			uInfo("no live pulsemon service detected; restart with: systemctl --user restart pulsemon   (system-wide install: sudo systemctl restart pulsemon)")
		} else {
			uWarn("no live pulsemon service detected; restart the pulsemon process to pick up the new binary.")
		}
		return 0
	}
	uInfo("restarting pulsemon (" + d + " service)...")
	if err := performRestart(d); err != nil {
		uErr("restart failed: " + err.Error())
		uErr("the new binary is installed but the service did not restart — check: " + journalHint(d))
		return 1
	}
	// Poll healthz to confirm the new binary actually came up. The new
	// process's port depends on its TLS config, which lives in the DB —
	// open it (same data volume; WAL allows a concurrent reader) so the
	// check can find a TLS-on-custom-port install. nil on failure: the
	// check then falls back to the default HTTPS port.
	db := openHealthzDB()
	if db != nil {
		defer db.Close()
	}
	if ok, detail := waitHealthy(db); ok {
		uInfo("pulsemon is up and healthy after restart (" + detail + ")")
	} else {
		// The new binary is not answering: roll the install back to
		// <exe>.prev, restart once more, and report exit 1 (the update
		// did not take, even if the old binary comes back healthy).
		uErr("service restarted but is not answering healthz yet (" + detail + ")")
		uErr("rolling back to the previous binary (" + exe + ".prev) and restarting...")
		if rerr := rollbackBinary(exe); rerr != nil {
			uErr("rollback failed: " + rerr.Error())
			uErr("check: " + journalHint(d))
			return 1
		}
		if perr := performRestart(d); perr != nil {
			uErr("restart after rollback failed: " + perr.Error())
			uErr("check: " + journalHint(d))
			return 1
		}
		if ok, detail2 := waitHealthy(db); ok {
			uInfo("rolled back to the previous binary; pulsemon is healthy again (" + detail2 + ")")
		} else {
			uErr("rolled back to the previous binary, but it is not answering healthz either (" + detail2 + ")")
			uErr("check: " + journalHint(d))
		}
		return 1
	}
	return 0
}

// handleRollbackRestart is the post-rollback restart decision for
// `pulsemon update rollback [--restart]`: the same auto-restart rule as
// handleRestart (only a confidently detected live systemd service), with
// the install-and-hint fallbacks otherwise.
func handleRollbackRestart(exe string, restart bool) int {
	if exe == "/pulsemon" {
		if restart {
			uWarn("--restart ignored: container detected — the binary in the image is unchanged; rebuild with `docker compose up -d --build` to pick up the previous binary.")
		} else {
			uWarn("container detected — the binary inside the image is unchanged; rebuild with `docker compose up -d --build` to pick up the previous binary.")
		}
		return 0
	}

	if !restart {
		if _, err := os.Stat("/run/systemd/system"); err == nil {
			uInfo("restart with: systemctl --user restart pulsemon   (system-wide install: sudo systemctl restart pulsemon)")
		} else {
			uWarn("restart the pulsemon process to pick up the previous binary.")
		}
		return 0
	}

	d := detectRestart()
	if d == "" {
		if _, err := os.Stat("/run/systemd/system"); err == nil {
			uInfo("no live pulsemon service detected; restart with: systemctl --user restart pulsemon   (system-wide install: sudo systemctl restart pulsemon)")
		} else {
			uWarn("no live pulsemon service detected; restart the pulsemon process to pick up the previous binary.")
		}
		return 0
	}
	uInfo("restarting pulsemon (" + d + " service)...")
	if err := performRestart(d); err != nil {
		uErr("restart failed: " + err.Error())
		uErr("check: " + journalHint(d))
		return 1
	}
	db := openHealthzDB()
	if db != nil {
		defer db.Close()
	}
	if ok, detail := waitHealthy(db); ok {
		uInfo("pulsemon is up and healthy after restart (" + detail + ")")
	} else {
		uErr("service restarted but is not answering healthz yet (" + detail + ")")
		uErr("check: " + journalHint(d))
		return 1
	}
	return 0
}

// detectRestart and performRestart are vars (not plain funcs) so tests can
// stub them: a unit test must NEVER run systemctl against the host it runs
// on. The real implementations shell out to systemctl; the stubs in
// update_restart_test.go just record what would have run.
var (
	detectRestart  = detectRestartSystemd
	performRestart = func(bus string) error { return runRestart(bus) }
)

// apiAutoRestart reports whether the in-dashboard update (POST /api/update,
// which runs INSIDE the server process) may restart the service itself
// after the binary swap. systemd (the default): yes. Windows: NO — the
// service runs as its own virtual service account (NT SERVICE\Pulsemon),
// and that VSA cannot start/stop its own service (mandatory-integrity
// enforcement denies it even though the DACL grants START|STOP — probed
// live from the service's own token), so an in-process restart is
// impossible. The Windows in-dashboard update stages the verified binary
// and hands the operator the restart (restartServiceHint); an elevated
// console `pulsemon update --restart` keeps the full auto-restart path
// (a High-integrity token passes the SCM check). Windows overrides in
// update_windows.go.
var apiAutoRestart = true

// restartServiceHint is the operator-facing restart instruction carried in
// the "installed" (staged) update response. The systemd default is generic;
// Windows overrides in update_windows.go with the service name and its two
// restart paths (services.msc / Restart-Service).
var restartServiceHint = "the new binary is installed; restart the pulsemon service to pick it up"

// detectRestartSystemd reports which systemd bus the live pulsemon service runs
// on: "user" if a user-bus service is active, "system" if a system-bus service
// is active (root), else "" when no live service is confidently detectable.
// It probes the USER bus first (that's how install.sh installs it) and falls
// back to the system bus. Probing via is-active (exit code, not output) means
// root's nonexistent user bus and non-systemd hosts both report "" — the safe
// "don't guess a restart" answer.
func detectRestartSystemd() string {
	if systemctlActive("user") {
		return "user"
	}
	if systemctlActive("system") {
		return "system"
	}
	return ""
}

// systemctlActive reports whether the pulsemon service is active on the given
// bus ("user" or "system"). `systemctl is-active` exits 0 only when active.
// Bounded by activeTimeout: systemctl talks to dbus, and a wedged bus
// must not stall `pulsemon update --restart` — an unanswered probe is treated
// as "no live service" and the safe hint is printed.
func systemctlActive(bus string) bool {
	args := []string{"is-active", "pulsemon"}
	if bus == "user" {
		args = append([]string{"--user"}, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), activeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, systemctlPath(), args...)
	// is-active prints "active"/"inactive"/"failed"/"unknown"; we only care
	// about the exit code, so discard output.
	return cmd.Run() == nil
}

// validRestartBus reports whether bus names a bus the restart paths
// understand: "user" or "system" (systemd) or "windows-service" (the
// Windows SCM). "" is accepted (no bus — the caller detects at runtime).
// The watchdog CLI validates --bus against this: a garbage value would
// be issued to systemctl for a unit that is not there.
func validRestartBus(bus string) bool {
	switch bus {
	case "", "user", "system", "windows-service":
		return true
	}
	return false
}

// runRestart restarts the pulsemon service on the given bus and waits for the
// command to return. Bounded by restartTimeout: systemctl restart can wait a
// while for the unit to settle (a slow or stuck service), and the bound keeps
// a wedged dbus from hanging the update indefinitely.
//
// A `reset-failed` on the SAME bus runs first: a crash-looped broken binary
// trips StartLimitBurst, and until the failed state is reset the restart
// fails with "start-limit-hit" no matter how often it is retried — exactly
// the state the post-rollback restart faces. Best effort: on a healthy unit
// reset-failed is a no-op, and a reset failure must not block the restart.
func runRestart(bus string) error {
	resetArgs := []string{"reset-failed", "pulsemon"}
	restartArgs := []string{"restart", "pulsemon"}
	if bus == "user" {
		resetArgs = append([]string{"--user"}, resetArgs...)
		restartArgs = append([]string{"--user"}, restartArgs...)
	}
	run := func(args []string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), restartTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, systemctlPath(), args...)
		// If systemctl (or a wrapper) leaves a child holding the output
		// pipe, the context kill alone would not release CombinedOutput:
		// bound the wait too.
		cmd.WaitDelay = 2 * time.Second
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	// reset-failed first (see above); its result is deliberately
	// discarded — the restart below is the load-bearing call.
	_, _ = run(resetArgs)
	out, err := run(restartArgs)
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// journalHint is the operator's next diagnostic step after a restart problem.
func journalHint(bus string) string {
	if bus == "user" {
		return "journalctl --user -u pulsemon"
	}
	if bus == "windows-service" {
		return "the Windows Event Log (Application) + %ProgramData%\\Pulsemon\\pulsemon-watchdog.log"
	}
	return "journalctl -u pulsemon"
}

// unitFileCandidates are the pulsemon systemd unit files the CLI consults
// for unit-level environment: the user unit first
// (install.sh's default), then the system unit.
func unitFileCandidates() []string {
	var out []string
	if home, err := os.UserHomeDir(); err == nil {
		out = append(out, filepath.Join(home, ".config/systemd/user/pulsemon.service"))
	}
	out = append(out, "/etc/systemd/system/pulsemon.service")
	return out
}

// unitEnvVar returns name's value from the pulsemon unit's Environment=
// lines: `pulsemon update --restart` runs from the
// operator's shell, which does NOT carry the unit's PULSEMON_ADDR /
// PULSEMON_DB — the post-restart healthz poll and the DB lookup then fell
// back to defaults, so a non-default-port install could never verify its
// own update. Shell env wins (callers check it first); this is the
// fallback. Understands systemd's Environment= shapes: K=V, quoted K=V,
// and space-separated lists.
func unitEnvVar(name string) string {
	for _, path := range unitFileCandidates() {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "Environment=") {
				continue
			}
			for _, kv := range strings.Fields(strings.TrimPrefix(line, "Environment=")) {
				kv = strings.Trim(kv, `"'`)
				if k, v, ok := strings.Cut(kv, "="); ok && k == name {
					return strings.Trim(v, `"'`)
				}
			}
		}
	}
	return ""
}

// systemctlPath is the systemctl binary the updater/restart helpers execute.
// A var so tests can inject a fake: a unit test must NEVER run the host's real
// systemctl (it would restart a real pulsemon service on a dev/test box).
var systemctlPath = resolveSystemctl

// resolveSystemctl picks the systemctl binary. The fixed system locations win
// over $PATH so a writable directory early in PATH cannot substitute its own
// "systemctl"; PATH is only the fallback for unusual layouts (NixOS, containers).
func resolveSystemctl() string {
	for _, p := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	if p, err := exec.LookPath("systemctl"); err == nil {
		return p
	}
	return "systemctl"
}
