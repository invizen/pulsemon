//go:build linux

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// isContainer reports whether we are the entrypoint of a container
// (re-exec is not possible: when PID 1 exits, the container stops).
func isContainer() bool {
	if exe, err := os.Executable(); err == nil && exe == "/pulsemon" {
		return true
	}
	if fileExists("/.dockerenv") {
		return true
	}
	return false
}

// isSystemdManaged reports whether systemd started this process.
func isSystemdManaged() bool {
	return os.Getenv("SYSTEMD_EXEC_PID") != ""
}

// autoRestarts reports whether requestRestart on this platform actually
// performs a restart. On Linux it does in every runtime: the systemd path
// spawns a detached helper, the container path SIGTERMs the entrypoint, and
// the bare-process path re-execs. So the TLS settings response can report
// "restarting": true.
func autoRestarts() bool { return true }

// requestRestart makes a listener config change take effect. The listener
// binds at startup, so a config change needs a fresh process. Each runtime
// has its own respawn mechanism:
//
//   - systemd service → a DETACHED `pulsemon restart` helper runs
//     `systemctl restart` (blocking there is fine: it is a separate
//     process). Our own SIGTERM comes from systemctl's stop phase and
//     drives the clean shutdown in main. The helper must NOT inherit
//     SYSTEMD_EXEC_PID — it is an external caller, not the service.
//   - container → SIGTERM to ourselves; `restart: unless-stopped` makes
//     the docker daemon respawn the container with the new config.
//   - bare process → re-exec: fork a child (PULSEMON_RESTARTING=1, whose
//     listener retries the bind for 30s while we still hold the port)
//     and SIGTERM ourselves so the child's bind succeeds.
//
// Callers must have flushed their API response BEFORE calling this: the
// process is about to die.
func requestRestart() restartOutcome {
	exe, _ := os.Executable()
	switch {
	case isSystemdManaged():
		cmd := exec.Command(exe, "restart")
		env := make([]string, 0, len(os.Environ()))
		for _, kv := range os.Environ() {
			if strings.HasPrefix(kv, "SYSTEMD_EXEC_PID=") {
				continue // the helper must act as an external caller
			}
			env = append(env, kv)
		}
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			return restartOutcome{hint: "restart the pulsemon service to apply TLS"}
		}
		// Reap the helper when it exits (systemctl restart returns, the
		// helper is done): without a Wait, a failing helper lingers as a
		// <defunct> child until we die. Detached — the restart path must
		// not block on it.
		go func() { _ = cmd.Wait() }()
		return restartOutcome{restarted: true}
	case isContainer():
		syscall.Kill(os.Getpid(), syscall.SIGTERM)
		return restartOutcome{
			restarted: true,
			hint:      "if the dashboard does not return on HTTPS shortly, run: docker restart pulsemon",
		}
	default:
		// Only SIGTERM ourselves if the child actually started: a failed
		// re-exec must NOT leave us dead with no successor (the previous
		// fire-and-forget killed the monitor on any fork/exec failure —
		// fd exhaustion, deleted binary — turning a TLS settings change
		// into a permanent outage).
		if err := callReexec(); err != nil {
			return restartOutcome{hint: "re-exec failed: " + err.Error() + " — restart pulsemon manually to apply the change"}
		}
		callKillSelf()
		return restartOutcome{restarted: true}
	}
}

// reexecFn and killSelf are the two side effects of the bare-process
// restart path. They are vars (like update.go's detectRestart /
// performRestart) so tests can inject outcomes WITHOUT spawning a real
// child or SIGTERMing the test process. restartMu guards the pair: a test
// stub swaps them while the server's TLS-settings goroutine can still be
// mid-requestRestart, and the unsynchronized swap is a data race the
// detector flags (read via callReexec/callKillSelf, write via
// setRestartFnsForTest).
var (
	restartMu sync.RWMutex
	reexecFn  = reexec
	killSelf  = func() { syscall.Kill(os.Getpid(), syscall.SIGTERM) }
)

// callReexec invokes the (possibly test-injected) re-exec under the read
// lock so a concurrent stub swap cannot race the read.
func callReexec() error {
	restartMu.RLock()
	fn := reexecFn
	restartMu.RUnlock()
	return fn()
}

// callKillSelf is the killSelf counterpart of callReexec.
func callKillSelf() {
	restartMu.RLock()
	fn := killSelf
	restartMu.RUnlock()
	fn()
}

// setRestartFnsForTest atomically swaps both injection points (tests only).
func setRestartFnsForTest(reexec func() error, kill func()) {
	restartMu.Lock()
	reexecFn, killSelf = reexec, kill
	restartMu.Unlock()
}

// reexec forks a fresh copy of this process. The child sets
// PULSEMON_RESTARTING=1 so its listen loop retries the bind for 30s
// while this process still holds the port. It RETURNS any exec error so
// the caller can keep the old process running instead of SIGTERMing
// itself into a void with no successor.
func reexec() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), "PULSEMON_RESTARTING=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Start()
}

// startRestartHelper spawns the detached `pulsemon restart` helper that
// performs the actual systemctl restart. The helper must NOT inherit
// SYSTEMD_EXEC_PID (it acts as an external caller, not the service). It is
// invoked through startRestartHelperFn so the systemd-managed path of
// runRestartCommand is testable WITHOUT spawning a real process.
func startRestartHelper() error {
	exe, _ := os.Executable()
	cmd := exec.Command(exe, "restart")
	cmd.Env = filterEnv("SYSTEMD_EXEC_PID=")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

// startRestartHelperFn and restartSystemdServiceFn are the two external side
// effects of runRestartCommand, exposed as vars so tests can verify the
// systemd-managed path takes the helper branch (and NEVER the blocking
// self-restart) without spawning a real helper or calling systemctl. Access
// is single-goroutine (the subcommand dispatch), so no lock is needed.
var (
	startRestartHelperFn    = startRestartHelper
	restartSystemdServiceFn = restartSystemdService
)

// runRestartCommand is the manual `pulsemon restart` subcommand: restart
// the pulsemon installation on this box:
//   - we ARE the systemd service → a detached `pulsemon restart` helper
//     runs `systemctl restart` (we cannot block on our own restart:
//     systemctl would target this very process and hang on its stop
//     phase). Checked FIRST so the blocking path is never reached.
//   - external caller (console, the detached helper) → systemctl restart
//     (blocking is fine: a separate process)
//   - inside a container → SIGTERM to PID 1 (the entrypoint); the
//     container's restart policy respawns it
//   - otherwise → hint (a bare process has no manager to ask)
func runRestartCommand() dispatchKind {
	if isSystemdManaged() {
		// We ARE the service process: cannot block on our own restart.
		// Ask a detached helper; on failure report it rather than fall
		// through to the blocking self-restart (which would hang).
		if err := startRestartHelperFn(); err != nil {
			fmt.Fprintf(os.Stderr, "pulsemon: failed to start the restart helper: %v\n", err)
			return dExit1
		}
		return dExit0
	}
	if err := restartSystemdServiceFn(); err == nil {
		fmt.Println("pulsemon: service restarted")
		return dExit0
	}
	if isContainer() {
		if err := syscall.Kill(1, syscall.SIGTERM); err == nil {
			log.Println("pulsemon: signalled the entrypoint; the container's restart policy respawns it")
			return dExit0
		}
	}
	fmt.Fprintln(os.Stderr, "pulsemon: no restartable pulsemon service detected on this host")
	return dExit1
}

// restartSystemdService tries the user session first, then system-wide.
// Bounded per attempt: systemctl restart can block
// (job queuing, a unit stuck in activating) and the update path's other
// external calls are all bounded — an unbounded Run here could hang the
// CLI/server past its own budgets. 60s is generous for a normal restart
// and still finite.
func restartSystemdService() error {
	var last error
	for _, args := range [][]string{{"--user", "restart", "pulsemon"}, {"restart", "pulsemon"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		err := exec.CommandContext(ctx, systemctlPath(), args...).Run()
		cancel()
		if err == nil {
			return nil
		}
		last = err
	}
	return last
}

func filterEnv(prefix string) []string {
	out := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, prefix) {
			out = append(out, kv)
		}
	}
	return out
}
