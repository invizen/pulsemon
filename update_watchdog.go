package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"pulsemon/internal/store"
	"strconv"
	"strings"
	"time"
)

// runWatchdog is the detached post-restart guardian for the API's
// auto-restart path (I2): the server process dies WITH
// the service restart it triggers, so without a watchdog a broken new
// binary stays broken with no one to roll it back. The watchdog polls the
// same healthz targets the CLI uses (accepting ok OR degraded — see
// healthzPayloadOK), and on failure restores <prev> over <dst> and restarts
// the service.
//
// Exit codes: 0 = the new binary is healthy, or a rollback was performed
// successfully; 1 = the rollback itself failed (the box needs a human).
func runWatchdog(prev, dst, bus string, timeout time.Duration, oldPid int) int {
	if prev == "" || dst == "" {
		uErr("watchdog: --prev and --dst are required")
		return 1
	}
	// Guard order. The spawning server holds the update
	// flock until its own death (the restart we are guarding), and its
	// healthz answers with a VALID payload while it is still up. So the
	// old order — lock once, then poll — failed both ways: the single
	// LOCK_NB acquisition hit EWOULDBLOCK while the server was alive and
	// the watchdog exited 1 instantly (no guardian at all, silently:
	// detachSpawn nils stdio), and any fix that kept polling while the old
	// process lived would misread the OLD server as a healthy restart.
	// Therefore: wait for the old PID to exit, THEN acquire the lock (with
	// retries bounded to lockRetryBudget), THEN poll healthz.
	if oldPid > 0 && !waitForProcessExit(oldPid, wdOldProcTimeout) {
		uErr("watchdog: old server process " + strconv.Itoa(oldPid) +
			" still alive after " + wdOldProcTimeout.String() + "; exiting without touching the binary (its health is not the new one's)")
		return 1
	}
	lockDeadline := time.Now().Add(lockRetryBudget)
	var lockFile *os.File
	for {
		var err error
		lockFile, err = acquireUpdateLock()
		if err == nil {
			break
		}
		if !errors.Is(err, errUpdateLockHeld) || !time.Now().Before(lockDeadline) {
			uErr("watchdog: update lock: " + err.Error())
			return 1
		}
		time.Sleep(200 * time.Millisecond)
	}
	defer lockFile.Close()

	db := openHealthzDB()
	if db != nil {
		defer db.Close()
	}
	ok, detail := waitHealthyWithTimeout(db, timeout)
	if ok {
		uInfo("watchdog: service is healthy after restart (" + detail + ")")
		// Healthy is not the same as intact: the v1.1.19->v1.1.20
		// incident left a HEALTHY service with its sensors wiped. This
		// is the belt-and-suspenders check (DB restore + binary rollback
		// if the live sensor count dropped below the pre-update one).
		verifySensorsIntactWatchdog(db, prev, dst, bus)
		return 0
	}
	uErr("watchdog: service not healthy after restart (" + detail + "); restoring " + prev)
	if err := rollbackBinaryFile(prev, dst); err != nil {
		uErr("watchdog: rollback failed: " + err.Error())
		return 1
	}
	uInfo("watchdog: previous binary restored to " + dst)
	// The SPAWN-TIME bus is authoritative for this restart: a broken
	// binary has crashed the service into activating/failed, where
	// detectRestart() (systemctl is-active) reports "" and a
	// detect-only restart would be skipped, leaving the monitor dead.
	// Detection is the fallback for a watchdog spawned without --bus
	// (an older version, or a manual run) — the old safe default.
	restartBus := bus
	if restartBus == "" {
		restartBus = detectRestart()
	}
	if restartBus != "" {
		if err := performRestart(restartBus); err != nil {
			uErr("watchdog: restart after rollback failed: " + err.Error())
			return 1
		}
		uInfo("watchdog: service restarted with the previous binary")
	}
	return 0
}

// stopForRestoreFn stops the running service before the watchdog restores
// the pre-update DB and rolls the binary back: a live process must not have
// the DB open (the restore removes -wal/-shm and rewrites the file) nor be
// holding the binary image. Platform default (Linux): systemctl stop on the
// detected bus. Windows overrides this in update_windows.go (SCM stop —
// best-effort for the VSA). Tests stub it.
var stopForRestoreFn = func() error {
	bus := detectRestartSystemd()
	if bus == "" {
		return fmt.Errorf("no active pulsemon systemd service detected")
	}
	args := []string{"stop", "pulsemon"}
	if bus == "user" {
		args = append([]string{"--user"}, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), restartTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, systemctlPath(), args...)
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("stop pulsemon (%s bus): %v: %s", bus, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// serviceStateFn reports the live service state: "running", "stopped",
// "pending", or "" with an error. The watchdog's data-restore path must
// know whether a live process is holding the DB open BEFORE it rewrites
// the file (a restore under a live writer corrupts the data). Platform
// default (Linux): systemctl is-active. Windows overrides in
// update_windows.go (SCM QueryServiceStatus with the VSA's proven query
// right — its START/STOP are integrity-denied, so the state is the only
// reliable signal of who holds the DB). Tests stub it.
var serviceStateFn = func() (string, error) {
	bus := detectRestartSystemd()
	if bus == "" {
		return "stopped", nil // not active on either bus
	}
	args := []string{"is-active", "pulsemon"}
	if bus == "user" {
		args = append([]string{"--user"}, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), activeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, systemctlPath(), args...)
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.CombinedOutput()
	state := strings.TrimSpace(string(out))
	if err != nil {
		// is-active exits non-zero for every non-active state but still
		// prints it: trust the printed state over the exit code.
		switch state {
		case "inactive", "failed", "deactivating", "activating", "":
			return "stopped", nil
		default:
			return "", fmt.Errorf("systemctl is-active: %v: %s", err, state)
		}
	}
	if state == "active" {
		return "running", nil
	}
	return state, nil
}

// restartSensorWaitTimeout bounds the post-restart healthz sensor-count
// poll in the watchdog verifier. The watchdog ALREADY waited for the
// service to become healthy (waitHealthyWithTimeout passed) — the count
// poll is the same endpoint one probe later, so 30s is generous headroom
// (the 90s the retired helper used covered the service START, which the
// watchdog does not re-wait for). A var so a test can shrink it.
var restartSensorWaitTimeout = 30 * time.Second

// restartSensorWait is a seam over waitSensorCount so the verifier's test
// can stub it (a unit test must not poll a real port).
var restartSensorWait = func(db *store.Store, timeout time.Duration) (int, bool, string) {
	return waitSensorCount(db, timeout)
}

// restoreDatabaseFile replaces the live DB with a copy of backup (a
// consistent VACUUM INTO snapshot). The service is STOPPED when this runs,
// so nobody has the DB open. The live -wal/-shm files belong to the live
// DB's last session and must NOT replay over the restored file: remove
// them first (SQLite would replay them on the next open, mixing stale WAL
// pages into the snapshot).
//
// The copy is STREAMED to a temp file in the live file's directory and
// then renamed into place — never read wholesale into RAM (the backup is
// hundreds of MB at the declared fleet), and never written in place
// (an in-place rewrite truncates the live file first, so a power loss
// mid-write strands a truncated DB; this path already runs only after
// the watchdog proved data loss, which is exactly when a second failure
// is least acceptable). Same-directory temp + rename is what makes the
// swap atomic: the live path sees the old file whole or the new one
// whole, never a prefix. The .preupdate backup survives either way.
func restoreDatabaseFile(backup, live string) error {
	_ = os.Remove(live + "-wal")
	_ = os.Remove(live + "-shm")
	src, err := os.Open(backup)
	if err != nil {
		return err
	}
	defer src.Close()
	tmp, err := os.CreateTemp(filepath.Dir(live), ".pulsemon-restore-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err = io.Copy(tmp, src); err == nil {
		err = tmp.Chmod(0o600)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), live)
}

// verifySensorsIntactWatchdog is the post-restart data-integrity check the
// watchdog runs on the HEALTHY path (the belt-and-suspenders half of the
// self-update): the update wrote pulsemon.db.preupdate (a VACUUM INTO
// snapshot) BEFORE swapping the binary, so now that the service is back
// up, compare the live sensor count against the pre-update one. A
// shortfall means the update lost sensor data (the v1.1.19->v1.1.20
// "sensors wiped" incident: the binary swap raced a schema migration and
// the new schema lost rows). The only self-heal is restoring the pre-
// update DB and rolling the binary back to the known-good pair, then
// bringing the service up on it.
//
// It runs while the watchdog HOLDS the update lock (runWatchdog acquired
// it), so it cannot race the unhealthy-path rollback.
//
// SAFETY: the service is RUNNING when this runs (it answered healthz). A
// DB restore under a live writer corrupts the data, so the restore only
// proceeds when the service is stopped: a stopped service (the crash-loop
// case) is restored directly; a running service is stopped first, and a
// stop that is DENIED (the Windows VSA lacks SERVICE_STOP —
// integrity-enforced, see update_windows.go) means nothing is touched and
// the log carries exact manual-restore instructions. The data is safe in
// the backup either way.
//
// The watchdog is detached (no console, no inherited pipes), so uInfo/uErr
// would vanish: every finding also goes to pulsemon-watchdog.log next to
// the DB — the operator's only post-mortem record.
//
// History: docs/DECISIONS.md -> windows-upgrade-safety,
//
//	windows-recovery-restart
func verifySensorsIntactWatchdog(db *store.Store, prevBin, dstBin, bus string) {
	dbPath := healthzDBPath()
	backup := filepath.Join(filepath.Dir(dbPath), "pulsemon.db.preupdate")
	logLine := func(format string, a ...any) {
		// Go forbids extra fixed args alongside a `s...` expansion (the
		// expansion must supply the ENTIRE variadic tail), so the
		// timestamp rides in the slice.
		args := append([]any{time.Now().Format(time.RFC3339)}, a...)
		line := fmt.Sprintf("%s watchdog: "+format+"\n", args...)
		f, err := os.OpenFile(filepath.Join(filepath.Dir(dbPath), "pulsemon-watchdog.log"),
			os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return
		}
		defer f.Close()
		_, _ = f.WriteString(line)
	}

	if _, err := os.Stat(backup); err != nil {
		logLine("no pre-update backup at %s — sensor verification skipped", backup)
		return
	}
	// Read-only: the verifier must never write to the safety copy, and a
	// read-write open would set journal_mode(WAL) and strand -wal/-shm
	// sidecars beside the snapshot (see store.NewStoreReadOnly).
	bst, err := store.NewStoreReadOnly(backup)
	if err != nil {
		logLine("cannot open pre-update backup (%v) — sensor verification skipped", err)
		return
	}
	want, err := bst.SensorCount()
	bst.Close()
	if err != nil {
		logLine("cannot count sensors in pre-update backup (%v) — sensor verification skipped", err)
		return
	}
	if want == 0 {
		logLine("no sensors in the pre-update backup — nothing to verify")
		return
	}

	live, ok, detail := restartSensorWait(db, restartSensorWaitTimeout)
	if !ok {
		logLine("live sensor count unavailable (%s) — the watchdog's unhealthy path owns a service that will not answer; leaving data as-is", detail)
		return
	}
	rest, reason := sensorRestoreDecision(live, want, true)
	if !rest {
		logLine("sensors intact: %s", reason)
		// The update is VERIFIED: this snapshot has served its purpose, so
		// remove it. A surviving backup is the stale-baseline trap — months
		// later the operator may legitimately delete sensors, and a future
		// watchdog comparing the lower live count against THIS months-old
		// snapshot would declare data loss and restore it, wiping the
		// intervening months of config, users and history. The next update
		// writes a fresh snapshot atomically (BackupTo renames into place).
		if err := os.Remove(backup); err != nil {
			logLine("note: verified pre-update backup %s could not be removed (%v) — the next update replaces it atomically", backup, err)
		}
		return
	}
	logLine("DATA LOSS after update: %s — restoring the pre-update DB and the previous binary", reason)

	state, sErr := serviceStateFn()
	if (state == "running" || state == "pending") && sErr == nil {
		if err := stopForRestoreFn(); err != nil {
			logLine("cannot stop the running service to restore the database (%v) — MANUAL ACTION REQUIRED: stop the pulsemon service, replace the data DB with the backup at %s, replace the service binary with %s, then start the service", err, backup, prevBin)
			return
		}
	} else if sErr != nil && state != "stopped" {
		logLine("cannot determine the service state (%v) — a running service would hold the DB open, so nothing was restored; check the pulsemon service, then restore the DB from %s and the binary from %s if needed", sErr, backup, prevBin)
		return
	}
	// state == "stopped": no live writer; safe to restore.
	if err := restoreDatabaseFile(backup, dbPath); err != nil {
		logLine("DATABASE RESTORE FAILED: %v — restore %s over the data DB manually", err, backup)
		return
	}
	logLine("pre-update database restored from %s", backup)
	if err := rollbackBinaryFile(prevBin, dstBin); err != nil {
		logLine("BINARY ROLLBACK FAILED: %v — replace the service binary with %s manually", err, prevBin)
		return
	}
	logLine("previous binary restored to %s", dstBin)
	// The SPAWN-TIME bus is authoritative here too: the service was just
	// stopped for the restore, so detectRestart() (is-active) reports ""
	// and a detect-only restart would hit the SYSTEM bus without --user —
	// failing on every user-bus install.
	restartBus := bus
	if restartBus == "" {
		restartBus = detectRestart()
	}
	if restartBus == "" {
		logLine("no service bus known (none passed and none detected) — if the service's recovery action is configured it will start the service on the restored pair by itself; otherwise start the pulsemon service manually")
		return
	}
	if err := performRestart(restartBus); err != nil {
		logLine("restart after restore: %v — if the service's SCM recovery action is configured it will start the service on the restored pair by itself; otherwise start the pulsemon service manually", err)
		return
	}
	logLine("service restarted on the restored database and previous binary")
}

// wdOldProcTimeout bounds the watchdog's wait for the SPAWNING server
// process to exit (systemd stop drains up to ~6s; 20s is generous headroom).
// lockRetryBudget bounds the wait for the update flock to be released by
// that dying server. Both are vars so tests can shrink them.
var (
	wdOldProcTimeout = 20 * time.Second
	lockRetryBudget  = 10 * time.Second
)

// waitForProcessExit reports whether pid exited within timeout.
func waitForProcessExit(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if processGone(pid) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// watchdogTimeout is the health-poll budget for the restart watchdog,
// overridable via PULSEMON_WATCHDOG_TIMEOUT (Go duration, clamped to
// 5s..5m, invalid values warn and keep the 30s default). The hardcoded 30s
// can roll back a WORKING update on an
// install whose startup work — InitSchema, warmStats — legitimately takes
// longer on a very large DB; the operator can widen the window without a
// code change.
func watchdogTimeout() time.Duration {
	const def = 30 * time.Second
	v := os.Getenv("PULSEMON_WATCHDOG_TIMEOUT")
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 5*time.Second || d > 5*time.Minute {
		uWarn("ignoring invalid PULSEMON_WATCHDOG_TIMEOUT " + strconv.Quote(v) + " (want a Go duration between 5s and 5m0s) — using " + def.String())
		return def
	}
	return d
}

// spawnUpdateWatchdog detaches `pulsemon update --watchdog ...` (I2) so the
// API's auto-restart path keeps a guardian after this process dies. The
// watchdog polls healthz and rolls back to <exe>.prev if the new binary
// never comes up. --old-pid is us: the watchdog must not lock-acquire or
// health-poll until THIS process is gone.
//
// bus is the systemd bus detectRestart reported ("user"/"system"): on
// systemd the watchdog is spawned through `systemd-run --scope` so it lives
// in its own transient cgroup — a plain detach (Setsid) keeps it inside
// pulsemon.service's cgroup, where KillMode=control-group (the default)
// kills it with the service on the very restart it was guarding.
func spawnUpdateWatchdog(exe, bus string) error {
	return detachSpawn(buildWatchdogCommand(exe, bus))
}

// buildWatchdogCommand returns the command that spawns the detached
// watchdog, factored out of spawnUpdateWatchdog so the spawn contract is
// testable without starting a process. Two invariants:
//
//  1. It executes <exe>.prev when that file exists — the binary at <exe>
//     is the one we JUST installed, i.e. possibly the broken one (wrong
//     arch, crash in init). Spawning IT to guard itself failed in exactly
//     the failure modes the watchdog exists for; the previous binary is
//     the known-good one that also carries a working `update watchdog`
//     implementation. No .prev (first update from a pre-.prev release)
//     falls back to <exe>: nothing to roll back to, but the spawn must
//     not fail for lack of a binary.
//
//  2. On systemd with a known bus it wraps the spawn in
//     `systemd-run [--user] --scope`, placing the watchdog in an
//     independent transient cgroup that `systemctl restart pulsemon`
//     cannot kill (KillMode=control-group kills only the unit's own
//     cgroup). Without systemd-run (non-systemd host) the plain command
//     is returned and the caller's detach is all the isolation there is.
//
//  3. The bus rides into the watchdog argv (--bus) as the AUTHORITATIVE
//     post-rollback restart target: at rollback time the service is
//     crashed (activating/failed) or stopped (the DB-restore path), so a
//     fresh detectRestart() there reports no bus and the restart is
//     lost. An empty bus (non-systemd host) keeps the argv shape
//     constant; the watchdog then falls back to detection.
func buildWatchdogCommand(exe, bus string) *exec.Cmd {
	watchdogBin := exe + ".prev"
	if _, err := os.Stat(watchdogBin); err != nil {
		watchdogBin = exe
	}
	args := []string{"update", "watchdog",
		"--prev", exe + ".prev", "--dst", exe,
		"--bus", bus,
		"--timeout", watchdogTimeout().String(),
		"--old-pid", strconv.Itoa(os.Getpid())}
	if run := systemdRunPath(); bus != "" && run != "" {
		prefix := []string{"--scope"}
		if bus == "user" {
			prefix = []string{"--user", "--scope"}
		}
		return exec.Command(run, append(prefix, append([]string{watchdogBin}, args...)...)...)
	}
	return exec.Command(watchdogBin, args...)
}
