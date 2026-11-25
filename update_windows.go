//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// binaryOwner is a no-op on Windows: there is no POSIX uid/gid to preserve
// across a binary swap, and the installed binary's ACL is managed by the
// installer / the SCM, not by the self-update.
func binaryOwner(dst string) (uid, gid uint32, ok bool) {
	return 0, 0, false
}

// backupBinary keeps the running .exe at prev (the M4 rollback artifact)
// before swapBinary. On Windows a RENAME, not a hardlink: NTFS permits
// hardlinking a RUNNING exe, so os.Link(dst, prev) SUCCEEDS — leaving dst
// mapped by the running process — and swapBinary's rename of the new
// binary OVER the locked dst then fails with ERROR_ACCESS_DENIED, killing
// every Windows live update. Renaming the running exe aside is the one
// move Windows allows on a locked .exe, and it leaves the dst name free
// for the swap. A stale .prev (unlocked now that its process has exited)
// is removed first, since the rename fails on an occupied name.
func backupBinary(dst, prev string) error {
	_ = os.Remove(prev)
	if rerr := os.Rename(dst, prev); rerr != nil && !os.IsNotExist(rerr) {
		return fmt.Errorf("save previous binary as %s: %w", prev, rerr)
	}
	return nil
}

// swapBinary replaces the running .exe with tmpName. On Windows the running
// exe is LOCKED — you cannot rename over or delete it — but you CAN rename
// it aside. installBinary has ALREADY moved the running exe aside to
// <dst>.prev (the M4 rollback artifact) before calling this, so the only
// step left is moving the new tmp file into place. The .prev stays put
// (locked by the running process until it exits) so `pulsemon update
// rollback` can restore it later.
func swapBinary(tmpName, dst string) error {
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("install new binary: %w", err)
	}
	return nil
}

// cleanupStaleBinary removes a leftover <exe>.old from a prior self-update.
// The previous process held a lock on it, so it couldn't be deleted then; now
// that a fresh process is running, the old file is unlocked and can go.
// (.old is the LEGACY swap scheme — the current code keeps .prev — this
// cleanup stays so installs upgraded across that change shed the leftover.)
func cleanupStaleBinary() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	_ = os.Remove(exe + ".old")
}

// ---- Windows restart wiring for the shared update flow -------------------
//
// The service runs as a virtual account (NT SERVICE\Pulsemon), and that
// VSA CANNOT restart its own service — probed live from the service's own
// token on zendev (2026-11-23, 2026-11-24): the service object's DACL
// grants the VSA START|STOP (the installer's GrantServiceSelfAccess ACE,
// CCLCSWLOCRRC = CHANGE_CONFIG|QUERY_STATUS|STOP|START|USER_DEFINED_
// CONTROL|QUERY_RECOVERY|READ_CONTROL), yet OpenService with START or
// STOP is access-denied. The denial is mandatory-integrity enforcement:
// the service object carries a higher integrity label than the VSA's
// Medium-integrity token, and the UI policy blocks write-type rights
// (START/STOP) across that gap regardless of the DACL. No ACE the
// installer can write changes that.
//
// Consequence (2026-11-24, decision windows-update-staged): the
// in-dashboard self-update is STAGED, not self-restarting. The dashboard
// update runs INSIDE the service process, and the VSA cannot restart that
// service, so there is no in-process restart path at all:
// apiAutoRestart = false (below), and POST /api/update keeps the verified
// swap half (download → ed25519 + SHA-256 verify → atomic rename with the
// .prev rollback copy) and then answers {status:"installed"} with an
// operator hint. The operator restarts the service (services.msc /
// Restart-Service) to activate the new binary.
//
// The service's SCM recovery action (sc failure ... actions= restart/...,
// configured by the installer) stays as a CRASH safety net — a crashed
// service comes back automatically. It is NOT part of the update flow.
//
// An EXTERNAL process (elevated console `pulsemon update --restart`,
// `pulsemon restart`, the rollback watchdog) still does a synchronous
// stop→start through the native SCM: an elevated admin token is High
// integrity and passes the check.
//
// No systemctl, no PowerShell.
//
// History: docs/DECISIONS.md -> windows-vsa-scm-rights,
// windows-recovery-restart (superseded for the update flow by
// windows-update-staged)
func init() {
	detectRestart = detectRestartWindows
	performRestart = performRestartWindows
	// The VSA's SCM stop is best-effort here (integrity-denied on any
	// in-service call): the shared restore code treats a denial as
	// "leave the data alone, tell the human" — see update.go.
	stopForRestoreFn = stopWindowsServiceFn
	serviceStateFn = windowsServiceState
	// The in-dashboard update NEVER restarts the service: the VSA cannot
	// restart its own service (mandatory-integrity — probed live from the
	// service's own token), so it stages the binary and hands the operator
	// the restart. The external (elevated console) path keeps the full
	// auto-restart + watchdog.
	apiAutoRestart = false
	restartServiceHint = "the new binary is installed; restart the Pulsemon service to pick it up (services.msc → Pulsemon → Restart service, or `Restart-Service Pulsemon`)"
	// The Windows clean drain is bounded at ~30s (probe + alert + HTTP
	// backstops) plus SCM stop grace; the shared 20s old-pid budget would
	// make the rollback watchdog (and the external update's watchdog)
	// give up on a slow-but-clean stop.
	wdOldProcTimeout = 45 * time.Second
}

// openSCM opens the local SCManager database with SC_MANAGER_CONNECT —
// the widest right the service's VSA holds on it, and enough to open a
// service object with any per-service access mask.
func openSCM() (windows.Handle, error) {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, fmt.Errorf("open SCM: %w", err)
	}
	return h, nil
}

// openServiceHandle opens the pulsemon service object with the exact
// access mask access. The mask is checked at OPEN time, so a missing
// right (e.g. STOP before the installer's VSA ACE is applied) fails
// here, before any control is issued.
func openServiceHandle(scHandle windows.Handle, access uint32) (windows.Handle, error) {
	s, err := windows.OpenService(scHandle, windows.StringToUTF16Ptr(serviceName), access)
	if err != nil {
		return 0, fmt.Errorf("open service %s: %w", serviceName, err)
	}
	return s, nil
}

// scmStateFn queries the pulsemon service's current SCM state (the raw
// svc.State). Used by detectRestartWindows. Var so the windows test can
// stub it. (The shared, string-valued serviceStateFn in update.go is the
// watchdog-restore seam; this one keeps the typed state for the detector.)
var scmStateFn = func() (svc.State, error) {
	sc, err := openSCM()
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(sc)
	s, err := openServiceHandle(sc, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(s)
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(s, &st); err != nil {
		return 0, fmt.Errorf("query service %s: %w", serviceName, err)
	}
	return svc.State(st.CurrentState), nil
}

// detectRestartWindows reports a live pulsemon service: the registration
// exists AND the SCM says it is running. With apiAutoRestart = false the
// value no longer gates a restart — it only feeds the response's bus
// field and logs; the in-dashboard update stages the binary either way.
// (The console `update --restart` and the rollback watchdog restart the
// same service from OUTSIDE it, where the SCM check passes.) A
// stopped/absent service gets the install-and-hint answer, the Windows
// twin of the systemd "no live service" path.
func detectRestartWindows() string {
	st, err := scmStateFn()
	if err != nil || st != svc.Running {
		return ""
	}
	return "windows-service"
}

// performRestartWindows is the shared performRestart on Windows. The new
// binary is ALREADY in place when this runs (installBinary did the
// rename-aside + rename-in), so the only step left is the restart.
//
// EXTERNAL callers only: the in-dashboard update never reaches here
// (apiAutoRestart = false — the VSA cannot restart its own service, see
// the file header; it stages the binary and hands the operator the
// restart). An elevated console process (`pulsemon update --restart`,
// `pulsemon restart`, the rollback watchdog) survives the restart, so it
// performs the synchronous stop→start (an elevated token has the rights).
func performRestartWindows(string) error {
	return restartWindowsServiceFn()
}

// windowsServiceState is the Windows serviceStateFn: the SCM state of the
// pulsemon service via QueryServiceStatus. The VSA's QUERY right works
// (the service object's DACL grants QUERY_STATUS — probed live from the
// service's own token on zendev), while its START/STOP are
// integrity-denied, so the state is the only reliable signal of whether a
// live process holds the data DB open. Returns "running", "stopped", or
// "pending" (start/stop in flight); "" + err when it cannot be determined
// (the shared restore code treats "cannot determine" as "don't touch the
// data").
func windowsServiceState() (string, error) {
	sc, err := openSCM()
	if err != nil {
		return "", err
	}
	defer windows.CloseServiceHandle(sc)
	s, err := openServiceHandle(sc, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return "", err
	}
	defer windows.CloseServiceHandle(s)
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(s, &st); err != nil {
		return "", err
	}
	switch st.CurrentState {
	case windows.SERVICE_RUNNING:
		return "running", nil
	case windows.SERVICE_STOPPED:
		return "stopped", nil
	default:
		// start/stop/continue pending — treat as in-flight; the shared
		// restore code will attempt the stop (harmless if already
		// stopping) before touching the DB.
		return "pending", nil
	}
}

// serviceBinPathFn reads the service's binPath from the registry
// (HKLM\SYSTEM\CurrentControlSet\Services\Pulsemon\ImagePath) — the same
// value `sc create` stored, readable with plain KEY_READ and no SCM
// rights at all. os.Executable() would also be the new binary for the
// updating service, but the rollback WATCHDOG runs from <exe>.prev, which
// is renamed out from under it during a rollback — its PEB path then
// points at a file that no longer exists. The registry value is stable in
// both cases. Var so the windows test can stub it.
var serviceBinPathFn = func() (string, error) {
	var k windows.Handle
	if err := windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE,
		windows.StringToUTF16Ptr(`SYSTEM\CurrentControlSet\Services\`+serviceName),
		0, windows.KEY_READ, &k); err != nil {
		return "", fmt.Errorf("open service registry key: %w", err)
	}
	defer windows.RegCloseKey(k)
	// sc create stores the binPath quoted; strip the surrounding quotes.
	var (
		valType uint32
		bufLen  uint32
	)
	if err := windows.RegQueryValueEx(k, windows.StringToUTF16Ptr(`ImagePath`), nil, &valType, nil, &bufLen); err != nil {
		return "", fmt.Errorf("read service ImagePath: %w", err)
	}
	buf := make([]byte, bufLen)
	if err := windows.RegQueryValueEx(k, windows.StringToUTF16Ptr(`ImagePath`), nil, &valType, &buf[0], &bufLen); err != nil {
		return "", fmt.Errorf("read service ImagePath: %w", err)
	}
	// REG_SZ is UTF-16.
	path := windows.UTF16ToString((*[1 << 20]uint16)(unsafe.Pointer(&buf[0]))[:bufLen/2])
	return strings.Trim(path, `"`), nil
}

// stopWindowsServiceFn stops the pulsemon service and WAITS for the clean
// shutdown (probe/alert/HTTP drain) to reach the stopped state. A Start on
// a StopPending service is refused, so the wait is not optional. Var so the
// windows test can stub it.
var stopWindowsServiceFn = func() error {
	sc, err := openSCM()
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(sc)
	s, err := openServiceHandle(sc, windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(s)
	var st windows.SERVICE_STATUS
	if err := windows.ControlService(s, uint32(svc.Stop), &st); err != nil {
		// An already-stopped service (a crash, an earlier stop, an
		// operator stop) IS the goal state of a stop: ControlService
		// answers ERROR_SERVICE_NOT_ACTIVE (1062), and treating that as
		// an error made every restart of a stopped service fail before
		// the start ever ran (the watchdog's post-rollback restart, an
		// operator `pulsemon restart` after a crash).
		if err == windows.ERROR_SERVICE_NOT_ACTIVE {
			return nil
		}
		return fmt.Errorf("stop service %s: %w", serviceName, err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		if err := windows.QueryServiceStatus(s, &st); err != nil {
			return fmt.Errorf("query service %s: %w", serviceName, err)
		}
		if st.CurrentState == windows.SERVICE_STOPPED {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("service %s did not reach stopped within 60s", serviceName)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// startWindowsServiceFn starts the pulsemon service. Var so the windows
// test can stub it.
var startWindowsServiceFn = func() error {
	sc, err := openSCM()
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(sc)
	s, err := openServiceHandle(sc, windows.SERVICE_START)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(s)
	if err := windows.StartService(s, 0, nil); err != nil {
		return fmt.Errorf("start service %s: %w", serviceName, err)
	}
	return nil
}

// restartWindowsServiceFn performs a synchronous stop→start of the pulsemon
// service through the native SCM (raw windows.OpenService/ControlService):
// no PowerShell child process (the old `powershell -Command
// "Restart-Service"` spawned a second process and depended on the
// PowerShell install). Used by the `pulsemon restart` subcommand (via the
// listener seam) and by external update callers — processes that SURVIVE
// the restart and can block on it.
// Var so the windows test can stub it.
var restartWindowsServiceFn = func() error {
	if err := stopWindowsServiceFn(); err != nil {
		return err
	}
	return startWindowsServiceFn()
}
