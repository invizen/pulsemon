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
// token on zendev (2026-11-23): the service object's DACL grants the VSA
// START|STOP (the installer's GrantServiceSelfAccess ACE,
// CCLCSWLOCRRC = CHANGE_CONFIG|QUERY_STATUS|STOP|START|USER_DEFINED_
// CONTROL|QUERY_RECOVERY|READ_CONTROL), yet OpenService with START or
// STOP is access-denied. The denial is mandatory-integrity enforcement:
// the service object carries a higher integrity label than the VSA's
// Medium-integrity token, and the UI policy blocks write-type rights
// (START/STOP) across that gap regardless of the DACL. No ACE the
// installer can write changes that — so the VSA's in-service restart is
// delegated to the SCM itself:
//
//   - the installer configures the service's RECOVERY ACTION
//     (sc failure ... actions= restart/...);
//   - the in-service update flow runs the clean drain, then exits with
//     a non-zero code WITHOUT reporting Stopped to the SCM;
//   - the SCM records an unexpected termination (7031) and runs the
//     recovery action: restart the service — now with the NEW binary.
//
// The restart is executed by services.exe (SYSTEM), so the VSA needs no
// SCM rights for it. The VSA keeps its QUERY rights (the installer's
// ACE) for the state checks below, which DO work from the VSA token.
//
// An EXTERNAL process (elevated console `pulsemon update --restart`,
// `pulsemon restart`) still does a synchronous stop→start through the
// native SCM: an elevated admin token is High integrity and passes the
// check.
//
// No systemctl, no PowerShell.
//
// History: docs/DECISIONS.md -> windows-vsa-scm-rights,
//          windows-recovery-restart

func init() {
	detectRestart = detectRestartWindows
	performRestart = performRestartWindows
	// The VSA's SCM stop is best-effort here (integrity-denied on the
	// in-service path): the shared restore code treats a denial as
	// "leave the data alone, tell the human" — see update.go.
	stopForRestoreFn = stopWindowsServiceFn
	serviceStateFn = windowsServiceState
	// The Windows clean drain is bounded at ~30s (probe + alert + HTTP
	// backstops) plus SCM stop grace; the shared 20s old-pid budget would
	// make the rollback watchdog give up on a slow-but-clean stop.
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
// exists AND the SCM says it is running. (The in-dashboard update, the
// console `update --restart`, and the rollback watchdog all restart the
// SAME service; performRestartWindows branches on whether the CALLER is
// that service.) A stopped/absent service gets the install-and-hint answer,
// the Windows twin of the systemd "no live service" path.
func detectRestartWindows() string {
	st, err := scmStateFn()
	if err != nil || st != svc.Running {
		return ""
	}
	return "windows-service"
}

// updateExitCode is the exit code the service uses when it has completed
// a self-update and is exiting for the SCM's recovery restart. The exit
// happens WITHOUT a Stopped report to the SCM, so the SCM records an
// unexpected termination (event 7031) and runs the configured recovery
// action (restart) — the new binary then starts. The code itself is not
// SCM-significant (any unreported non-zero exit triggers recovery); 3
// distinguishes an update exit from a crash in post-mortem log triage.
const updateExitCode = 3

// performRestartWindows is the shared performRestart on Windows. The new
// binary is ALREADY in place when this runs (installBinary did the
// rename-aside + rename-in), so:
//
//   - the service process (the in-dashboard update) is about to die: run
//     the clean drain, then exit for the SCM's recovery restart (the VSA
//     cannot stop/start its own service — integrity-enforced; see the
//     file header). The recovery action is set by the installer.
//   - an external process (console `pulsemon update --restart`, the
//     rollback path) survives the restart: a synchronous stop→start (an
//     elevated console token has the rights).
func performRestartWindows(string) error {
	if isWindowsService() {
		return selfRestartViaRecoveryFn()
	}
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

// recoveryActionConfiguredFn reports whether the service's recovery
// configuration contains a RESTART action. The in-service update relies
// on the SCM restarting the service after its deliberate failure-exit,
// so an update on a machine where the recovery action was cleared after
// install would leave the monitor stopped with no one to bring it back.
// It reads HKLM\SYSTEM\CurrentControlSet\Services\Pulsemon\Recovery
// (REG_BINARY SERVICE_RECOVERY_STRUCTURE: DWORD reset, DWORD actions[N])
// with plain KEY_READ — no SCM rights. The installer sets the action
// (installer/pulsemon.iss); a missing/mangled value means it was reset
// by hand. Var so the windows test can stub it.
var recoveryActionConfiguredFn = func() bool {
	var k windows.Handle
	if err := windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE,
		windows.StringToUTF16Ptr(`SYSTEM\CurrentControlSet\Services\`+serviceName),
		0, windows.KEY_READ, &k); err != nil {
		return false
	}
	defer windows.RegCloseKey(k)
	var (
		valType uint32
		bufLen  uint32
	)
	if err := windows.RegQueryValueEx(k, windows.StringToUTF16Ptr(`Recovery`), nil, &valType, nil, &bufLen); err != nil {
		return false
	}
	v := make([]byte, bufLen)
	if err := windows.RegQueryValueEx(k, windows.StringToUTF16Ptr(`Recovery`), nil, &valType, &v[0], &bufLen); err != nil || len(v) < 8 {
		return false
	}
	// First recovery action at offset 4; 0x2 =
	// SERVICE_RECOVERY_ACTION_RESTART_SERVICE.
	firstAction := uint32(v[4]) | uint32(v[5])<<8 | uint32(v[6])<<16 | uint32(v[7])<<24
	return firstAction == 0x2
}

// selfRestartViaRecoveryFn is the in-service restart: verify the recovery
// action is configured (refuse an update that would strand the monitor
// stopped), run the SAME clean drain a Stop control triggers (close the
// handler's stop channel and wait for the server's done channel), then
// exit(updateExitCode) WITHOUT reporting Stopped. The SCM's recovery
// action restarts the service with the new binary — services.exe does
// the starting, so the VSA needs no SCM rights for any of it.
//
// Bounded drain: the clean shutdown is ~30s worst case (probe + alert +
// HTTP backstops); 45s matches wdOldProcTimeout so the rollback watchdog
// (which waits for this process to die) is never left guessing.
// Var so the windows test can stub it.
var selfRestartViaRecoveryFn = func() error {
	if !recoveryActionConfiguredFn() {
		return fmt.Errorf("the %s service has no restart recovery action configured — the installer sets it (sc failure %s actions= restart/...); re-run the installer, then update again", serviceName, serviceName)
	}
	if serviceStopCh == nil {
		return fmt.Errorf("no running service drain channel (isWindowsService mismatch)")
	}
	fmt.Fprintf(os.Stderr, "pulsemon: self-update complete; clean drain, then exiting for the SCM recovery restart\n")
	close(serviceStopCh)
	select {
	case <-serviceDoneCh:
	case <-time.After(45 * time.Second):
		fmt.Fprintln(os.Stderr, "pulsemon: clean drain did not finish within 45s; exiting for the recovery restart anyway")
	}
	os.Exit(updateExitCode)
	return nil // unreachable
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
