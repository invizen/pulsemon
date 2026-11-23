//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
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
// The service runs as a virtual account (NT SERVICE\Pulsemon). The SCM
// grants a service's own logon account full control of the service's
// security descriptor, so this process can stop and start its OWN service
// through the native SCM (golang.org/x/sys/windows/svc/mgr) — no systemctl,
// no PowerShell.

func init() {
	detectRestart = detectRestartWindows
	performRestart = performRestartWindows
	// The Windows clean drain is bounded at ~30s (probe + alert + HTTP
	// backstops) plus SCM stop grace; the shared 20s old-pid budget would
	// make the rollback watchdog give up on a slow-but-clean stop.
	wdOldProcTimeout = 45 * time.Second
}

// serviceStateFn queries the pulsemon service's current SCM state. Var so
// the windows test can stub it.
var serviceStateFn = func() (svc.State, error) {
	m, err := mgr.Connect()
	if err != nil {
		return 0, err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return 0, err
	}
	return st.State, nil
}

// detectRestartWindows reports a live pulsemon service: the registration
// exists AND the SCM says it is running. (The in-dashboard update, the
// console `update --restart`, and the rollback watchdog all restart the
// SAME service; performRestartWindows branches on whether the CALLER is
// that service.) A stopped/absent service gets the install-and-hint answer,
// the Windows twin of the systemd "no live service" path.
func detectRestartWindows() string {
	st, err := serviceStateFn()
	if err != nil || st != svc.Running {
		return ""
	}
	return "windows-service"
}

// performRestartWindows is the shared performRestart on Windows. The new
// binary is ALREADY in place when this runs (installBinary did the
// rename-aside + rename-in), so:
//
//   - the service process (the in-dashboard update) is about to die: detach
//     a restart helper from the NEW binary, then ask the SCM to stop us.
//     The helper (same virtual-account token) starts the service once it
//     observes the stopped state.
//   - an external process (console `pulsemon update --restart`, the rollback
//     watchdog) survives the restart: a synchronous stop→start.
func performRestartWindows(string) error {
	if isWindowsService() {
		exe, err := serviceBinPathFn()
		if err != nil {
			return err
		}
		if err := spawnRestartHelper(exe); err != nil {
			return fmt.Errorf("spawn restart helper: %w", err)
		}
		return selfStopFn()
	}
	return restartWindowsServiceFn()
}

// serviceBinPathFn reads the service's binPath from the SCM — the canonical
// in-place binary the service runs from. os.Executable() would also be the
// new binary for the updating service, but the rollback WATCHDOG runs from
// <exe>.prev, which is renamed out from under it during a rollback — its
// PEB path then points at a file that no longer exists. The SCM binPath is
// stable in both cases. Var so the windows test can stub it.
var serviceBinPathFn = func() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("open SCM: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return "", fmt.Errorf("open service %s: %w", serviceName, err)
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return "", fmt.Errorf("service config: %w", err)
	}
	// sc create stores the binPath quoted; strip the surrounding quotes.
	return strings.Trim(cfg.BinaryPathName, `"`), nil
}

// spawnRestartHelper detaches `pulsemon __restart-helper` from the binary at
// exePath (the NEW one, in place). detachSpawn (update_detach_windows.go)
// gives it no console and no inherited pipes, so it survives the service's
// death. Var so the windows test can stub it.
var spawnRestartHelper = func(exePath string) error {
	return detachSpawn(exec.Command(exePath, "__restart-helper"))
}

// selfStopFn asks the SCM to stop our own service. The Stop control reaches
// the service handler, which runs the clean drain and exits; the detached
// helper starts the service again. Returns once the stop is ISSUED (the
// drain then runs in the handler, not here). Var so the windows test can
// stub it.
var selfStopFn = func() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("open SCM: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service %s: %w", serviceName, err)
	}
	defer s.Close()
	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("stop service %s: %w", serviceName, err)
	}
	return nil
}

// stopWindowsServiceFn stops the pulsemon service and WAITS for the clean
// shutdown (probe/alert/HTTP drain) to reach the stopped state. A Start on
// a StopPending service is refused, so the wait is not optional. Var so the
// windows test can stub it.
var stopWindowsServiceFn = func() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("open SCM: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service %s: %w", serviceName, err)
	}
	defer s.Close()
	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("stop service %s: %w", serviceName, err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		st, err := s.Query()
		if err != nil {
			return fmt.Errorf("query service %s: %w", serviceName, err)
		}
		if st.State == svc.Stopped {
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
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("open SCM: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service %s: %w", serviceName, err)
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service %s: %w", serviceName, err)
	}
	return nil
}

// restartWindowsServiceFn performs a synchronous stop→start of the pulsemon
// service through the native SCM (golang.org/x/sys/windows/svc/mgr): no
// PowerShell child process (the old `powershell -Command "Restart-Service"`
// spawned a second process and depended on the PowerShell install). Used by
// the `pulsemon restart` subcommand (via the listener seam) and by external
// update callers — processes that SURVIVE the restart and can block on it.
// Var so the windows test can stub it.
var restartWindowsServiceFn = func() error {
	if err := stopWindowsServiceFn(); err != nil {
		return err
	}
	return startWindowsServiceFn()
}
