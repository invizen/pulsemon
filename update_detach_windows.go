//go:build windows

package main

import (
	"os/exec"

	"golang.org/x/sys/windows"
)

// stillActive is Windows' STILL_ACTIVE exit code for a running process.
const stillActive = 259

// processGone reports whether pid no longer exists. An unopenable PID is
// gone; otherwise the query-limited handle's exit code decides.
func processGone(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return true
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return true
	}
	return code != stillActive
}

// detachSpawn starts cmd fully detached (I2 watchdog): no console window,
// independent of the caller's process group, so it survives the caller's
// death (the server process dies with the service restart it triggers).
func detachSpawn(cmd *exec.Cmd) error {
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
	}
	return cmd.Start()
}
