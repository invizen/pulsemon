//go:build windows

package main

import (
	"os/exec"

	"golang.org/x/sys/windows"
)

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
