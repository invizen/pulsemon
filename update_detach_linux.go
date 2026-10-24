//go:build linux

package main

import (
	"errors"
	"os/exec"
	"syscall"
)

// processGone reports whether pid no longer exists. Signal 0 does no harm;
// ESRCH means the process is gone, EPERM means it exists but is not ours.
func processGone(pid int) bool {
	err := syscall.Kill(pid, 0)
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.ESRCH)
}

// detachSpawn starts cmd in its own session with no controlling terminal
// and no stdio, so it survives the caller's death (the I2 watchdog: the
// server process dies with the service restart it triggers, and the
// watchdog must outlive it).
func detachSpawn(cmd *exec.Cmd) error {
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}
