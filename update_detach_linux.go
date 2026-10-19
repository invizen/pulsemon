//go:build linux

package main

import (
	"os/exec"
	"syscall"
)

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
