//go:build linux

package main

import (
	"errors"
	"os"
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

// systemdRunPath is the systemd-run binary the watchdog spawner uses to
// place the watchdog in its own transient scope cgroup. A var so tests can
// inject a fixed path (or "" to exercise the plain-detach fallback).
// Unlike resolveSystemctl, a missing binary reports "": the caller must
// distinguish "no systemd-run" (fall back to a plain detach) from a path
// to exec.
var systemdRunPath = resolveSystemdRun

// resolveSystemdRun picks the systemd-run binary. The fixed system
// locations win over $PATH so a writable directory early in PATH cannot
// substitute its own "systemd-run"; PATH is only the fallback for unusual
// layouts (NixOS, containers).
func resolveSystemdRun() string {
	for _, p := range []string{"/usr/bin/systemd-run", "/bin/systemd-run"} {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	if p, err := exec.LookPath("systemd-run"); err == nil {
		return p
	}
	return ""
}
