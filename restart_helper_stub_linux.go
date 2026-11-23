//go:build !windows

package main

import (
	"fmt"
	"os"
)

// runRestartHelper is the non-Windows twin of the Windows self-restart
// helper (restart_helper_windows.go): the subcommand exists on every
// platform so the shared dispatch table in main.go compiles; on Linux the
// systemd restart path is synchronous for the caller, so no helper is
// needed and the subcommand is a loud no-op.
func runRestartHelper() int {
	fmt.Fprintln(os.Stderr, "pulsemon: __restart-helper is a Windows service-internal subcommand")
	return 1
}
