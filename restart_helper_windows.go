//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// runRestartHelper is the detached self-restart helper for the Windows
// in-dashboard update: the updating service process is about to die, so a
// child of the NEW binary waits here for the service to reach the stopped
// state, then starts it again. The child inherits the service's virtual
// account (NT SERVICE\Pulsemon), which the SCM grants full control of its
// own service.
//
// It logs to <datadir>\pulsemon-restart.log: the process is detached with
// no console, so the file is the only post-mortem audience.
//
// Exit codes: 0 = service started; non-zero = the service was left as-is
// (a human looks at the log).
func runRestartHelper() int {
	logLine := func(format string, a ...any) {
		// Go forbids extra fixed args alongside a `s...` expansion (the
		// expansion must supply the ENTIRE variadic tail), so the timestamp
		// rides in the slice.
		args := append([]any{time.Now().Format(time.RFC3339)}, a...)
		line := fmt.Sprintf("%s restart-helper: "+format+"\n", args...)
		path := filepath.Join(filepath.Dir(dbPathFromEnv()), "pulsemon-restart.log")
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			log.Printf("restart-helper: log write: %v", err)
			return
		}
		defer f.Close()
		_, _ = f.WriteString(line)
	}

	logLine("started; waiting for the %s service to stop", serviceName)
	m, err := mgr.Connect()
	if err != nil {
		logLine("open SCM failed: %v", err)
		return 1
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		logLine("open service failed: %v", err)
		return 2
	}
	defer s.Close()

	// The updating service's clean drain is bounded at ~30s (probe + alert
	// + HTTP backstops) plus SCM stop grace; 90s is generous headroom.
	deadline := time.Now().Add(90 * time.Second)
	for {
		st, err := s.Query()
		if err != nil {
			logLine("query service failed: %v", err)
			return 3
		}
		if st.State == svc.Stopped {
			break
		}
		if time.Now().After(deadline) {
			logLine("service did not reach stopped within 90s; leaving it alone")
			return 4
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err := s.Start(); err != nil {
		logLine("start service failed: %v", err)
		return 5
	}
	logLine("service started")
	return 0
}
