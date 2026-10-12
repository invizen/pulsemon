//go:build windows

package main

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// defaultDBPath is the Windows data location: %ProgramData%\Pulsemon, the
// machine-wide (not per-user) store a service should use. ProgramData is
// writable by the service's LocalSystem account and survives user logoffs.
func defaultDBPath() string {
	return filepath.Join(os.Getenv("ProgramData"), "Pulsemon", "pulsemon.db")
}

// ensureDataDir creates the Windows data dir if missing. The Inno installer
// also creates it; this makes a manual/console run work without it.
func ensureDataDir() {
	_ = os.MkdirAll(filepath.Dir(defaultDBPath()), 0o755)
}

// icmpHint is the /api/healthz hint shown when no ICMP transport could open.
func icmpHint() string {
	return "ICMP socket unavailable: the unprivileged datagram socket failed and the raw fallback needs elevation. Run the pulsemon service under an account that can send ICMP (Local System by default), or check that a firewall / antivirus isn't blocking ICMP echo."
}

// isWindowsService reports whether this process is running under the Service
// Control Manager. Services run in the non-interactive session 0, while
// interactive user processes run in session 1+; ProcessIdToSessionId is the
// standard, reliable discriminator. (x/sys/windows/svc in v0.48.0 has no
// IsServiceRunning helper, so we check the session directly.)
func isWindowsService() bool {
	var sessionID uint32
	if err := windows.ProcessIdToSessionId(uint32(os.Getpid()), &sessionID); err != nil {
		return false
	}
	return sessionID == 0
}

// runMain is the Windows entry point. Under the SCM it runs as a service
// (svc.Run drives the handler); otherwise (a manual console run, e.g. for
// testing) it blocks on Ctrl+C like the Linux path.
func runMain() {
	cleanupStaleBinary() // remove a <exe>.old left by a prior self-update
	if !isWindowsService() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		stop := make(chan struct{})
		go func() {
			<-sig
			close(stop)
		}()
		runServer(stop)
		return
	}
	if err := svc.Run("pulsemon", &pulsemonHandler{}); err != nil {
		log.Fatalf("pulsemon service: %v", err)
	}
}

// pulsemonHandler is the Windows service control handler (x/sys/windows/svc
// v0.48.0 API: Execute reads ChangeRequest from r, writes Status to s, and
// returns a service-specific-exit-code flag + exit code). It reports
// StartPending → Running to the SCM, runs the server in a goroutine, and — on
// a Stop/Shutdown command — closes the server's stop channel and WAITS for the
// clean shutdown to finish before reporting Stopped. That ordering keeps the
// SCM from killing the process mid-drain (the probe-stop, alert-drain, and
// HTTP shutdown in runServer all complete first).
type pulsemonHandler struct{}

func (h *pulsemonHandler) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.StartPending}

	stop := make(chan struct{})
	done := make(chan struct{})
	s <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	go func() {
		defer close(done)
		runServer(stop)
	}()

	for {
		select {
		case req, ok := <-r:
			if !ok {
				// SCM closed the control channel (tearing the service down).
				close(stop)
				<-done
				s <- svc.Status{State: svc.Stopped}
				return false, 0
			}
			switch req.Cmd {
			case svc.Stop, svc.Shutdown:
				close(stop)
				<-done // wait for the clean shutdown before reporting Stopped
				s <- svc.Status{State: svc.Stopped}
				return false, 0
			}
			// Interrogate and the rest are handled/ignored: the SCM answers
			// Interrogate from the last Status we posted.
		case <-done:
			// The server returned on its own (a fatal log.Fatalf would have
			// os.Exit'd already, so a clean return means orderly completion).
			s <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
}
