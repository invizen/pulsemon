//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/svc"
)

// serviceName is the SCM service name. The installer registers it as
// "Pulsemon" (capital P); service names are case-insensitive for lookup, so
// one const keeps the spelling out of the call sites (svc.Run, the SCM
// restart paths, the installer).
const serviceName = "Pulsemon"

// defaultDBPath is the Windows data location: %ProgramData%\Pulsemon, the
// machine-wide (not per-user) store a service should use. The data dir's
// ACL is the installer's (NT SERVICE\Pulsemon + Administrators — see M1 in
// installer/pulsemon.iss) and survives user logoffs.
func defaultDBPath() string {
	return filepath.Join(os.Getenv("ProgramData"), "Pulsemon", "pulsemon.db")
}

// ensureDataDir creates the Windows data dir if missing. The Inno
// installer also creates it (and locks its ACL down — see M1 in
// installer/pulsemon.iss); this makes a manual/console run work without
// it. It operates on the directory of the DB actually in use
// (dbPathFromEnv — PULSEMON_DB when set): the old code hardcoded
// defaultDBPath(), so an operator who pointed PULSEMON_DB elsewhere was
// left with a DB whose parent nothing ever created, and a RELATIVE
// PULSEMON_DB would have planted the database in the process's working
// directory (the "%ProgramData% is always absolute" reasoning only
// covered the default path). MkdirAll failures are returned: a data dir
// that cannot be created means the server cannot start, and that must be
// loud.
func ensureDataDir() error {
	dbPath := dbPathFromEnv()
	if !filepath.IsAbs(dbPath) {
		return fmt.Errorf("PULSEMON_DB must be an absolute path (got %q): a relative path would put the database — and its secrets — in the process's working directory", dbPath)
	}
	dir := filepath.Dir(dbPath)
	if _, err := os.Stat(dir); err == nil {
		// Existing dir: the installer's ACL (a service install) or a
		// prior run's hardening stands — re-applying icacls would also
		// strip grants the installer manages.
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create data dir %s: %w", dir, err)
	}
	// A NEWLY created dir inherits the parent's ACL — under %ProgramData%
	// that is BUILTIN\Users:(RX), which would leave pulsemon.db (bcrypt
	// hashes, webhook/SMTP secrets) readable by every local user on a
	// portable run. Lock it down to Administrators + the running user
	// BEFORE the DB file is written (2026-11-25 external review MINOR-26).
	// The installer grants the VSA additively on service installs. A
	// hardening failure is fatal: a world-readable secret store must not
	// run silently.
	if out, err := exec.Command("icacls", dir, "/inheritance:r",
		"/grant", "Administrators:(OI)(CI)F",
		"/grant", currentWindowsUser()+":(OI)(CI)F").CombinedOutput(); err != nil {
		return fmt.Errorf("harden data dir %s ACL: %v: %s", dir, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// currentWindowsUser is "DOMAIN\user" from whoami (present on every
// supported Windows): icacls's grant target for the portable-run owner.
func currentWindowsUser() string {
	out, err := exec.Command("whoami").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// hardenDataPath is a no-op on Windows: there is no umask, and the data
// directory's ACL is set by the installer (a service install) or by
// ensureDataDir's icacls pass (a newly created portable dir) — the CLI
// path opens the store in an already-existing dir.
func hardenDataPath(dbPath string) {}

// icmpHint is the /api/healthz hint shown when no ICMP transport could open.
func icmpHint() string {
	return "ICMP socket unavailable: the unprivileged datagram socket failed to open. Check that a firewall / antivirus isn't blocking ICMP echo, and restart the service (a boot-timing race is the usual cause). Note: the raw-socket fallback needs elevation and is unavailable to the service's virtual account (NT SERVICE\\Pulsemon), so the datagram socket is the only ICMP path."
}

// isWindowsService reports whether this process runs under the Service
// Control Manager. svc.IsWindowsService() (x/sys/windows/svc) checks BOTH
// the session-0 AND the parent being services.exe — the session-0-only
// check this file used misclassified Task Scheduler / WinRM / NSSM / CI
// runner launches into the service path, where svc.Run then fatals
// (2026-11-25 external review MINOR-26). Var so a windows test can stub
// it: a test process must not be reclassified as the service.
var isWindowsService = func() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
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
		runServer(stop, nil)
		return
	}
	if err := svc.Run(serviceName, &pulsemonHandler{}); err != nil {
		log.Fatalf("pulsemon service: %v", err)
	}
}

// pulsemonHandler is the Windows service control handler (x/sys/windows/svc
// v0.50.0 API: Execute reads ChangeRequest from r, writes Status to s, and
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
	ready := make(chan struct{})
	// Report Running ONLY once the server is actually listening: a DB/TLS
	// init fatal then exits the process while the SCM still sees
	// StartPending — a start failure, not a runtime crash (2026-11-25
	// external review MINOR-26: the old shape posted Running before
	// runServer began, masking startup config errors as runtime crashes).
	go func() {
		defer close(done)
		runServer(stop, func() { close(ready) })
	}()
	select {
	case <-ready:
	case <-done:
		// The server returned before it ever listened (an init fatal
		// os.Exit's first; a clean return here is the only survivor).
		s <- svc.Status{State: svc.Stopped}
		return false, 0
	}
	s <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case req, ok := <-r:
			if !ok {
				// SCM closed the control channel (tearing the service
				// down). Post StopPending FIRST:
				// without it the SCM still believes the service is
				// Running and its stop timer can kill the process mid
				// drain on box shutdown.
				s <- svc.Status{State: svc.StopPending, WaitHint: 40000}
				close(stop)
				<-done
				s <- svc.Status{State: svc.Stopped}
				return false, 0
			}
			switch req.Cmd {
			case svc.Stop, svc.Shutdown:
				// StopPending + WaitHint while the drain runs (same
				// reason): the handler blocks here until the server
				// finishes its graceful drain; the hint tells the SCM
				// we are alive and working, so a slow-but-progressing
				// shutdown is not killed.
				s <- svc.Status{State: svc.StopPending, WaitHint: 40000}
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
