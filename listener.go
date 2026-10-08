package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Listener / TLS configuration.
//
// HTTP: PULSEMON_ADDR env (install-time, operator choice) or ":9299". The
// dashboard does NOT manage the HTTP port.
//
// HTTPS: served on the "listener_https_port" settings row (default 443),
// bound to the same host as PULSEMON_ADDR. When a cert/key pair is in
// place the dashboard serves HTTPS ONLY on that port — the HTTP port is
// not bound, so nothing is ever reachable in plaintext.
//
// TLS cert/key resolution order:
//  1. PULSEMON_CERT + PULSEMON_KEY env (install-time; both required)
//  2. <data>/tls/cert.pem + key.pem (written by the dashboard's
//     Settings → TLS upload; lives in the data volume so it survives
//     container rebuilds)
//
// A corrupt or mismatched pair in place at startup must NOT fail the
// process: pulsemon keeps serving plain HTTP and the user fixes it from
// the dashboard.

const defaultHTTPSPort = 443

type listenerCfg struct {
	httpsPort int
	certPath  string // "" = plain HTTP only
	keyPath   string
	source    string // "env" | "dashboard" | ""
}

// loadListenerCfg resolves the listener configuration from env + settings.
// db may be nil (pre-DB contexts); env is always read first.
func loadListenerCfg(db *DB) listenerCfg {
	c := listenerCfg{httpsPort: defaultHTTPSPort}
	if db == nil {
		return c
	}
	if p := db.GetSetting("listener_https_port"); p != "" {
		if n, err := parsePort(p); err == nil {
			c.httpsPort = n
		}
	}
	if envCert, envKey := certPaths(); envCert != "" {
		c.certPath, c.keyPath, c.source = envCert, envKey, "env"
		return c
	}
	dir := tlsDir(db)
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if fileExists(cert) && fileExists(key) {
		c.certPath, c.keyPath, c.source = cert, key, "dashboard"
	}
	return c
}

// tlsDir is where the dashboard stores uploaded TLS material: inside the
// data dir (the one volume that always exists and persists).
func tlsDir(db *DB) string {
	return filepath.Join(filepath.Dir(dbPathFromEnv()), "tls")
}

// parsePort validates a listener port: 1..65535.
func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("not a port: %q", s)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port out of range: %d", n)
	}
	return n, nil
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// httpsAddrFor derives the TLS listen address from PULSEMON_ADDR (same
// host, HTTPS port): ":80" → ":443", "127.0.0.1:8080" → "127.0.0.1:443".
func httpsAddrFor(httpsPort int) string {
	addr := listenAddr()
	host := ""
	if i := strings.LastIndex(addr, ":"); i >= 0 && i+1 < len(addr) {
		host = addr[:i]
	}
	return net.JoinHostPort(host, strconv.Itoa(httpsPort))
}

// isContainer reports whether we are the entrypoint of a container
// (re-exec is not possible: when PID 1 exits, the container stops).
func isContainer() bool {
	if exe, err := os.Executable(); err == nil && exe == "/pulsemon" {
		return true
	}
	if fileExists("/.dockerenv") {
		return true
	}
	return false
}

// isSystemdManaged reports whether systemd started this process.
func isSystemdManaged() bool {
	return os.Getenv("SYSTEMD_EXEC_PID") != ""
}

// restartOutcome is what a restart request produced: the process restarted
// (or is about to), or a hint the operator must run (containers).
type restartOutcome struct {
	restarted bool
	hint      string
}

// requestRestart makes a listener config change take effect. The listener
// binds at startup, so a config change needs a fresh process. Each runtime
// has its own respawn mechanism:
//
//   - systemd service → a DETACHED `pulsemon restart` helper runs
//     `systemctl restart` (blocking there is fine: it is a separate
//     process). Our own SIGTERM comes from systemctl's stop phase and
//     drives the clean shutdown in main. The helper must NOT inherit
//     SYSTEMD_EXEC_PID — it is an external caller, not the service.
//   - container → SIGTERM to ourselves; `restart: unless-stopped` makes
//     the docker daemon respawn the container with the new config.
//   - bare process → re-exec: fork a child (PULSEMON_RESTARTING=1, whose
//     listener retries the bind for 30s while we still hold the port)
//     and SIGTERM ourselves so the child's bind succeeds.
//
// Callers must have flushed their API response BEFORE calling this: the
// process is about to die.
func requestRestart() restartOutcome {
	exe, _ := os.Executable()
	switch {
	case isSystemdManaged():
		cmd := exec.Command(exe, "restart")
		env := make([]string, 0, len(os.Environ()))
		for _, kv := range os.Environ() {
			if strings.HasPrefix(kv, "SYSTEMD_EXEC_PID=") {
				continue // the helper must act as an external caller
			}
			env = append(env, kv)
		}
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			return restartOutcome{hint: "restart the pulsemon service to apply TLS"}
		}
		return restartOutcome{restarted: true}
	case isContainer():
		syscall.Kill(os.Getpid(), syscall.SIGTERM)
		return restartOutcome{
			restarted: true,
			hint:      "if the dashboard does not return on HTTPS shortly, run: docker restart pulsemon",
		}
	default:
		reexec()
		syscall.Kill(os.Getpid(), syscall.SIGTERM)
		return restartOutcome{restarted: true}
	}
}

// reexec forks a fresh copy of this process. The child sets
// PULSEMON_RESTARTING=1 so its listen loop retries the bind for 30s
// while this process still holds the port.
func reexec() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), "PULSEMON_RESTARTING=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		// re-exec failed — keep the old config running rather than die
		return
	}
}

// runRestartCommand is the manual `pulsemon restart` subcommand: restart
// the pulsemon installation on this box (an external caller, so blocking
// on systemctl is fine):
//   - systemd service (user, then system) → systemctl restart
//   - inside a container → SIGTERM to PID 1 (the entrypoint); the
//     container's restart policy respawns it
//   - otherwise → hint (a bare process has no manager to ask)
func runRestartCommand() dispatchKind {
	if err := restartSystemdService(); err == nil {
		fmt.Println("pulsemon: service restarted")
		return dExit0
	}
	if isContainer() {
		if err := syscall.Kill(1, syscall.SIGTERM); err == nil {
			log.Println("pulsemon: signalled the entrypoint; the container's restart policy respawns it")
			return dExit0
		}
	}
	if isSystemdManaged() {
		// We ARE the service process: cannot block on our own restart.
		// Ask a detached helper and let the stop phase's SIGTERM drive
		// the clean shutdown (server context) / exit (subcommand).
		exe, _ := os.Executable()
		cmd := exec.Command(exe, "restart")
		cmd.Env = filterEnv("SYSTEMD_EXEC_PID=")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err == nil {
			return dExit0
		}
	}
	fmt.Fprintln(os.Stderr, "pulsemon: no restartable pulsemon service detected on this host")
	return dExit1
}

// restartSystemdService tries the user session first, then system-wide.
func restartSystemdService() error {
	var last error
	for _, args := range [][]string{{"--user", "restart", "pulsemon"}, {"restart", "pulsemon"}} {
		if err := exec.Command("systemctl", args...).Run(); err == nil {
			return nil
		} else {
			last = err
		}
	}
	return last
}

func filterEnv(prefix string) []string {
	out := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, prefix) {
			out = append(out, kv)
		}
	}
	return out
}
