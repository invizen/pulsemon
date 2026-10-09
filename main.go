package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// listenAddr is the HTTP listen address. Override with PULSEMON_ADDR — a full
// "host:port" (e.g. ":9299" for all interfaces on 9299, "127.0.0.1:9299" for
// localhost only, or "10.0.0.5:9299" for a specific interface). Port 8080 was
// the original default but is heavily claimed on homelab boxes (Traefik,
// Pi-hole, reverse proxies); 9299 is the new default.
func listenAddr() string {
	if a := os.Getenv("PULSEMON_ADDR"); a != "" {
		return a
	}
	return ":9299"
}

// dbPathFromEnv returns the database path: PULSEMON_DB if set, else the
// Docker default.
func dbPathFromEnv() string {
	if p := os.Getenv("PULSEMON_DB"); p != "" {
		return p
	}
	return "/data/pulsemon.db"
}

// certPaths returns the TLS certificate/key pair to serve HTTPS with, or
// ("", "") for plain HTTP. Both PULSEMON_CERT and PULSEMON_KEY must be set
// together — a cert without a key (or vice versa) is a misconfiguration
// worth failing on at startup, not a half-working listener.
// certFatal is the failure path for a partial TLS env config; stubbed in
// tests so log.Fatalf (which exits) does not kill the test process.
var certFatal = func(msg string) { log.Fatal(msg) }

func certPaths() (string, string) {
	cert := os.Getenv("PULSEMON_CERT")
	key := os.Getenv("PULSEMON_KEY")
	if cert == "" && key == "" {
		return "", "" // plain HTTP
	}
	if cert == "" || key == "" {
		certFatal("CRITICAL: PULSEMON_CERT and PULSEMON_KEY must be set together")
	}
	return cert, key
}

// dispatchKind is the outcome of dispatching os.Args.
type dispatchKind int

const (
	dRunServer dispatchKind = iota
	dExit0
	dExit1
	dExit2
)

// dispatch parses the command line and executes any non-server command.
// Only dRunServer means "fall through and start the HTTP server". Keeping it
// out of main() makes the arg handling testable (see cli_test.go); the one
// side effect that must live in main is os.Exit, so the caller exits with the
// kind's status.
func dispatch(args []string) dispatchKind {
	if len(args) <= 1 {
		return dRunServer
	}
	switch args[1] {
	case "update":
		// runUpdate returns its exit code instead of calling os.Exit
		// itself (os.Exit skips deferred cleanup of the downloaded temp
		// file); main() exits with the mapped status.
		switch runUpdate(args[2:]) {
		case 0:
			return dExit0
		case 2:
			return dExit2
		default:
			return dExit1
		}
	case "-healthz", "--healthz":
		return runHealthcheck()
	case "restart":
		// Apply a config that needs a fresh process (listener/TLS).
		return runRestartCommand()
	case "auth-user":
		// Dashboard accounts: pulsemon auth-user add|remove|list [NAME]
		return runAuthUser(args[2:])
	case "-v", "-version", "--version", "version":
		fmt.Println("pulsemon", Version)
		return dExit0
	}
	// Anything else must be a known flag. Unknown flags (pulsemon -invalid,
	// pulsemon --foo) previously fell through to a normal server start — the
	// operator's typo silently booted a dashboard instead of surfacing an
	// error.
	if strings.HasPrefix(args[1], "-") {
		fmt.Fprintf(os.Stderr, "pulsemon: unknown flag %q\n\n", args[1])
		fmt.Fprint(os.Stderr, "Usage:\n  pulsemon            start the monitor + dashboard\n  pulsemon update [check|VERSION] [--restart]  self-update (check only, or pin a version); --restart also restarts the service\n  pulsemon auth-user add <user> <pass>   create a dashboard account (first account enables auth)\n  pulsemon auth-user remove <user>       delete a dashboard account\n  pulsemon auth-user list                list dashboard accounts\n  pulsemon -healthz     verify the store is usable (container healthcheck)\n  pulsemon -version     print the build version and exit\n")
		if os.Getenv("PULSEMON_TEST_NOFATAL") == "" {
			os.Exit(1)
		}
		return dExit1
	}
	return dRunServer
}

// runHealthcheck opens the store via NewDB so the pragmas (busy_timeout,
// WAL, foreign_keys) apply — a bare sql.Open runs with a 0 ms busy_timeout
// and fails with SQLITE_BUSY the instant a probe write or WAL checkpoint is
// in flight, which would crash-loop a container. NewDB's SELECT 1 already
// verifies reachability; the COUNT additionally proves the schema exists.
func runHealthcheck() dispatchKind {
	db, err := NewDB(dbPathFromEnv())
	if err != nil {
		log.Printf("healthz: open: %v", err)
		return dExit1
	}
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM sensors").Scan(&n); err != nil {
		log.Printf("healthz: query: %v", err)
		return dExit1
	}
	return dExit0
}

// tlsKeyPairOK pre-validates the cert+key pair the listener is about to
// serve. tls.LoadX509KeyPair reads both files and parses the key — so an
// encrypted or corrupt key is caught HERE, at startup, with a clear
// message, instead of surfacing mid-handshake from ServeTLS after the
// 30s bind-retry window.
func tlsKeyPairOK(cert, key string) error {
	_, err := tls.LoadX509KeyPair(cert, key)
	return err
}

// startListener starts the HTTP (and, when a TLS pair is in place,
// HTTPS) listener in the background and wires its fatal errors to
// log.Fatalf (same behavior as the old inline goroutine).
//
// HTTPS is served on the configured TLS port; the plain-HTTP port is
// NOT bound when TLS is active — the dashboard is reachable only over
// TLS. This is deliberate: a box that uploaded a cert must not stay
// reachable in plaintext on the old port.
//
// When PULSEMON_RESTARTING is set (we are the child of a re-exec), the
// bind may fail for up to 30s while the parent still holds the port;
// retry with backoff instead of dying.
func startListener(srv *http.Server, db *DB) {
	cfg := loadListenerCfg(db)
	retry := os.Getenv("PULSEMON_RESTARTING") == "1"

	go func() {
		if cfg.certPath != "" {
			if _, err := os.Stat(cfg.certPath); err != nil {
				log.Printf("WARNING: %s is not readable (%v); serving plain HTTP until it is in place", cfg.certPath, err)
			} else if _, err := os.Stat(cfg.keyPath); err != nil {
				log.Printf("WARNING: %s is not readable (%v); serving plain HTTP until it is in place", cfg.keyPath, err)
			} else if err := tlsKeyPairOK(cfg.certPath, cfg.keyPath); err != nil {
				// A pair is in place but unusable (encrypted key,
				// corrupt cert, mismatched pair). Fail fast with the
				// reason instead of looping or serving plaintext.
				log.Fatalf("TLS: %s + %s are in place but cannot be loaded: %v", cfg.certPath, cfg.keyPath, err)
			} else {
				srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
				addr := httpsAddrFor(cfg.httpsPort)
				log.Println("Starting server on " + addr + " (TLS, cert " + cfg.source + ")")
				deadline := time.Now().Add(30 * time.Second)
				for {
					err := listenTLS(srv, addr, cfg.certPath, cfg.keyPath)
					if err == nil {
						return
					}
					if err != http.ErrServerClosed && !retry && time.Now().After(deadline) {
						// TLS was configured and the bind keeps failing:
						// fail fast rather than serve plaintext.
						log.Fatalf("Listen (TLS: %s): %v", addr, err)
					}
					if err == http.ErrServerClosed || time.Now().After(deadline) {
						log.Println("listener stopped")
						return
					}
					time.Sleep(500 * time.Millisecond)
				}
			}
		}
		addr := listenAddr()
		srv.Addr = addr // ListenAndServe defaults to :80 when Addr is empty
		log.Println("Starting server on " + addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Listen: %v", err)
		}
	}()
}

// listenTLS binds and serves TLS on a fresh listener; returns when the
// server is shut down. The listener is always closed so a retry after a
// failed serve does not leak a socket.
func listenTLS(srv *http.Server, addr, cert, key string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	srv.Addr = addr
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ServeTLS(ln, cert, key) }()
	return <-errCh
}

// runAuthUser manages dashboard accounts from the host:
//
//	pulsemon auth-user add <username> <password>
//	pulsemon auth-user remove <username>
//	pulsemon auth-user list
//
// add on an open (no-users) dashboard is what enables authentication.
// remove is refused for the last remaining user — `auth-user remove` on
// the final account errors, and the "disable authentication" action in the
// dashboard (which removes all users) is the explicit off-switch.
func runAuthUser(args []string) dispatchKind {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: pulsemon auth-user add <username> <password> | remove <username> | list")
		return dExit2
	}
	db, err := NewDB(dbPathFromEnv())
	if err != nil {
		log.Printf("auth-user: open: %v", err)
		return dExit1
	}
	defer db.Close()
	// The users table is created by InitSchema (the server runs it on
	// startup); run it here too so the CLI works on a store that has
	// never had a server boot (idempotent).
	if err := db.InitSchema(); err != nil {
		log.Printf("auth-user: schema: %v", err)
		return dExit1
	}
	a := NewAuthState(db)
	switch args[0] {
	case "add":
		if len(args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: pulsemon auth-user add <username> <password>")
			return dExit2
		}
		if err := a.AddUser(args[1], args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "auth-user add:", err)
			return dExit1
		}
		if n, _ := db.UserCount(); n == 1 {
			fmt.Println("Dashboard authentication is now ENABLED —", args[1], "can log in at the dashboard URL.")
		} else {
			fmt.Println("User added:", args[1])
		}
		return dExit0
	case "remove":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: pulsemon auth-user remove <username>")
			return dExit2
		}
		if err := a.RemoveUser(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, "auth-user remove:", err)
			return dExit1
		}
		if n, _ := db.UserCount(); n == 0 {
			fmt.Println("Dashboard authentication is now DISABLED — no users remain.")
		} else {
			fmt.Println("User removed:", args[1])
		}
		return dExit0
	case "list":
		users, err := db.ListUsers()
		if err != nil {
			log.Printf("auth-user list: %v", err)
			return dExit1
		}
		if len(users) == 0 {
			fmt.Println("No dashboard users — authentication is disabled.")
			return dExit0
		}
		for _, u := range users {
			fmt.Println(u.Username)
		}
		return dExit0
	default:
		fmt.Fprintf(os.Stderr, "unknown auth-user action %q\nusage: pulsemon auth-user add <username> <password> | remove <username> | list\n", args[0])
		return dExit2
	}
}

func main() {
	// Self-update, healthcheck, and version are dispatched before the server
	// starts; unknown flags are rejected there (see dispatch).
	switch dispatch(os.Args) {
	case dExit0:
		return
	case dExit1:
		os.Exit(1)
	case dExit2:
		os.Exit(2)
	}

	db, err := NewDB(dbPathFromEnv())
	if err != nil {
		log.Fatalf("Failed to open DB: %v", err)
	}
	defer db.Close()

	if err := db.InitSchema(); err != nil {
		log.Fatalf("Failed to init schema: %v", err)
	}

	if err := db.SeedSensors(); err != nil {
		log.Printf("Warning: failed to seed sensors: %v", err)
	}

	pw := NewProbeWorker(db)
	ctx, cancel := context.WithCancel(context.Background())
	// Track the worker so shutdown can wait for it: Run returns only after
	// every per-sensor probe loop has exited (see ProbeWorker.Run), which is
	// the guarantee that no probe write is in flight when we close the DB.
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		pw.Run(ctx)
	}()

	server := NewServer(db, pw)
	srv := &http.Server{
		// authGate re-checks the enabled state (user count) per request:
		// a host `pulsemon auth-user add/remove` must take effect on the
		// very next request without a restart.
		Handler:           server.authGate(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	startListener(srv, db)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop
	log.Println("Shutting down...")

	// 1. Stop background probing FIRST so no new probe writes start, and wait
	// for in-flight probes to finish (Run blocks until its sensor loops exit).
	cancel()
	select {
	case <-workerDone:
		log.Println("Probe worker stopped")
	case <-time.After(10 * time.Second):
		// Each in-flight probe is bounded by its own timeout (default 1s),
		// so this is effectively unreachable; if it ever fires, the DB close
		// below would abort an in-flight write — log it loudly.
		log.Println("WARNING: probe worker did not stop in 10s; in-flight probes may be aborted")
	}

	// 2. Abort in-flight webhook POSTs. Without this, a delivery stuck in a
	// network blip keeps its connection open until the client's 10s timeout
	// and holds process exit that long; with stopCtx cancelled, it aborts at
	// the next read instead.
	pw.StopAlerts()

	// 3. Drain in-flight alert deliveries BEFORE the deferred db.Close: an
	// alert fired on the final probe tick is a fire-and-forget goroutine
	// whose first act is a settings read — without this, Close() lands mid
	// delivery and the alert dies. In-flight POSTs are already aborted by
	// StopAlerts, so this drain is effectively immediate; the 15s is a
	// backstop only.
	pw.DrainAlerts(15 * time.Second)
	log.Println("Alert deliveries drained")

	// 4. Drain active HTTP connections.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server shutdown error: %v", err)
	}
	log.Println("Server exited")
}
