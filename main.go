package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// listenAddr is the HTTP listen address. Override with ZENMON_ADDR — a full
// "host:port" (e.g. ":9299" for all interfaces on 9299, "127.0.0.1:9299" for
// localhost only, or "10.0.0.5:9299" for a specific interface). Port 8080 was
// the original default but is heavily claimed on homelab boxes (Traefik,
// Pi-hole, reverse proxies); 9299 is the new default.
func listenAddr() string {
	if a := os.Getenv("ZENMON_ADDR"); a != "" {
		return a
	}
	return ":9299"
}

// dbPathFromEnv returns the database path: ZENMON_DB if set, else the
// Docker default.
func dbPathFromEnv() string {
	if p := os.Getenv("ZENMON_DB"); p != "" {
		return p
	}
	return "/data/zenmon.db"
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
	case "-v", "-version", "--version", "version":
		fmt.Println("zenmon", Version)
		return dExit0
	}
	// Anything else must be a known flag. Unknown flags (zenmon -invalid,
	// zenmon --foo) previously fell through to a normal server start — the
	// operator's typo silently booted a dashboard instead of surfacing an
	// error.
	if strings.HasPrefix(args[1], "-") {
		fmt.Fprintf(os.Stderr, "zenmon: unknown flag %q\n\n", args[1])
		fmt.Fprint(os.Stderr, "Usage:\n  zenmon            start the monitor + dashboard\n  zenmon update [check|VERSION] [--restart]  self-update (check only, or pin a version); --restart also restarts the service\n  zenmon -healthz     verify the store is usable (container healthcheck)\n  zenmon -version     print the build version and exit\n")
		if os.Getenv("ZENMON_TEST_NOFATAL") == "" {
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
	addr := listenAddr()
	srv := &http.Server{
		Addr:              addr,
		Handler:           server.Mux(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Println("Starting server on " + addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Listen: %v", err)
		}
	}()

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
