package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
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

func main() {
	// Self-update: `zenmon update` (works from any directory — it finds the
	// running binary via os.Executable). See update.go. runUpdate only
	// returns on success paths (errors exit itself), so return here to keep
	// the server from starting afterwards.
	if len(os.Args) > 1 && os.Args[1] == "update" {
		runUpdate(os.Args[2:])
		return
	}

	// Healthcheck (Docker HEALTHCHECK / systemd ExecStartPre): open the store
	// via NewDB so the pragmas (busy_timeout, WAL, foreign_keys) apply — the
	// old code used a bare sql.Open with a 0 ms busy_timeout, which failed
	// with SQLITE_BUSY the instant a probe write or WAL checkpoint was in
	// flight. NewDB's SELECT 1 already verifies reachability; the COUNT
	// additionally proves the schema exists.
	if len(os.Args) > 1 && os.Args[1] == "-healthz" {
		db, err := NewDB(dbPathFromEnv())
		if err != nil {
			log.Printf("healthz: open: %v", err)
			os.Exit(1)
		}
		defer db.Close()
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM sensors").Scan(&n); err != nil {
			log.Printf("healthz: query: %v", err)
			os.Exit(1)
		}
		return
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

	// 2. Drain active HTTP connections.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server shutdown error: %v", err)
	}
	log.Println("Server exited")
}
