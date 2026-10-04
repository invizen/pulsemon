package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// Self-update: `zenmon update` (works from any directory — it finds the
	// running binary via os.Executable). See update.go. runUpdate only
	// returns on success paths (errors exit itself), so return here to keep
	// the server from starting afterwards.
	if len(os.Args) > 1 && os.Args[1] == "update" {
		runUpdate(os.Args[2:])
		return
	}

	// Real healthcheck (SPEC fix #5): the flag actually opens the database and
	// runs a query. Exits 0 only when the store is usable.
	if len(os.Args) > 1 && os.Args[1] == "-healthz" {
		dbPath := os.Getenv("ZENMON_DB")
		if dbPath == "" {
			dbPath = "/data/zenmon.db"
		}
		db, err := sql.Open("sqlite", dbPath)
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

	dbPath := os.Getenv("ZENMON_DB")
	if dbPath == "" {
		dbPath = "/data/zenmon.db"
	}

	db, err := NewDB(dbPath)
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
	defer cancel()
	go pw.Run(ctx)

	server := NewServer(db, pw)
	srv := &http.Server{
		Addr:              ":8080",
		Handler:           server.Mux(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Println("Starting server on :8080")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop
	log.Println("Shutting down server...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server shutdown error: %v", err)
	}
	log.Println("Server exited")
}
