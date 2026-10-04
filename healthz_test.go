package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// TestHealthzPragmaParity pins the fix for the -healthz flag bypassing the
// DSN pragmas. The old code opened the store with a bare sql.Open (no
// _pragma=busy_timeout / journal_mode / foreign_keys), so the healthcheck ran
// with a 0 ms busy timeout — any moment of write contention (probe worker
// mid-write, WAL checkpoint) failed it with SQLITE_BUSY and could crash-loop
// a container. -healthz must open the store exactly like the app does (NewDB).
func TestHealthzPragmaParity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "healthz.db")
	app, err := NewDB(path)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer app.Close()
	if _, err := app.Exec("CREATE TABLE sensors (id TEXT PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Exec("INSERT INTO sensors (id) VALUES ('a')"); err != nil {
		t.Fatal(err)
	}
	// app stays open for the whole test — it simulates the running instance
	// whose write transactions the healthcheck has to coexist with.

	t.Run("old-style bare open has zero busy timeout", func(t *testing.T) {
		bare, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatalf("bare open: %v", err)
		}
		defer bare.Close()
		var bt int
		if err := bare.QueryRow("PRAGMA busy_timeout").Scan(&bt); err != nil {
			t.Fatalf("query busy_timeout: %v", err)
		}
		if bt != 0 {
			t.Fatalf("bare open busy_timeout = %d, want 0 (this is the bug the old -healthz had)", bt)
		}
	})

	t.Run("healthz open via NewDB has the app pragmas", func(t *testing.T) {
		// This is exactly what `zenmon -healthz` does now.
		hz, err := NewDB(path)
		if err != nil {
			t.Fatalf("healthz NewDB: %v", err)
		}
		defer hz.Close()
		var bt int
		if err := hz.QueryRow("PRAGMA busy_timeout").Scan(&bt); err != nil {
			t.Fatalf("query busy_timeout: %v", err)
		}
		if bt != 15000 {
			t.Fatalf("healthz busy_timeout = %d, want 15000", bt)
		}
		var jm string
		if err := hz.QueryRow("PRAGMA journal_mode").Scan(&jm); err != nil {
			t.Fatalf("query journal_mode: %v", err)
		}
		if jm != "wal" {
			t.Fatalf("healthz journal_mode = %q, want wal", jm)
		}
		var n int
		if err := hz.QueryRow("SELECT COUNT(*) FROM sensors").Scan(&n); err != nil {
			t.Fatalf("healthz count query: %v", err)
		}
		if n != 1 {
			t.Fatalf("sensors count = %d, want 1", n)
		}
	})

	t.Run("write contention: bare fails instantly, NewDB waits it out", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Hold a write transaction for ~700 ms (simulates a probe write).
		holder, err := NewDB(path)
		if err != nil {
			t.Fatal(err)
		}
		defer holder.Close()
		hconn, err := holder.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer hconn.Close()
		done := make(chan struct{})
		go func() {
			defer close(done)
			if _, err := hconn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
				t.Errorf("holder begin: %v", err)
				return
			}
			time.Sleep(700 * time.Millisecond)
			_, _ = hconn.ExecContext(ctx, "COMMIT")
		}()
		time.Sleep(50 * time.Millisecond) // let the holder grab the lock

		// The old healthz (bare open, 0 ms timeout) dies the instant it
		// hits the write lock.
		start := time.Now()
		bare, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatalf("bare open: %v", err)
		}
		_, bareErr := bare.Exec("BEGIN IMMEDIATE")
		bareDur := time.Since(start)
		bare.Close()
		if bareErr == nil {
			t.Fatal("bare open: expected SQLITE_BUSY under write contention")
		}
		if !strings.Contains(strings.ToLower(bareErr.Error()), "busy") &&
			!strings.Contains(strings.ToLower(bareErr.Error()), "locked") {
			t.Fatalf("bare open error = %v, want busy/locked", bareErr)
		}
		if bareDur > 500*time.Millisecond {
			t.Fatalf("bare open should fail instantly (0 ms timeout), took %v", bareDur)
		}

		// The fixed healthz (NewDB, 15 s timeout) blocks until the writer
		// commits, then proceeds.
		waiter, err := NewDB(path)
		if err != nil {
			t.Fatal(err)
		}
		defer waiter.Close()
		wconn, err := waiter.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer wconn.Close()
		start = time.Now()
		if _, err := wconn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
			t.Fatalf("NewDB connection should wait out the 700 ms write lock (15 s timeout): %v", err)
		}
		waitDur := time.Since(start)
		if _, err := wconn.ExecContext(ctx, "COMMIT"); err != nil {
			t.Fatal(err)
		}
		<-done
		// It must have actually waited (the lock is held until ~700 ms),
		// not succeeded before the holder had it.
		if waitDur < 300*time.Millisecond {
			t.Fatalf("waiter succeeded in %v — it did not wait on the held write lock", waitDur)
		}
	})
}

// TestHealthzEnvDefault pins the db path resolution shared by -healthz and the
// server: ZENMON_DB wins, the Docker default otherwise.
func TestHealthzEnvDefault(t *testing.T) {
	t.Setenv("ZENMON_DB", "")
	if got := dbPathFromEnv(); got != "/data/zenmon.db" {
		t.Fatalf("default path = %q, want /data/zenmon.db", got)
	}
	t.Setenv("ZENMON_DB", "/tmp/elsewhere.db")
	if got := dbPathFromEnv(); got != "/tmp/elsewhere.db" {
		t.Fatalf("env path = %q, want /tmp/elsewhere.db", got)
	}
}
