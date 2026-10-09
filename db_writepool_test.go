package main

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// TestConcurrentProbeWritesDoNotBusy is the guard for the "SQLite is a single
// writer, so SetMaxOpenConns(10) will throw busy/locked errors under load"
// finding. It drives the doProbe write pattern — concurrent INSERT INTO probes
// + UPDATE sensors, plus the one Begin()/Commit transaction (SetSensorTags) —
// from many goroutines, and adds a WRITE-LOCK HOLDER (a goroutine with an
// uncommitted transaction) that holds the exclusive SQLite write lock for 400ms
// while the writers fire. Under the real NewDB config (WAL + busy_timeout(15000)
// + MaxOpenConns(10)) every blocked writer WAITS (400ms << 15s) and then
// succeeds: zero errors, all rows land, and the pool drains. This refutes
// "periodic database is locked errors under fleet growth."
//
// The production write pattern is exactly this: per-sensor single-statement
// INSERTs/UPDATEs (microseconds each, serialized by SQLite's internal write
// lock), and one short transaction (SetSensorTags: a DELETE + a few INSERTs).
// No single write holds the lock for seconds, so busy_timeout never trips.
func TestConcurrentProbeWritesDoNotBusy(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "writepool.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	const nSensors = 24
	for i := 0; i < nSensors; i++ {
		id := fmt.Sprintf("w%d", i)
		if _, err := db.Exec(`INSERT INTO sensors (id,name,target,interval_s,timeout_ms,loss_warn,down_after,state,status,created_at)
			VALUES (?,?,?,5,1000,25,2,'active','up','2026-01-01T00:00:00Z')`, id, id, "127.0.0.1"); err != nil {
			t.Fatalf("insert sensor: %v", err)
		}
	}

	// Lock-holder: a goroutine grabs the exclusive SQLite write lock with an
	// uncommitted write and holds it for 400ms, then releases it. Writers that
	// land inside that window block on the write lock; busy_timeout(15000) makes
	// them WAIT (400ms << 15s) and then succeed — zero errors. (Holding the lock
	// for the whole test would keep it past the 15s busy timeout and legitimately
	// fail — that is NOT the production pattern, where no single write holds the
	// lock for seconds.)
	lockReleased := make(chan struct{})
	go func() {
		defer close(lockReleased)
		hx, err := db.Begin()
		if err != nil {
			t.Errorf("begin lock-holder: %v", err)
			return
		}
		if _, err := hx.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES ('w0', ?, 5.0)",
			time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			_ = hx.Rollback()
			t.Errorf("lock-holder write: %v", err)
			return
		}
		time.Sleep(400 * time.Millisecond)
		if err := hx.Commit(); err != nil {
			_ = hx.Rollback()
			t.Errorf("lock-holder commit: %v", err)
		}
	}()

	var wg sync.WaitGroup
	var mu sync.Mutex
	var errCount int
	const workers = 12
	const iters = 40
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				id := fmt.Sprintf("w%d", (seed+i)%nSensors)
				ts := time.Now().UTC().Format(time.RFC3339Nano)
				if _, err := db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES (?,?,?)", id, ts, "10.5"); err != nil {
					mu.Lock()
					errCount++
					mu.Unlock()
					t.Errorf("insert probe: %v", err)
					return
				}
				if _, err := db.Exec("UPDATE sensors SET status=? WHERE id=?", "up", id); err != nil {
					mu.Lock()
					errCount++
					mu.Unlock()
					t.Errorf("update sensor: %v", err)
					return
				}
				if i%10 == 0 {
					if err := db.SetSensorTags(id, []string{"a", "b"}); err != nil {
						mu.Lock()
						errCount++
						mu.Unlock()
						t.Errorf("set tags (tx path): %v", err)
						return
					}
				}
			}
		}(w)
	}
	wg.Wait()
	// Wait for the lock-holder to commit so its row is durable and the
	// exclusive write lock is released before we assert on the row count.
	<-lockReleased

	if errCount > 0 {
		t.Fatalf("%d write errors under MaxOpenConns(10)+WAL+busy_timeout with an active write-lock holder — expected 0 "+
			"(writes serialize at the SQLite layer; busy_timeout makes blocked writers wait, not fail)", errCount)
	}
	// All writer inserts landed, plus exactly the one lock-holder row.
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM probes").Scan(&n); err != nil {
		t.Fatalf("count probes: %v", err)
	}
	if want := workers*iters + 1; n != want {
		t.Fatalf("probes = %d, want %d (some writes lost)", n, want)
	}

	// Pool drains: a query after the burst completes promptly.
	done := make(chan error, 1)
	go func() { done <- db.QueryRow("SELECT 1").Err() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("post-burst query: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("post-burst query timed out (pool exhausted)")
	}
}

// TestMaxOpenConnsOneSelfDeadlocksOnNestedQuery is the deterministic rebuttal
// to the proposed "fix" (db.SetMaxOpenConns(1)). A single pooled connection
// self-deadlocks on any nested query while iterating rows.Next(): the outer
// cursor holds the ONLY connection, so the nested query blocks forever waiting
// for a connection that will never be released. This is the historical
// production bug the current SetMaxOpenConns(10) config prevents. The test
// runs the identical nested-query pattern under MaxOpenConns(1) (expect a
// deadlock, asserted via a deadline) and under MaxOpenConns(10) (expect it to
// complete), so "do not drop to 1" is settled by evidence, not debate.
func TestMaxOpenConnsOneSelfDeadlocksOnNestedQuery(t *testing.T) {
	seed := func(t *testing.T, maxConns int) (*sql.DB, func()) {
		t.Helper()
		db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "oneconn.db"))
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		db.SetMaxOpenConns(maxConns)
		if _, err := db.Exec("CREATE TABLE x (id INTEGER)"); err != nil {
			t.Fatalf("create: %v", err)
		}
		for i := 0; i < 5; i++ {
			if _, err := db.Exec("INSERT INTO x VALUES (?)", i); err != nil {
				t.Fatalf("insert: %v", err)
			}
		}
		return db, func() { db.Close() }
	}

	// MaxOpenConns(1): the cursor holds the only connection; the nested query
	// must block (self-deadlock). Assert the block with a deadline.
	db1, close1 := seed(t, 1)
	rows, err := db1.Query("SELECT id FROM x")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if !rows.Next() {
		rows.Close()
		close1()
		t.Fatal("no rows")
	}
	done := make(chan error, 1)
	go func() {
		var n int
		done <- db1.QueryRow("SELECT COUNT(*) FROM x").Scan(&n)
	}()
	select {
	case <-done:
		rows.Close()
		close1()
		t.Fatal("nested query COMPLETED under MaxOpenConns(1) — expected a self-deadlock (this is why the pool must not be 1)")
	case <-time.After(2 * time.Second):
		// Expected: the nested query is still blocked on the exhausted pool.
	}
	rows.Close()
	// Once the cursor releases the connection, the pool is usable again.
	var n int
	if err := db1.QueryRow("SELECT COUNT(*) FROM x").Scan(&n); err != nil {
		t.Fatalf("post-close query: %v", err)
	}
	if n != 5 {
		t.Errorf("count = %d, want 5", n)
	}
	close1()

	// Control: the SAME nested-query pattern under MaxOpenConns(10) completes,
	// because the cursor and the nested query use different pooled connections.
	db10, close10 := seed(t, 10)
	r10, err := db10.Query("SELECT id FROM x")
	if err != nil {
		t.Fatalf("query(10): %v", err)
	}
	if !r10.Next() {
		r10.Close()
		close10()
		t.Fatal("no rows (10)")
	}
	if err := db10.QueryRow("SELECT COUNT(*) FROM x").Scan(&n); err != nil {
		t.Fatalf("nested query under MaxOpenConns(10) failed: %v", err)
	}
	r10.Close()
	close10()
}
