package main

// Review 2026-10-24 (Major): ImmediateTx had two connection-poisoning gaps
// that both hand a pooled *sql.Conn back with an OPEN SQLite transaction —
// the next BEGIN IMMEDIATE on that conn fails "cannot start a transaction
// within a transaction" and every writer wedges until restart:
//  1. COMMIT used the caller's ctx: a client cancel (or SQLITE_BUSY past
//     busy_timeout) skipped/failed the statement while SQLite semantics
//     leave the transaction ACTIVE. The existing comment defended the
//     ROLLBACK side only.
//  2. A panic inside fn (net/http recovers per-connection) skipped both the
//     rollback path and returned through the deferred conn.Close().
// Both now roll back on a fresh context before the conn is released.

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func immediatetxFixture(t *testing.T) *DB {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "imtx.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return db
}

// TestImmediateTxPanicRollsBack: a panic inside fn must not poison the
// pool, and the panicking partial write must not become visible.
func TestImmediateTxPanicRollsBack(t *testing.T) {
	db := immediatetxFixture(t)

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("panic did not propagate to the caller (http-layer semantics preserved expectation)")
			}
		}()
		_ = db.ImmediateTx(context.Background(), func(c *sql.Conn) error {
			if _, err := c.ExecContext(context.Background(),
				"INSERT INTO settings (setting_key, value) VALUES ('panic-key', 'ghost')"); err != nil {
				return err
			}
			panic("boom")
		})
	}()

	// The pool must still accept a transaction (pre-fix: "cannot start a
	// transaction within a transaction" on the reused conn, forever).
	if err := db.ImmediateTx(context.Background(), func(c *sql.Conn) error {
		_, err := c.ExecContext(context.Background(),
			"INSERT INTO settings (setting_key, value) VALUES ('after-panic', 'ok')")
		return err
	}); err != nil {
		t.Fatalf("pool poisoned after panic — ImmediateTx failed: %v", err)
	}
	var ghost int
	if err := db.QueryRow("SELECT COUNT(*) FROM settings WHERE setting_key = 'panic-key'").Scan(&ghost); err != nil {
		t.Fatalf("count: %v", err)
	}
	if ghost != 0 {
		t.Errorf("panicking partial write became visible (tx was never rolled back)")
	}
}

// TestImmediateTxCommitFailureRescuesPool drives a DETERMINISTIC COMMIT
// failure — a deferred FK violation that only surfaces at COMMIT time — and
// pins the post-fix contract: the error propagates, nothing half-committed
// is visible, and the pooled conn comes back CLEAN (next writer succeeds).
// (The obvious cancel-the-ctx approach was tried first and rejected: this
// driver stack empirically LANDS a single-step COMMIT on an already-canceled
// ctx, so it never exercises the failure path. The real production triggers
// — SQLITE_BUSY past busy_timeout, an I/O error at fsync — cannot be induced
// in-process; the deferred-FK failure exercises the same rescue branch:
// COMMIT returns error, rescue ROLLBACK runs (here against SQLite's own
// auto-rollback, making its own error the documented swallow), conn is
// released clean.)
func TestImmediateTxCommitFailureRescuesPool(t *testing.T) {
	db := immediatetxFixture(t)

	err := db.ImmediateTx(context.Background(), func(c *sql.Conn) error {
		if _, err := c.ExecContext(context.Background(), "PRAGMA defer_foreign_keys = ON"); err != nil {
			return err
		}
		// FK to sensors(id) — violation is deferred to COMMIT, where it fails.
		_, err := c.ExecContext(context.Background(),
			"INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES ('ghost-sensor', '2026-01-01T00:00:00Z', 1.0)")
		return err
	})
	if err == nil {
		t.Fatalf("expected the deferred-FK COMMIT to fail")
	}

	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM probes WHERE sensor_id = 'ghost-sensor'").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("FK-violating row became visible despite failed COMMIT")
	}

	// THE regression: the next writer must not inherit an open tx.
	if err := db.ImmediateTx(context.Background(), func(c *sql.Conn) error {
		_, err := c.ExecContext(context.Background(),
			"INSERT INTO settings (setting_key, value) VALUES ('rescue-next', 'ok')")
		return err
	}); err != nil {
		t.Fatalf("pool poisoned after failed COMMIT — ImmediateTx failed: %v", err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM settings WHERE setting_key = 'rescue-next'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("follow-up write did not commit (n=%d, err=%v)", n, err)
	}
}
