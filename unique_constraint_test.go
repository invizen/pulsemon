package main

import (
	"database/sql"
	"errors"
	"path/filepath"
	"pulsemon/internal/store"
	"testing"
)

// TestIsUniqueConstraintErr pins finding #10: uniqueness-constraint detection
// is by SQLite RESULT CODE, not by driver message text. It covers BOTH
// extended codes the old text match caught — a UNIQUE-index violation
// (SQLITE_CONSTRAINT_UNIQUE, 2067) and a PRIMARY KEY violation
// (SQLITE_CONSTRAINT_PRIMARYKEY, 1555) — plus the negatives (a non-unique db
// error, a plain text error carrying the OLD wording, and nil).
//
// The plain-text case is load-bearing: if a driver upgrade changed the
// "UNIQUE constraint failed: ..." wording, the 409 paths this guards keep
// working because they key on the stable ABI codes — and this test fails
// loudly if anyone ever reverts to message-text matching.
func TestIsUniqueConstraintErr(t *testing.T) {
	// In-memory DB for the two positive cases (no schema dependency).
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	// PRIMARY KEY violation (1555) — mirrors the users.username column.
	if _, err := db.Exec("CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)"); err != nil {
		t.Fatalf("create users: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO users (username, password_hash) VALUES ('dup', 'x')`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, uerr := db.Exec(`INSERT INTO users (username, password_hash) VALUES ('dup', 'y')`); uerr == nil {
		t.Fatal("duplicate PRIMARY KEY INSERT must fail")
	} else if !isUniqueConstraintErr(uerr) {
		t.Fatalf("isUniqueConstraintErr(PRIMARY KEY violation) = false, want true (err = %v)", uerr)
	}

	// UNIQUE-index violation (2067) — mirrors the sensors.name column.
	if _, err := db.Exec("CREATE TABLE sensors (id TEXT PRIMARY KEY, name TEXT, UNIQUE(name))"); err != nil {
		t.Fatalf("create sensors: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sensors (id, name) VALUES ('a', 'n1')`); err != nil {
		t.Fatalf("seed sensor: %v", err)
	}
	if _, uerr := db.Exec(`INSERT INTO sensors (id, name) VALUES ('b', 'n1')`); uerr == nil {
		t.Fatal("duplicate UNIQUE-index INSERT must fail")
	} else if !isUniqueConstraintErr(uerr) {
		t.Fatalf("isUniqueConstraintErr(UNIQUE-index violation) = false, want true (err = %v)", uerr)
	}

	// A non-unique db error (a syntax error) must classify false.
	if _, e := db.Exec("INSERT INTO users (username) VALUES"); e != nil {
		if isUniqueConstraintErr(e) {
			t.Fatalf("isUniqueConstraintErr(non-unique db error %v) = true, want false", e)
		}
	}

	// A plain (non-sqlite) error carrying the OLD text must classify false —
	// detection must not fall back to message text.
	if isUniqueConstraintErr(errors.New("UNIQUE constraint failed: sensors.name")) {
		t.Fatal("isUniqueConstraintErr(plain text error) = true, want false — detection must key on the result code, not the message")
	}
	if isUniqueConstraintErr(nil) {
		t.Fatal("isUniqueConstraintErr(nil) = true, want false")
	}

	// The real store schema must also classify the users PK violation true
	// (guards against the in-memory probe drifting from production schema).
	rdb, err := store.NewStore(filepath.Join(t.TempDir(), "uniq.db"))
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	defer rdb.Close()
	if err := rdb.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if _, err := rdb.Exec("INSERT INTO users (username, password_hash, created_at, is_admin) VALUES ('dup', 'x', '2026-01-01T00:00:00Z', 0)"); err != nil {
		t.Fatalf("seed real user: %v", err)
	}
	if _, uerr := rdb.Exec("INSERT INTO users (username, password_hash, created_at, is_admin) VALUES ('dup', 'y', '2026-01-01T00:00:00Z', 0)"); uerr == nil {
		t.Fatal("duplicate real user INSERT must fail")
	} else if !isUniqueConstraintErr(uerr) {
		t.Fatalf("isUniqueConstraintErr(real store users PK violation) = false, want true (err = %v)", uerr)
	}
}
