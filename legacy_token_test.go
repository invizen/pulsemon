package main

// Review 2026-10-24 (Major): InitSchema cleared the legacy auth_token
// setting UNCONDITIONALLY — including when UserCount() errored or the
// migration INSERT failed. A failed migration destroyed the operator's
// only credential AND left zero users with no auth_bootstrapped flag,
// which the setup gate reads as a FRESH install: the dashboard silently
// downgraded to unauthenticated setup mode. The token is now destroyed
// only on a confirmed outcome; failures keep it and retry next boot.

import (
	"path/filepath"
	"testing"
	"time"
)

func legacyTokenFixture(t *testing.T) *DB {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "legacy-token.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return db
}

// TestLegacyTokenKeptOnMigrationFailure: with the users table gone
// (simulating any UserCount/INSERT failure), the helper must NOT clear the
// token — pre-fix it was destroyed with zero users migrated.
func TestLegacyTokenKeptOnMigrationFailure(t *testing.T) {
	db := legacyTokenFixture(t)
	const tok = "$2a$10$dummybchashvalue"
	if err := db.SetSetting("auth_token", tok); err != nil {
		t.Fatalf("set token: %v", err)
	}
	if _, err := db.Exec("DROP TABLE users"); err != nil {
		t.Fatalf("drop users: %v", err)
	}
	if err := migrateLegacyAuthToken(db); err != nil {
		t.Fatalf("migration failure must defer, not fail boot: %v", err)
	}
	if got := db.GetSetting("auth_token"); got != tok {
		t.Fatalf("legacy token destroyed on a failed migration (got %q, want it kept for retry) — operator credential lost + setup-mode downgrade", got)
	}
}

// TestLegacyTokenMigratesOnRetry: once the failure clears (InitSchema
// recreates users), the kept token migrates to 'admin' and is THEN cleared,
// with auth_bootstrapped set.
func TestLegacyTokenMigratesOnRetry(t *testing.T) {
	db := legacyTokenFixture(t)
	const tok = "$2a$10$dummybchashvalue"
	if err := db.SetSetting("auth_token", tok); err != nil {
		t.Fatalf("set token: %v", err)
	}
	if _, err := db.Exec("DROP TABLE users"); err != nil {
		t.Fatalf("drop users: %v", err)
	}
	if err := migrateLegacyAuthToken(db); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	if db.GetSetting("auth_token") == "" {
		t.Fatalf("token cleared despite failed migration")
	}
	// Recovery: users table back (InitSchema is idempotent and re-runs the
	// helper, exactly like a reboot after the fault clears).
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema retry: %v", err)
	}
	if got := db.GetSetting("auth_token"); got != "" {
		t.Errorf("token not cleared after a SUCCESSFUL migration (got %q)", got)
	}
	var hash string
	if err := db.QueryRow("SELECT password_hash FROM users WHERE username = 'admin'").Scan(&hash); err != nil {
		t.Fatalf("admin user not migrated: %v", err)
	}
	if hash != tok {
		t.Errorf("migrated hash = %q, want the original token (login must verify unchanged)", hash)
	}
	if db.GetSetting("auth_bootstrapped") != "1" {
		t.Errorf("auth_bootstrapped not set — a later auth-off state would read as a fresh install")
	}
}

// TestLegacyTokenClearedWhenUsersExist: existing users mean the migration
// already happened (or was skipped legitimately) — the token is cleared with
// NO duplicate admin row.
func TestLegacyTokenClearedWhenUsersExist(t *testing.T) {
	db := legacyTokenFixture(t)
	if _, err := db.Exec(`INSERT INTO users (username, password_hash, created_at) VALUES ('ops', 'h', ?)`,
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if err := db.SetSetting("auth_token", "stale-token"); err != nil {
		t.Fatalf("set token: %v", err)
	}
	if err := migrateLegacyAuthToken(db); err != nil {
		t.Fatalf("helper: %v", err)
	}
	if got := db.GetSetting("auth_token"); got != "" {
		t.Errorf("stale token not cleared when users exist (got %q)", got)
	}
	var admins int
	if err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'admin'").Scan(&admins); err != nil {
		t.Fatalf("count: %v", err)
	}
	if admins != 0 {
		t.Errorf("duplicate admin inserted despite existing users")
	}
}
