package store

// Review 2026-10-24 (Major): InitSchema cleared the legacy auth_token
// setting UNCONDITIONALLY — including when UserCount() errored or the
// migration INSERT failed. A failed migration destroyed the operator's
// only credential AND left zero users with no auth_bootstrapped flag,
// which the setup gate reads as a FRESH install: the dashboard silently
// downgraded to unauthenticated setup mode. The token is now destroyed
// only on a confirmed outcome; failures keep it and retry next boot.

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func legacyTokenFixture(t *testing.T) *Store {
	t.Helper()
	db, err := NewStore(filepath.Join(t.TempDir(), "legacy-token.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
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
	if err := MigrateLegacyAuthToken(db); err != nil {
		t.Fatalf("migration failure must defer, not fail boot: %v", err)
	}
	if got := db.GetSetting("auth_token"); got != tok {
		t.Fatalf("legacy token destroyed on a failed migration (got %q, want it kept for retry) — operator credential lost + setup-mode downgrade", got)
	}
}

// TestLegacyTokenMigratesOnRetry: once the failure clears (InitSchema
// recreates users), the kept token migrates to 'admin' and is THEN cleared,
// with auth_bootstrapped set. The retry is a plain re-run of the startup
// step (MigrateLegacyAuthToken) — no version-stamp reset: the token
// migration is no longer a versioned step, so nothing can stamp it complete
// on deferral.
func TestLegacyTokenMigratesOnRetry(t *testing.T) {
	db := legacyTokenFixture(t)
	const tok = "$2a$10$dummybchashvalue"
	if err := db.SetSetting("auth_token", tok); err != nil {
		t.Fatalf("set token: %v", err)
	}
	if _, err := db.Exec("DROP TABLE users"); err != nil {
		t.Fatalf("drop users: %v", err)
	}
	if err := MigrateLegacyAuthToken(db); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	if db.GetSetting("auth_token") == "" {
		t.Fatalf("token cleared despite failed migration")
	}
	// Recovery: users table back (InitSchema's base schema recreates it);
	// the next boot's startup step migrates the kept token.
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := MigrateLegacyAuthToken(db); err != nil {
		t.Fatalf("retry pass (startup step): %v", err)
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

// TestDeferredLegacyTokenMigrationRetriesNextBoot pins the versioned-regime
// defect end to end: a pre-versioning legacy install (token set, 0 users,
// probe history) whose first boot DEFERS the token migration on a transient
// DB failure must complete it on the next boot. The old shape stamped
// user_version 11+12 inside the deferred pass, so every later boot skipped
// the migration forever — 0 users + a dead token = a token-protected
// install booted fully open. The token migration is now an unversioned
// startup step, so a deferral can never be stamped permanent.
// History: docs/DECISIONS.md → legacy-token-startup-step
func TestDeferredLegacyTokenMigrationRetriesNextBoot(t *testing.T) {
	db := legacyTokenFixture(t)
	const tok = "$2a$10$dummybchashvalue"
	// Pre-versioning legacy shape: token + probe history, no users.
	if err := db.SetSetting("auth_token", tok); err != nil {
		t.Fatalf("set token: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('s1', 'legacy', '10.0.0.1', 'icmp', 60, 1000, 25, 2, 3, 'active', 'up', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("seed sensor: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES ('s1', '2026-10-13T00:00:00Z', 1.5)`); err != nil {
		t.Fatalf("seed probe: %v", err)
	}
	if _, err := db.Exec("DROP TABLE users"); err != nil {
		t.Fatalf("drop users: %v", err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 0`); err != nil {
		t.Fatalf("reset user_version: %v", err)
	}

	// Boot 1: the migration defers on a transient UserCount failure.
	orig := legacyTokenUserCount
	legacyTokenUserCount = func(*Store) (int, error) { return 0, errors.New("transient db failure") }
	if err := db.InitSchema(); err != nil {
		t.Fatalf("boot 1 InitSchema: %v", err)
	}
	legacyTokenUserCount = orig
	if got := db.GetSetting("auth_token"); got != tok {
		t.Fatalf("token destroyed on a deferred migration (got %q, want it kept for retry)", got)
	}

	// Boot 2: the failure cleared; the startup step must complete the
	// migration (the old versioned shape skipped it forever here).
	if err := MigrateLegacyAuthToken(db); err != nil {
		t.Fatalf("boot 2 startup step: %v", err)
	}
	if got := db.GetSetting("auth_token"); got != "" {
		t.Fatalf("token not cleared after the retry (got %q)", got)
	}
	var admin int
	if err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'admin' AND is_admin = 1").Scan(&admin); err != nil {
		t.Fatalf("count: %v", err)
	}
	if admin != 1 {
		t.Fatalf("migrated admin (is_admin=1) missing after the retry: count=%d", admin)
	}
}

// TestMigrateUserAdminColumnAtomicWithStamp pins slot 12's tx atomicity:
// when the step's promotion statement fails, the WHOLE step rolls back —
// the is_admin column added earlier in the same step must not survive, and
// the version stamp must not advance. The old shape ran both statements on
// pool connections, so the ALTER committed independently of the stamp and
// a failed step left a half-migrated schema.
// History: docs/DECISIONS.md → legacy-token-startup-step
func TestMigrateUserAdminColumnAtomicWithStamp(t *testing.T) {
	db := legacyTokenFixture(t) // fresh: head stamped, is_admin column present
	// Pre-slot-12 shape: column gone, version at 11.
	if _, err := db.Exec("ALTER TABLE users DROP COLUMN is_admin"); err != nil {
		t.Fatalf("drop column: %v", err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 11`); err != nil {
		t.Fatalf("set version: %v", err)
	}
	// Fail the promotion statement: the step must roll back as a unit.
	orig := userAdminPromoteSQL
	userAdminPromoteSQL = `UPDATE nonexistent_table SET x = 1`
	err := db.InitSchema()
	userAdminPromoteSQL = orig
	if err == nil {
		t.Fatal("InitSchema with a failing slot-12 statement must return an error")
	}
	var col int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('users') WHERE name = 'is_admin'`).Scan(&col); err != nil {
		t.Fatalf("pragma: %v", err)
	}
	if col != 0 {
		t.Fatal("is_admin column survived a failed slot-12 step — the step ran outside its transaction")
	}
	if v, err := db.schemaVersion(); err != nil {
		t.Fatalf("schemaVersion: %v", err)
	} else if v != 11 {
		t.Fatalf("user_version = %d after a failed step, want 11 (the stamp must not commit on failure)", v)
	}
	// Recovery: the step replays whole and succeeds (and any later steps
	// — added after slot 12 — replay to the head too).
	if err := db.InitSchema(); err != nil {
		t.Fatalf("replay InitSchema: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('users') WHERE name = 'is_admin'`).Scan(&col); err != nil {
		t.Fatalf("pragma: %v", err)
	}
	if col != 1 {
		t.Fatal("is_admin column missing after the replayed step")
	}
	if v, _ := db.schemaVersion(); v != schemaVersionHead {
		t.Fatalf("user_version = %d after replay, want head %d", v, schemaVersionHead)
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
	if err := MigrateLegacyAuthToken(db); err != nil {
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
