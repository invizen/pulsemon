package store

// Migration 11 is a deliberate no-op (its number is preserved so fleet DBs
// stay stamped by position; the legacy auth_token -> admin-user conversion is
// a separate idempotent STARTUP step, not a versioned one — a version stamp
// would commit on deferral and skip the retry forever). The finding's concern:
// a retry of the migration sequence at the 11 boundary must work WITHOUT
// resetting user_version to 0. A full reset re-runs every migration and is
// the pre-versioning escape hatch, not the normal recovery path.
// History: docs/DECISIONS.md → testing-benchmark-gaps

import "testing"

// TestInitSchemaMigration11RetryWithoutReset stamps a DB at the head, walks
// user_version back to just before migration 11 (the state of a DB that
// reached 10 and crashed before 11), and re-runs InitSchema. The no-op 11
// plus the real 12/13 steps must land and the DB must return to the head —
// no reset to 0 required.
func TestInitSchemaMigration11RetryWithoutReset(t *testing.T) {
	db := openTestStore(t)
	if v := getUserVersion(t, db); v != schemaVersionHead {
		t.Fatalf("fresh DB user_version = %d, want head %d", v, schemaVersionHead)
	}

	// Walk back to the migration-11 boundary (before the no-op 11).
	if _, err := db.Exec(`PRAGMA user_version = 10`); err != nil {
		t.Fatalf("reset user_version to 10: %v", err)
	}
	// Drop migration 13's covering index so the replay must actually
	// re-apply it (a pure skip would leave it missing and the assertion
	// below fails).
	if _, err := db.Exec(`DROP INDEX IF EXISTS idx_probes_sensor_ts_cov`); err != nil {
		t.Fatal(err)
	}

	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema retry from user_version=10: %v", err)
	}

	if v := getUserVersion(t, db); v != schemaVersionHead {
		t.Fatalf("user_version after retry = %d, want head %d (retry must reach the head without a reset to 0)", v, schemaVersionHead)
	}
	// Migration 13's covering index must be re-created by the replay.
	var cov int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_probes_sensor_ts_cov'`).Scan(&cov); err != nil || cov != 1 {
		t.Fatalf("covering index after retry: present=%d err=%v, want 1 (migration 13 must re-apply)", cov, err)
	}
}
