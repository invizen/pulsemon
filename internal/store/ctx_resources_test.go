package store

import (
	"context"
	"strconv"
	"strings"
	"testing"
)

// TestApplyMaintenanceTxHonorsCancelledCtx: applyMaintenanceTx used to
// drop the caller's ctx (bare tx.Exec), so a dead request context could
// not abort a maintenance transition. The ctx parameter is pinned at
// the signature level (this call does not compile without it) and
// behaviorally: a cancelled ctx must fail the transition, leave the tx
// roll-back-able, and persist nothing.
// History: docs/DECISIONS.md → db-ctx-torn-reads-resources
func TestApplyMaintenanceTxHonorsCancelledCtx(t *testing.T) {
	db := openTestStore(t)
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, state, status)
		VALUES ('s1', 's1', 'http://127.0.0.1:1', 'http', 10, 1000, 10, 2, 'active', 'up')`); err != nil {
		t.Fatalf("seed sensor: %v", err)
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := applyMaintenanceTx(ctx, tx, true, []string{"s1"}, `["s1"]`); err == nil {
		t.Fatal("applyMaintenanceTx succeeded with a cancelled context; the Execs must be ctx-aware")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback after aborted transition: %v", err)
	}
	var mode string
	err = db.QueryRow(`SELECT value FROM settings WHERE setting_key = 'maintenance_mode'`).Scan(&mode)
	if err == nil && mode == "1" {
		t.Fatal("aborted transition persisted maintenance_mode=1")
	}
	var state string
	if err := db.QueryRow(`SELECT state FROM sensors WHERE id = 's1'`).Scan(&state); err != nil {
		t.Fatalf("read sensor state: %v", err)
	}
	if state != "active" {
		t.Fatalf("aborted transition changed sensor state to %q, want active", state)
	}
}

// TestDeleteTagReturningRemovesAndLists: DELETE ... RETURNING must remove
// exactly the tag's rows and hand back the sensor ids (the respawn list
// for the probe loops), leaving other tags untouched.
// History: docs/DECISIONS.md → db-ctx-torn-reads-resources
func TestDeleteTagReturningRemovesAndLists(t *testing.T) {
	db := openTestStore(t)
	for _, id := range []string{"a", "b"} {
		if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, state, status)
			VALUES (?, ?, 'http://127.0.0.1:1', 'http', 10, 1000, 10, 2, 'active', 'up')`, id, id); err != nil {
			t.Fatalf("seed sensor %s: %v", id, err)
		}
	}
	if _, err := db.Exec(`INSERT INTO sensor_tags (sensor_id, tag) VALUES ('a','x'), ('b','x'), ('a','y')`); err != nil {
		t.Fatalf("seed tags: %v", err)
	}
	ids, err := db.DeleteTagReturning(context.Background(), "x")
	if err != nil {
		t.Fatalf("DeleteTagReturning: %v", err)
	}
	got := map[string]bool{}
	for _, id := range ids {
		got[id] = true
	}
	if len(ids) != 2 || !got["a"] || !got["b"] {
		t.Fatalf("returned ids = %v, want exactly [a b]", ids)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensor_tags WHERE tag = 'x'`).Scan(&n); err != nil {
		t.Fatalf("count x: %v", err)
	}
	if n != 0 {
		t.Fatalf("%d 'x' rows remain after delete, want 0", n)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sensor_tags WHERE tag = 'y'`).Scan(&n); err != nil {
		t.Fatalf("count y: %v", err)
	}
	if n != 1 {
		t.Fatalf("unrelated 'y' tag rows = %d, want 1 (untouched)", n)
	}
}

// TestInitSchemaRefusesNewerVersion: a DB stamped by a NEWER binary
// (user_version > this build's head) used to be accepted silently — the
// migration loop is a pure skip, so the server would boot against a
// schema it cannot fully read. It must now fail loudly.
// History: docs/DECISIONS.md → db-ctx-torn-reads-resources
func TestInitSchemaRefusesNewerVersion(t *testing.T) {
	db := openTestStore(t)
	if _, err := db.Exec("PRAGMA user_version = " + strconv.Itoa(schemaVersionHead+1)); err != nil {
		t.Fatalf("bump user_version: %v", err)
	}
	err := db.InitSchema()
	if err == nil {
		t.Fatal("InitSchema accepted a DB stamped newer than this binary's schema head")
	}
	if !strings.Contains(err.Error(), "newer than this binary") {
		t.Fatalf("error %q does not explain the version mismatch", err)
	}
}

// TestNewStoreProbeFailureReturnsError: a DSN that sql.Open accepts but
// SELECT 1 rejects (an existing DIRECTORY) must come back as an error —
// the failure path is where NewStore used to leak the handle (no
// db.Close). *sql.DB exposes no observable closed state, so the Close
// itself is verified by inspection; this pins the failure path stays a
// clean error.
// History: docs/DECISIONS.md → db-ctx-torn-reads-resources
func TestNewStoreProbeFailureReturnsError(t *testing.T) {
	dir := t.TempDir() // an existing directory: sqlite3_open is lazy, SELECT 1 fails
	if _, err := NewStore(dir); err == nil {
		t.Fatal("NewStore on a directory path: want a probe failure, got success")
	}
}
