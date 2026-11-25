// Pre-update DB backup + restore decision (windows-upgrade-safety,
// 2026-11-23, item 3) — the Linux-runnable pins. The Windows restart-helper
// wiring around them is compile-gated (GOOS=windows go build / vet); the
// decision core and the backup itself are platform-neutral on purpose so
// the gate box can EXECUTE them.
//
// Run with: go test -run 'TestBackupDatabasePreUpdate|TestSensorRestoreDecision' .

package main

import (
	"os"
	"path/filepath"
	"testing"

	"pulsemon/internal/store"
)

func seedSensors(t *testing.T, dbPath string, n int) {
	t.Helper()
	st, err := store.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := st.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	defer st.Close()
	for i := 0; i < n; i++ {
		id := store.NewID()
		if _, err := st.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, state, status, created_at)
			VALUES (?, ?, ?, 60, 1000, 25, 2, 'paused', 'up', ?)`, id, "s"+string(rune('a'+i)), "127.0.0.1", store.Now()); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
}

// backupDatabasePreUpdate must write pulsemon.db.preupdate (a consistent
// VACUUM INTO snapshot) next to the DB named by PULSEMON_DB, carrying the
// pre-update sensor count.
func TestBackupDatabasePreUpdateMakesConsistentCopy(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pulsemon.db")
	t.Setenv("PULSEMON_DB", dbPath)
	seedSensors(t, dbPath, 3)

	backupDatabasePreUpdate(nil) // must not block/fail the (simulated) update

	backup := filepath.Join(dir, "pulsemon.db.preupdate")
	b, err := store.NewStore(backup)
	if err != nil {
		t.Fatalf("backup not openable: %v", err)
	}
	defer b.Close()
	got, err := b.SensorCount()
	if err != nil {
		t.Fatalf("backup SensorCount: %v", err)
	}
	if got != 3 {
		t.Fatalf("backup SensorCount = %d, want 3", got)
	}
}

// No reachable DB (degenerate state: the path's directory does not even
// exist, so NewStore fails): best effort means NO panic, NO file, and the
// update proceeds. (A missing FILE in an existing dir is not testable here
// - sqlite would happily create it - so the test drives the real skip path
// via the NewStore error.)
func TestBackupDatabasePreUpdateNoDBIsBestEffort(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PULSEMON_DB", filepath.Join(dir, "no-such-dir", "pulsemon.db"))

	backupDatabasePreUpdate(nil) // must not panic

	if _, err := os.Stat(filepath.Join(dir, "no-such-dir")); !os.IsNotExist(err) {
		t.Fatalf("no directory/backup expected when the DB path is unreachable (err=%v)", err)
	}
}

// CRITICAL-2 (2026-11-25): the SECOND pre-update backup (dst already
// exists) must succeed and carry the CURRENT sensor state — the old
// `VACUUM INTO` failed with "output file already exists" and the
// warn-only path left the first, months-old, snapshot in place, which a
// later watchdog would restore over a legitimately smaller live DB.
func TestBackupDatabasePreUpdateSecondUpdateReplacesStaleBackup(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pulsemon.db")
	t.Setenv("PULSEMON_DB", dbPath)
	seedSensors(t, dbPath, 3)

	backupDatabasePreUpdate(nil) // update #1 (fresh dst)

	// Months later: the operator decommissions a sensor.
	st, err := store.NewStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Exec(`DELETE FROM sensors WHERE name = 'sa'`); err != nil {
		t.Fatal(err)
	}
	st.Close()

	backupDatabasePreUpdate(nil) // update #2 — must NOT warn-only-fail

	backup := filepath.Join(dir, "pulsemon.db.preupdate")
	ro, err := store.NewStoreReadOnly(backup)
	if err != nil {
		t.Fatalf("backup not openable: %v", err)
	}
	defer ro.Close()
	got, err := ro.SensorCount()
	if err != nil {
		t.Fatal(err)
	}
	if got != 2 {
		t.Fatalf("backup SensorCount after update #2 = %d, want 2 (a stale 3-sensor snapshot would trigger a false-positive restore later)", got)
	}
}

// The pure decision core of the post-restart verifier: restore ONLY on a
// live count that DROPPED below the pre-update count.
func TestSensorRestoreDecision(t *testing.T) {
	cases := []struct {
		name        string
		live, want  int
		haveBackup  bool
		wantRestore bool
	}{
		{"total loss (3 -> 0)", 0, 3, true, true},
		{"partial loss (3 -> 2)", 2, 3, true, true},
		{"intact (3 -> 3)", 3, 3, true, false},
		{"added during the window (3 -> 4) is NOT loss", 4, 3, true, false},
		{"no backup: nothing to verify against", 0, 3, false, false},
		{"live count unavailable (-1): watchdog owns that case", -1, 3, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rest, reason := sensorRestoreDecision(c.live, c.want, c.haveBackup)
			if rest != c.wantRestore {
				t.Fatalf("restore = %v (%s), want %v", rest, reason, c.wantRestore)
			}
			if reason == "" {
				t.Fatal("every decision must carry a log-ready reason")
			}
		})
	}
}
