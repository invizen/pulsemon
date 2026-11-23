//go:build windows

// verifySensorsIntact pins (windows-upgrade-safety, 2026-11-23, item 3) —
// the post-restart data-loss verifier in the restart-helper. Windows-only
// (the file it guards is windows-tagged): compile-gated on the gate box
// (GOOS=windows go build / go vet / go test -c), executed on a Windows host.
//
// Run with: go test -run TestVerifySensorsIntact .

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"pulsemon/internal/store"
)

// stubVerifier seams the I/O out of verifySensorsIntact and records the
// service actions. Returns the exit code plus the action trace.
func runVerifier(t *testing.T, liveCount int, liveOK bool, backupSensors int) (int, map[string]bool) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pulsemon.db")
	t.Setenv("PULSEMON_DB", dbPath)

	if backupSensors >= 0 {
		seedSensors(t, dbPath, backupSensors)
		// Make the pre-update snapshot the way the update flow does.
		backupDatabasePreUpdate()
		// Then simulate the data-losing update: the live DB loses sensors.
		if liveCount < backupSensors {
			st, err := store.NewStore(dbPath)
			if err != nil {
				t.Fatalf("reopen live: %v", err)
			}
			if _, err := st.Exec("DELETE FROM sensors"); err != nil {
				t.Fatalf("wipe live: %v", err)
			}
			st.Close()
		}
	}
	// Stale WAL/SHM next to the live DB (as the just-restarted service
	// would have left): the restore must remove them, else SQLite replays
	// them over the restored snapshot.
	os.WriteFile(dbPath+"-wal", []byte("stale-wal"), 0o644)
	os.WriteFile(dbPath+"-shm", []byte("stale-shm"), 0o644)

	// Dummy binary pair in a separate dir (the service bin dir).
	binDir := t.TempDir()
	exe := filepath.Join(binDir, "pulsemon.exe")
	os.WriteFile(exe, []byte("new-binary"), 0o755)
	os.WriteFile(exe+".prev", []byte("prev-binary"), 0o755)

	actions := map[string]bool{}
	oldWait := restartSensorWait
	oldOpen := openHealthzDB
	oldStop := stopWindowsServiceFn
	oldStart := startWindowsServiceFn
	oldBin := serviceBinPathFn
	t.Cleanup(func() {
		restartSensorWait = oldWait
		openHealthzDB = oldOpen
		stopWindowsServiceFn = oldStop
		startWindowsServiceFn = oldStart
		serviceBinPathFn = oldBin
	})
	restartSensorWait = func(db *store.Store, timeout time.Duration) (int, bool, string) {
		return liveCount, liveOK, "test"
	}
	openHealthzDB = func() *store.Store { return nil }
	stopWindowsServiceFn = func() error { actions["stop"] = true; return nil }
	startWindowsServiceFn = func() error { actions["start"] = true; return nil }
	serviceBinPathFn = func() (string, error) { return exe, nil }

	var lines []string
	logLine := func(format string, a ...any) {
		lines = append(lines, format)
		_ = a
	}
	rc := verifySensorsIntact(logLine)

	// Expose the log for failure messages.
	t.Cleanup(func() {
		for _, l := range lines {
			t.Logf("helper: %s", l)
		}
	})
	return rc, actions
}

func TestVerifySensorsIntactIntactNoAction(t *testing.T) {
	// 3 sensors before, 3 after: verified, no service action.
	rc, actions := runVerifier(t, 3, true, 3)
	if rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	if actions["stop"] || actions["start"] {
		t.Fatalf("intact update must not stop/start the service: %v", actions)
	}
}

func TestVerifySensorsIntactDataLossRestoresAndRollsBack(t *testing.T) {
	// 3 sensors before, 0 after: restore the DB, roll the binary back,
	// restart the service on the known-good pair.
	rc, actions := runVerifier(t, 0, true, 3)
	if rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	if !actions["stop"] || !actions["start"] {
		t.Fatalf("a data-loss restore must stop and start the service: %v", actions)
	}
}

func TestVerifySensorsIntactNoBackupSkips(t *testing.T) {
	// No pre-update backup (pre-feature update): nothing to verify, no
	// action, exit 0.
	rc, actions := runVerifier(t, 0, true, -1)
	if rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	if actions["stop"] || actions["start"] {
		t.Fatalf("no backup = no action: %v", actions)
	}
}

func TestVerifySensorsIntactUnhealthyNoAction(t *testing.T) {
	// The service never answers healthz: the WATCHDOG owns that case
	// (binary rollback). The verifier must not double-act: no stop,
	// non-zero exit for the log.
	rc, actions := runVerifier(t, -1, false, 3)
	if rc == 0 {
		t.Fatal("an unverifiable service must not exit 0 (the log is the audience)")
	}
	if actions["stop"] || actions["start"] {
		t.Fatalf("an unhealthy service must not be stopped by the verifier: %v", actions)
	}
}
