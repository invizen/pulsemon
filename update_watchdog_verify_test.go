// Watchdog data-integrity check (windows-recovery-restart, 2026-11-23): the
// HEALTHY path of runWatchdog runs verifySensorsIntactWatchdog — when the
// live sensor count dropped below the pre-update backup, restore the
// pre-update DB and roll the binary back. The restore is gated on service
// state (a running service holds the DB open; a denied stop means nothing
// is touched). Platform-neutral on purpose so the Linux gate box can
// EXECUTE it.
//
// Run with: go test -run 'TestVerifySensors' .

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pulsemon/internal/store"
)

// verifyHarness stubs every seam the verification touches.
type verifyHarness struct {
	liveCount    int
	liveOK       bool
	serviceState string
	stateErr     error
	stopErr      error
	stopped      bool
	restarted    bool
}

func withVerifyHarness(t *testing.T, h *verifyHarness) {
	t.Helper()
	oldWait, oldState, oldStop := restartSensorWait, serviceStateFn, stopForRestoreFn
	oldPerf, oldDetect := performRestart, detectRestart
	restartSensorWait = func(*store.Store, time.Duration) (int, bool, string) {
		return h.liveCount, h.liveOK, "test"
	}
	serviceStateFn = func() (string, error) { return h.serviceState, h.stateErr }
	stopForRestoreFn = func() error { h.stopped = true; return h.stopErr }
	performRestart = func(string) error { h.restarted = true; return nil }
	detectRestart = func() string { return "test-bus" }
	t.Cleanup(func() {
		restartSensorWait, serviceStateFn, stopForRestoreFn = oldWait, oldState, oldStop
		performRestart, detectRestart = oldPerf, oldDetect
	})
}

func watchdogVerifyLog(t *testing.T, dir string) string {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(dir, "pulsemon-watchdog.log"))
	return string(b)
}

// setupVerifyFixture lays out: a live DB (liveSensors sensors), a
// pulsemon.db.preupdate backup (backupSensors sensors), and the binary pair
// (prevBin = OLD, dstBin = NEW).
func setupVerifyFixture(t *testing.T, liveSensors, backupSensors int) (dir, prevBin, dstBin string) {
	t.Helper()
	dir = t.TempDir()
	dbPath := filepath.Join(dir, "pulsemon.db")
	t.Setenv("PULSEMON_DB", dbPath)
	seedSensors(t, dbPath, liveSensors)
	backup := filepath.Join(dir, "pulsemon.db.preupdate")
	if backupSensors >= 0 {
		// Make the "pre-update" snapshot the way PRODUCTION does —
		// store.BackupTo (VACUUM INTO) — so the fixture has the real
		// .preupdate shape: a delete-journal snapshot, NOT a byte-copy
		// of a WAL file (a read-only open of a WAL-mode file creates
		// -wal/-shm sidecars, which the read-only pin must not see).
		src := filepath.Join(dir, "backup-src.db")
		seedSensors(t, src, backupSensors)
		st, err := store.NewStore(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.BackupTo(backup); err != nil {
			t.Fatal(err)
		}
		st.Close()
		os.Remove(src)
	}
	prevBin = filepath.Join(dir, "pulsemon.exe.prev")
	dstBin = filepath.Join(dir, "pulsemon.exe")
	if err := os.WriteFile(prevBin, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dstBin, []byte("NEW"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir, prevBin, dstBin
}

func liveSensorCount(t *testing.T, dir string) int {
	t.Helper()
	st, err := store.NewStore(filepath.Join(dir, "pulsemon.db"))
	if err != nil {
		t.Fatalf("open live DB: %v", err)
	}
	defer st.Close()
	n, err := st.SensorCount()
	if err != nil {
		t.Fatalf("live SensorCount: %v", err)
	}
	return n
}

// 3 before, 3 after: verified, nothing touched.
func TestVerifySensorsIntactNoAction(t *testing.T) {
	dir, prevBin, dstBin := setupVerifyFixture(t, 3, 3)
	h := &verifyHarness{liveCount: 3, liveOK: true, serviceState: "running"}
	withVerifyHarness(t, h)

	verifySensorsIntactWatchdog(nil, prevBin, dstBin)

	if h.stopped || h.restarted {
		t.Error("intact sensors: no stop/restart expected")
	}
	if got, _ := os.ReadFile(dstBin); string(got) != "NEW" {
		t.Error("intact sensors: the binary must not be rolled back")
	}
	if n := liveSensorCount(t, dir); n != 3 {
		t.Errorf("intact sensors: live DB = %d sensors, want 3 (untouched)", n)
	}
	if log := watchdogVerifyLog(t, dir); !strings.Contains(log, "sensors intact") {
		t.Errorf("log must record 'sensors intact', got: %s", log)
	}
}

// 3 before, 1 after, service STOPPED (the crash-loop case): restore the DB
// and roll the binary back, then restart.
func TestVerifySensorsDataLossStoppedServiceRestores(t *testing.T) {
	dir, prevBin, dstBin := setupVerifyFixture(t, 1, 3)
	h := &verifyHarness{liveCount: 1, liveOK: true, serviceState: "stopped"}
	withVerifyHarness(t, h)

	verifySensorsIntactWatchdog(nil, prevBin, dstBin)

	if h.stopped {
		t.Error("stopped service: no stop call expected")
	}
	if n := liveSensorCount(t, dir); n != 3 {
		t.Errorf("live DB after restore = %d sensors, want 3 (from the backup)", n)
	}
	if got, _ := os.ReadFile(dstBin); string(got) != "OLD" {
		t.Error("binary must be rolled back to the previous one")
	}
	if !h.restarted {
		t.Error("the service must be restarted on the restored pair")
	}
	log := watchdogVerifyLog(t, dir)
	if !strings.Contains(log, "DATA LOSS") || !strings.Contains(log, "previous binary restored") {
		t.Errorf("log must record the data loss and the restore, got: %s", log)
	}
}

// 3 before, 1 after, service RUNNING and the stop DENIED (the Windows VSA
// case): nothing is touched (a restore under a live writer corrupts the
// data), and the log carries manual-restore instructions.
func TestVerifySensorsDataLossRunningStopDenied(t *testing.T) {
	dir, prevBin, dstBin := setupVerifyFixture(t, 1, 3)
	h := &verifyHarness{
		liveCount:    1,
		liveOK:       true,
		serviceState: "running",
		stopErr:      errors.New("access is denied"),
	}
	withVerifyHarness(t, h)

	verifySensorsIntactWatchdog(nil, prevBin, dstBin)

	if n := liveSensorCount(t, dir); n != 1 {
		t.Errorf("live DB = %d sensors, want 1 (MUST be untouched when the stop is denied)", n)
	}
	if got, _ := os.ReadFile(dstBin); string(got) != "NEW" {
		t.Error("binary must NOT be rolled back when the stop is denied")
	}
	if h.restarted {
		t.Error("no restart when the stop is denied")
	}
	if log := watchdogVerifyLog(t, dir); !strings.Contains(log, "MANUAL ACTION REQUIRED") {
		t.Errorf("log must carry manual-restore instructions, got: %s", log)
	}
}

// 3 before, 1 after, service RUNNING and the stop SUCCEEDS (the Linux /
// elevated case): full restore.
func TestVerifySensorsDataLossRunningStopSucceeds(t *testing.T) {
	dir, prevBin, dstBin := setupVerifyFixture(t, 1, 3)
	h := &verifyHarness{liveCount: 1, liveOK: true, serviceState: "running"}
	withVerifyHarness(t, h)

	verifySensorsIntactWatchdog(nil, prevBin, dstBin)

	if !h.stopped {
		t.Error("running service: the stop must be attempted first")
	}
	if n := liveSensorCount(t, dir); n != 3 {
		t.Errorf("live DB after restore = %d sensors, want 3", n)
	}
	if got, _ := os.ReadFile(dstBin); string(got) != "OLD" {
		t.Error("binary must be rolled back")
	}
	if !h.restarted {
		t.Error("the service must be restarted on the restored pair")
	}
}

// No pre-update backup: nothing to compare against — skip, no action.
func TestVerifySensorsNoBackupSkips(t *testing.T) {
	dir, prevBin, dstBin := setupVerifyFixture(t, 3, -1)
	h := &verifyHarness{liveCount: 3, liveOK: true, serviceState: "running"}
	withVerifyHarness(t, h)

	verifySensorsIntactWatchdog(nil, prevBin, dstBin)

	if h.stopped || h.restarted {
		t.Error("no backup: no action expected")
	}
	if log := watchdogVerifyLog(t, dir); !strings.Contains(log, "skipped") {
		t.Errorf("log must record the skip, got: %s", log)
	}
}

// A backup with zero sensors: nothing to lose — skip, no action.
func TestVerifySensorsZeroBackupSkips(t *testing.T) {
	dir, prevBin, dstBin := setupVerifyFixture(t, 0, 0)
	h := &verifyHarness{liveCount: 0, liveOK: true, serviceState: "running"}
	withVerifyHarness(t, h)

	verifySensorsIntactWatchdog(nil, prevBin, dstBin)

	if h.stopped || h.restarted {
		t.Error("empty backup: no action expected")
	}
	if log := watchdogVerifyLog(t, dir); !strings.Contains(log, "nothing to verify") {
		t.Errorf("log must record 'nothing to verify', got: %s", log)
	}
}

// The live count is unavailable (healthz answered no usable count): the
// unhealthy watchdog path owns that case — the verifier does not double-act.
func TestVerifySensorsLiveCountUnavailableSkips(t *testing.T) {
	dir, prevBin, dstBin := setupVerifyFixture(t, 1, 3)
	h := &verifyHarness{liveCount: -1, liveOK: false, serviceState: "running"}
	withVerifyHarness(t, h)

	verifySensorsIntactWatchdog(nil, prevBin, dstBin)

	if h.stopped || h.restarted {
		t.Error("unverifiable live count: no action expected")
	}
	if n := liveSensorCount(t, dir); n != 1 {
		t.Errorf("live DB = %d sensors, want 1 (untouched)", n)
	}
}

// CRITICAL-2 (2026-11-25): a VERIFIED update (sensors intact) must remove
// the pre-update backup. A surviving snapshot is the stale-baseline trap:
// months of legitimate sensor deletion later, a future watchdog comparing
// the lower live count against THIS months-old backup would declare data
// loss and restore it — wiping the intervening months of config, users
// and history.
func TestVerifySensorsIntactRemovesVerifiedBackup(t *testing.T) {
	dir, prevBin, dstBin := setupVerifyFixture(t, 3, 3)
	h := &verifyHarness{liveCount: 3, liveOK: true, serviceState: "running"}
	withVerifyHarness(t, h)

	backup := filepath.Join(dir, "pulsemon.db.preupdate")
	verifySensorsIntactWatchdog(nil, prevBin, dstBin)

	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Errorf("verified backup must be removed after a healthy update (stat err=%v) — a stale snapshot is a false-positive restore waiting to happen", err)
	}
	if log := watchdogVerifyLog(t, dir); !strings.Contains(log, "sensors intact") {
		t.Errorf("log must record 'sensors intact', got: %s", log)
	}
}

// Positive control to the pin above: the DATA-LOSS path restores FROM the
// backup — it must NOT remove it (restoreDatabaseFile copies; the
// operator may need the snapshot again after the rollback).
func TestVerifySensorsDataLossKeepsBackup(t *testing.T) {
	dir, prevBin, dstBin := setupVerifyFixture(t, 1, 3)
	h := &verifyHarness{liveCount: 1, liveOK: true, serviceState: "stopped"}
	withVerifyHarness(t, h)

	backup := filepath.Join(dir, "pulsemon.db.preupdate")
	verifySensorsIntactWatchdog(nil, prevBin, dstBin)

	if _, err := os.Stat(backup); err != nil {
		t.Errorf("the data-loss path restores FROM the backup — it must keep it (stat err=%v)", err)
	}
}

// CRITICAL-2 (2026-11-25): the watchdog must open the backup READ-ONLY.
// Source-shape pin: the behavioral discriminator is invisible to a
// post-run directory check — a read-write WAL open DOES create -wal/-shm
// sidecars, but the watchdog's own Close() (last connection) checkpoints
// and removes them, so both shapes end with a clean directory. The
// store-level proof that NewStoreReadOnly genuinely refuses writes lives
// in internal/store/store_backup_replace_test.go; this pin proves the
// watchdog is the consumer of it.
func TestVerifySensorsOpensBackupReadOnly(t *testing.T) {
	src, err := os.ReadFile("update.go")
	if err != nil {
		t.Fatalf("read update.go: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "func verifySensorsIntactWatchdog(")
	if start < 0 {
		t.Fatal("verifySensorsIntactWatchdog not found in update.go")
	}
	end := strings.Index(body[start:], "\n}")
	if end < 0 {
		t.Fatal("verifySensorsIntactWatchdog body not found")
	}
	fn := body[start : start+end]
	if !strings.Contains(fn, "store.NewStoreReadOnly(backup)") {
		t.Error("verifySensorsIntactWatchdog no longer opens the pre-update backup with store.NewStoreReadOnly — the verifier must never write to the safety copy")
	}
	if strings.Contains(fn, "store.NewStore(backup)") {
		t.Error("verifySensorsIntactWatchdog opens the backup read-write (store.NewStore) — the safety copy becomes writable and WAL sidecars get created beside it")
	}
}
