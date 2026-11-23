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
		// A fresh store as the "pre-update" snapshot, then copy its bytes
		// over: the verifier opens the backup with NewStore.
		tmp := filepath.Join(dir, "backup-tmp.db")
		seedSensors(t, tmp, backupSensors)
		data, err := os.ReadFile(tmp)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(backup, data, 0o644); err != nil {
			t.Fatal(err)
		}
		os.Remove(tmp)
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
