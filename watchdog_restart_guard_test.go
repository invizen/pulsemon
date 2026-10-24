package main

// Review 2026-10-24 (Major): the I2 restart watchdog could never guard the
// dashboard update path. handleUpdate holds the cross-process update flock
// until it returns (defer lockFile.Close) — which is AFTER performRestart —
// while runWatchdog's first act was a SINGLE non-blocking flock acquisition.
// Empirically (live probe on zentest): with the lock held, `pulsemon update
// watchdog` exits 1 in 3ms. And any variant that polled health first would
// have read the OLD server's valid healthz payload as a healthy restart.
// Fix: wait for the spawning process (--old-pid) to exit, THEN retry the
// lock (lockRetryBudget), THEN poll healthz. These tests pin the guard order.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func watchdogFixture(t *testing.T) (prev, dst string) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("PULSEMON_DB", filepath.Join(tmp, "x.db"))
	prev = filepath.Join(tmp, "pulsemon.prev")
	dst = filepath.Join(tmp, "pulsemon")
	if err := os.WriteFile(prev, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("NEW"), 0o755); err != nil {
		t.Fatal(err)
	}
	oD, oP := detectRestart, performRestart
	detectRestart = func() string { return "" }
	performRestart = func(string) error { return nil }
	t.Cleanup(func() { detectRestart, performRestart = oD, oP })
	return prev, dst
}

func startHealthy(t *testing.T) {
	t.Helper()
	hz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","version":"v9.9.9"}`))
	}))
	t.Cleanup(hz.Close)
	t.Setenv("PULSEMON_ADDR", strings.TrimPrefix(hz.URL, "http://"))
}

// TestWatchdogWaitsForOldPID: with a healthy healthz ALREADY answering (the
// old server, still up), the watchdog must not declare success before the
// spawning process exits — pre-fix it polled immediately and returned 0
// (false healthy). The elapsed-time floor pins the wait.
func TestWatchdogWaitsForOldPID(t *testing.T) {
	prev, dst := watchdogFixture(t)
	startHealthy(t)
	child := exec.Command("sleep", "0.6")
	if err := child.Start(); err != nil {
		t.Skipf("cannot spawn sleep: %v", err)
	}
	// REAP it: kill(pid,0) succeeds on a zombie, and unlike production
	// (where systemd/PID-1 reaps the dying old server), this child is OURS
	// — without a reaper the watchdog would correctly see "still alive"
	// forever. Production semantics: flock fds close at process EXIT, so a
	// reaped old server means lock-released for the watchdog.
	go func() { _ = child.Wait() }()
	// Kill only — the reaper goroutine above owns the single Wait (two
	// Waits on one *exec.Cmd is a data race).
	t.Cleanup(func() { _ = child.Process.Kill() })

	start := time.Now()
	code := runWatchdog(prev, dst, 2*time.Second, child.Process.Pid)
	elapsed := time.Since(start)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (healthy once the old process is gone)", code)
	}
	if elapsed < 500*time.Millisecond {
		t.Fatalf("watchdog finished in %v while the old server lived — it polled health/lock BEFORE the spawn-side process died (the false-healthy path)", elapsed)
	}
	if b, _ := os.ReadFile(dst); string(b) != "NEW" {
		t.Errorf("dst = %q, want NEW untouched", b)
	}
}

// TestWatchdogGivesUpOnLiveOldPID: if the old process never exits within
// wdOldProcTimeout, the watchdog must exit 1 WITHOUT renaming anything —
// its healthz is not the new binary's health, and a blind rollback-rename
// of a running service's binary is worse than doing nothing.
func TestWatchdogGivesUpOnLiveOldPID(t *testing.T) {
	prev, dst := watchdogFixture(t)
	startHealthy(t)
	child := exec.Command("sleep", "5")
	if err := child.Start(); err != nil {
		t.Skipf("cannot spawn sleep: %v", err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })

	oT := wdOldProcTimeout
	wdOldProcTimeout = 200 * time.Millisecond
	defer func() { wdOldProcTimeout = oT }()

	code := runWatchdog(prev, dst, time.Second, child.Process.Pid)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (old process still alive; no guard possible)", code)
	}
	if b, _ := os.ReadFile(dst); string(b) != "NEW" {
		t.Errorf("dst = %q, want NEW untouched (no rollback against a live old process)", b)
	}
}

// TestWatchdogRetriesUpdateLock: the flock is held (the spawning server is
// still alive); the watchdog must RETRY within lockRetryBudget instead of
// exiting on the first EWOULDBLOCK.
func TestWatchdogRetriesUpdateLock(t *testing.T) {
	prev, dst := watchdogFixture(t)
	t.Setenv("PULSEMON_ADDR", "127.0.0.1:1") // unreachable: never reaches healthy
	lock, err := acquireUpdateLock()
	if err != nil {
		t.Fatalf("acquire lock: %v", err)
	}
	defer lock.Close()

	oB := lockRetryBudget
	lockRetryBudget = 300 * time.Millisecond
	defer func() { lockRetryBudget = oB }()

	start := time.Now()
	code := runWatchdog(prev, dst, time.Second, 0)
	elapsed := time.Since(start)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (lock never released)", code)
	}
	if elapsed < 250*time.Millisecond {
		t.Fatalf("watchdog gave up after %v — lock acquisition must RETRY within lockRetryBudget, not exit on the first EWOULDBLOCK (the pre-fix behavior)", elapsed)
	}
	if b, _ := os.ReadFile(dst); string(b) != "NEW" {
		t.Errorf("dst = %q, want NEW untouched", b)
	}
}

// TestWatchdogAcquiresLockAfterRelease: the lock holder (the dying server)
// releases shortly after spawn — the watchdog must pick the lock up and
// proceed to health polling.
func TestWatchdogAcquiresLockAfterRelease(t *testing.T) {
	prev, dst := watchdogFixture(t)
	startHealthy(t)
	lock, err := acquireUpdateLock()
	if err != nil {
		t.Fatalf("acquire lock: %v", err)
	}
	go func() {
		time.Sleep(250 * time.Millisecond)
		lock.Close()
	}()

	code := runWatchdog(prev, dst, 3*time.Second, 0)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (lock acquired after release, healthy)", code)
	}
	if b, _ := os.ReadFile(dst); string(b) != "NEW" {
		t.Errorf("dst = %q, want NEW untouched", b)
	}
}
