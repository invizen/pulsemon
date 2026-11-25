// CRITICAL-3 (2026-11-25): the rollback watchdog lost the service bus.
// buildWatchdogCommand captured the authoritative bus ("user"/"system") at
// spawn time, used it only for the systemd-run prefix, and discarded it; at
// rollback time the service had either crashed (activating/failed — the
// unhealthy path) or been stopped for the DB restore (the sensor-loss
// path), so detectRestart() (systemctl is-active) reported "" and the
// post-rollback restart was skipped entirely, or issued to the SYSTEM bus
// without --user — failing on every user-bus install. The monitor came
// back with the restored binary and stayed offline.
//
// These pins close the chain: the bus rides in the spawn argv, the CLI
// accepts and validates it, and BOTH rollback paths restart on the
// spawn-time bus. runRestart also resets a failed unit state first (a
// crash-looped broken binary trips StartLimitBurst, and until the failed
// state is cleared the restart fails with "start-limit-hit" no matter how
// often it is retried).
//
// Run with: go test -run 'TestBuildWatchdogCommandPassesBus|TestRunRestart|TestRunWatchdogUnhealthy|TestVerifySensorsRestartsWithSpawnBus|TestWatchdogCLI' .

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"pulsemon/internal/store"
)

// TestBuildWatchdogCommandPassesBus pins the spawn contract: the bus is in
// the watchdog argv (--bus) for every shape — plain and systemd-run scope,
// user/system, and the empty-bus (non-systemd) case, where the argv shape
// stays constant and the watchdog falls back to detection.
func TestBuildWatchdogCommandPassesBus(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "pulsemon")
	prev := exe + ".prev"
	for _, p := range []string{exe, prev} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("plain", func(t *testing.T) {
		oldRun := systemdRunPath
		systemdRunPath = func() string { return "" }
		t.Cleanup(func() { systemdRunPath = oldRun })

		for _, bus := range []string{"user", "system", ""} {
			cmd := buildWatchdogCommand(exe, bus)
			want := []string{prev, "update", "watchdog", "--prev", prev, "--dst", exe,
				"--bus", bus,
				"--timeout", watchdogTimeout().String(), "--old-pid", strconv.Itoa(os.Getpid())}
			if !reflect.DeepEqual(cmd.Args, want) {
				t.Errorf("bus=%q: args = %v, want %v", bus, cmd.Args, want)
			}
		}
	})

	t.Run("systemd-run", func(t *testing.T) {
		oldRun := systemdRunPath
		systemdRunPath = func() string { return "/usr/bin/systemd-run" }
		t.Cleanup(func() { systemdRunPath = oldRun })

		for _, tc := range []struct {
			bus    string
			prefix []string
		}{
			{"user", []string{"--user", "--scope"}},
			{"system", []string{"--scope"}},
		} {
			cmd := buildWatchdogCommand(exe, tc.bus)
			want := append([]string{"/usr/bin/systemd-run"}, append(tc.prefix, prev, "update", "watchdog")...)
			if !reflect.DeepEqual(cmd.Args[:len(want)], want) {
				t.Fatalf("bus=%q: args = %v, want prefix %v", tc.bus, cmd.Args, want)
			}
			// --bus must ride into the watchdog argv past the scope prefix.
			idx := -1
			for i, a := range cmd.Args {
				if a == "--bus" {
					idx = i
				}
			}
			if idx < 0 || idx+1 >= len(cmd.Args) || cmd.Args[idx+1] != tc.bus {
				t.Errorf("bus=%q: argv missing --bus %q: %v", tc.bus, tc.bus, cmd.Args)
			}
		}
	})
}

// fakeSystemctl writes a fake systemctl that logs its argv to log, one
// call per line.
func fakeSystemctl(t *testing.T, script string) (log string) {
	t.Helper()
	dir := t.TempDir()
	log = filepath.Join(dir, "calls.log")
	fake := filepath.Join(dir, "systemctl")
	full := "#!/bin/sh\n" + strings.ReplaceAll(script, "LOG", `"`+log+`"`)
	if err := os.WriteFile(fake, []byte(full), 0o755); err != nil {
		t.Fatal(err)
	}
	oldSP := systemctlPath
	systemctlPath = func() string { return fake }
	t.Cleanup(func() { systemctlPath = oldSP })
	return log
}

// TestRunRestartResetsFailedBeforeRestart pins the start-limit fix: a
// `reset-failed` on the SAME bus must be issued BEFORE the restart, for
// both user and system — without it, a crash-looped broken binary leaves
// the unit at start-limit-hit and the post-rollback restart can never
// succeed.
func TestRunRestartResetsFailedBeforeRestart(t *testing.T) {
	for _, bus := range []string{"user", "system"} {
		t.Run(bus, func(t *testing.T) {
			log := fakeSystemctl(t, "echo \"$@\" >> LOG\nexit 0\n")

			if err := runRestart(bus); err != nil {
				t.Fatalf("runRestart(%q) = %v, want nil", bus, err)
			}
			b, err := os.ReadFile(log)
			if err != nil {
				t.Fatalf("read calls.log: %v", err)
			}
			lines := strings.Split(strings.TrimSpace(string(b)), "\n")
			wantReset, wantRestart := "reset-failed pulsemon", "restart pulsemon"
			if bus == "user" {
				wantReset = "--user reset-failed pulsemon"
				wantRestart = "--user restart pulsemon"
			}
			if len(lines) != 2 || lines[0] != wantReset || lines[1] != wantRestart {
				t.Fatalf("systemctl calls = %v, want [%q, %q] (reset-failed before restart, on the same bus)", lines, wantReset, wantRestart)
			}
		})
	}
}

// TestRunRestartResetFailedFailureIsBestEffort pins the best-effort
// semantics: a reset-failed that fails (e.g. no such unit on the bus)
// must NOT block the restart — the restart is the load-bearing call.
func TestRunRestartResetFailedFailureIsBestEffort(t *testing.T) {
	log := fakeSystemctl(t, "echo \"$@\" >> LOG\ncase \"$1\" in\n  reset-failed) exit 1;;\nesac\nexit 0\n")

	if err := runRestart("system"); err != nil {
		t.Fatalf("runRestart = %v, want nil (a reset-failed failure must not block the restart)", err)
	}
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("read calls.log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 || lines[1] != "restart pulsemon" {
		t.Fatalf("systemctl calls = %v, want the restart to have run after the failed reset", lines)
	}
}

// unhealthyWatchdogFixture lays out the rollback inputs and points the
// healthz poll at a dead port (nothing answers → unhealthy).
func unhealthyWatchdogFixture(t *testing.T) (prev, dst string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("PULSEMON_DB", filepath.Join(dir, "x.db"))
	t.Setenv("PULSEMON_ADDR", "127.0.0.1:1")
	prev = filepath.Join(dir, "pulsemon.prev")
	dst = filepath.Join(dir, "pulsemon")
	if err := os.WriteFile(prev, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("NEW"), 0o755); err != nil {
		t.Fatal(err)
	}
	return prev, dst
}

// TestRunWatchdogUnhealthyRestartsWithSpawnBus is the core pin for the
// unhealthy path: the service has CRASHED (detectRestart reports ""), the
// rollback restored the previous binary, and the restart must now go out
// on the SPAWN-TIME bus — pre-fix, the detect-only lookup returned "" and
// the restart was skipped, leaving the monitor dead.
func TestRunWatchdogUnhealthyRestartsWithSpawnBus(t *testing.T) {
	prev, dst := unhealthyWatchdogFixture(t)

	var restarted []string
	oD, oP := detectRestart, performRestart
	detectRestart = func() string { return "" } // the crashed service: is-active reports nothing
	performRestart = func(bus string) error {
		restarted = append(restarted, bus)
		return nil
	}
	t.Cleanup(func() { detectRestart, performRestart = oD, oP })

	code := runWatchdog(prev, dst, "user", time.Second, 0)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (rollback + restart on the spawn-time bus)", code)
	}
	if b, _ := os.ReadFile(dst); string(b) != "OLD" {
		t.Errorf("dst = %q, want OLD (rolled back)", b)
	}
	if len(restarted) != 1 || restarted[0] != "user" {
		t.Fatalf("restarted = %v, want [user] (the spawn-time bus — a crashed service is not 'active', so re-detection must not decide the restart)", restarted)
	}
}

// Positive control: no spawn-time bus AND nothing detectable — the safe
// default is to roll back and NOT guess a restart (a blind system-bus
// restart on a user-bus install would fail; a restart with no bus at all
// is a guess on a mixed fleet).
func TestRunWatchdogUnhealthyNoBusNoRestart(t *testing.T) {
	prev, dst := unhealthyWatchdogFixture(t)

	var restarted []string
	oD, oP := detectRestart, performRestart
	detectRestart = func() string { return "" }
	performRestart = func(bus string) error {
		restarted = append(restarted, bus)
		return nil
	}
	t.Cleanup(func() { detectRestart, performRestart = oD, oP })

	code := runWatchdog(prev, dst, "", time.Second, 0)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (rollback succeeded; no bus is not an error)", code)
	}
	if b, _ := os.ReadFile(dst); string(b) != "OLD" {
		t.Errorf("dst = %q, want OLD (rolled back)", b)
	}
	if len(restarted) != 0 {
		t.Fatalf("restarted = %v, want none (no spawn-time bus, nothing detected — the old safe default)", restarted)
	}
}

// TestVerifySensorsRestartsWithSpawnBus is the core pin for the sensor-loss
// path: after the stop-for-restore, the service is DOWN, so detectRestart
// reports "" — pre-fix, performRestart(detectRestart()) issued
// `systemctl restart pulsemon` on the SYSTEM bus (no --user), failing on
// every user-bus install. The restart must go out on the spawn-time bus.
func TestVerifySensorsRestartsWithSpawnBus(t *testing.T) {
	// live=1 < backup=3 → data loss → the full restore path.
	dir, prevBin, dstBin := setupVerifyFixture(t, 1, 3)

	var restarted []string
	oldWait, oldState, oldStop := restartSensorWait, serviceStateFn, stopForRestoreFn
	oldPerf, oldDetect := performRestart, detectRestart
	restartSensorWait = func(*store.Store, time.Duration) (int, bool, string) { return 1, true, "test" }
	serviceStateFn = func() (string, error) { return "stopped", nil }
	stopForRestoreFn = func() error { return nil }
	performRestart = func(bus string) error {
		restarted = append(restarted, bus)
		return nil
	}
	detectRestart = func() string { return "" } // post-stop: the service is down
	t.Cleanup(func() {
		restartSensorWait, serviceStateFn, stopForRestoreFn = oldWait, oldState, oldStop
		performRestart, detectRestart = oldPerf, oldDetect
	})

	verifySensorsIntactWatchdog(nil, prevBin, dstBin, "user")

	if n := liveSensorCount(t, dir); n != 3 {
		t.Errorf("live DB after restore = %d sensors, want 3 (from the backup)", n)
	}
	if got, _ := os.ReadFile(dstBin); string(got) != "OLD" {
		t.Errorf("binary = %q, want OLD (rolled back)", got)
	}
	if len(restarted) != 1 || restarted[0] != "user" {
		t.Fatalf("restarted = %v, want [user] (the spawn-time bus — after the stop, re-detection reports \"\" and a detect-only restart would hit the system bus without --user)", restarted)
	}
}

// TestWatchdogCLIRejectsUnknownBus pins the parse-time validation: a
// garbage --bus is refused before the watchdog touches anything (it would
// otherwise be issued to systemctl for a unit that is not there).
func TestWatchdogCLIRejectsUnknownBus(t *testing.T) {
	dir := t.TempDir()
	prev, dst := filepath.Join(dir, "p.prev"), filepath.Join(dir, "p")
	if err := os.WriteFile(prev, []byte("OLD"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("NEW"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, out := captureOutput(t, func() int {
		return runUpdate([]string{"watchdog", "--prev", prev, "--dst", dst, "--bus", "bogus"})
	})
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (an unknown bus must be refused at parse time)", code)
	}
	if !strings.Contains(out, "invalid --bus") {
		t.Errorf("output missing the invalid --bus diagnostic: %s", out)
	}
}

// TestWatchdogCLIAcceptsKnownBus is the positive control: a valid --bus
// sails through parsing and reaches the old-pid guard (which exits 1
// while the "old" process — us — is alive). Reaching the guard proves the
// bus was accepted, not rejected.
func TestWatchdogCLIAcceptsKnownBus(t *testing.T) {
	dir := t.TempDir()
	prev, dst := filepath.Join(dir, "p.prev"), filepath.Join(dir, "p")
	if err := os.WriteFile(prev, []byte("OLD"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("NEW"), 0o644); err != nil {
		t.Fatal(err)
	}

	oT := wdOldProcTimeout
	wdOldProcTimeout = 200 * time.Millisecond
	t.Cleanup(func() { wdOldProcTimeout = oT })

	code, out := captureOutput(t, func() int {
		return runUpdate([]string{"watchdog", "--prev", prev, "--dst", dst, "--bus", "user",
			"--old-pid", strconv.Itoa(os.Getpid())})
	})
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (the old-pid guard exits; parsing must not)", code)
	}
	if !strings.Contains(out, "still alive") {
		t.Errorf("output missing the old-pid guard message (parsing accepted the bus and reached the guard): %s", out)
	}
}
