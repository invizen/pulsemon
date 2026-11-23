//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"pulsemon/internal/store"
)

// runRestartHelper is the detached self-restart helper for the Windows
// in-dashboard update: the updating service process is about to die, so a
// child of the NEW binary waits here for the service to reach the stopped
// state, then starts it again. The child inherits the service's virtual
// account (NT SERVICE\Pulsemon), which the SCM grants full control of its
// own service.
//
// It logs to <datadir>\pulsemon-restart.log: the process is detached with
// no console, so the file is the only post-mortem audience.
//
// Exit codes: 0 = service started; non-zero = the service was left as-is
// (a human looks at the log).
func runRestartHelper() int {
	logLine := func(format string, a ...any) {
		// Go forbids extra fixed args alongside a `s...` expansion (the
		// expansion must supply the ENTIRE variadic tail), so the timestamp
		// rides in the slice.
		args := append([]any{time.Now().Format(time.RFC3339)}, a...)
		line := fmt.Sprintf("%s restart-helper: "+format+"\n", args...)
		path := filepath.Join(filepath.Dir(dbPathFromEnv()), "pulsemon-restart.log")
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			log.Printf("restart-helper: log write: %v", err)
			return
		}
		defer f.Close()
		_, _ = f.WriteString(line)
	}

	logLine("started; waiting for the %s service to stop", serviceName)
	m, err := mgr.Connect()
	if err != nil {
		logLine("open SCM failed: %v", err)
		return 1
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		logLine("open service failed: %v", err)
		return 2
	}
	defer s.Close()

	// The updating service's clean drain is bounded at ~30s (probe + alert
	// + HTTP backstops) plus SCM stop grace; 90s is generous headroom.
	deadline := time.Now().Add(90 * time.Second)
	for {
		st, err := s.Query()
		if err != nil {
			logLine("query service failed: %v", err)
			return 3
		}
		if st.State == svc.Stopped {
			break
		}
		if time.Now().After(deadline) {
			logLine("service did not reach stopped within 90s; leaving it alone")
			return 4
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err := s.Start(); err != nil {
		logLine("start service failed: %v", err)
		return 5
	}
	logLine("service started")
	return verifySensorsIntact(logLine)
}

// restartSensorWaitTimeout bounds the post-restart healthz poll in the
// verifier. The helper already waited up to 90s for the STOP; the start is
// fast, but a crashing new binary may need a few seconds of SCM
// restart-on-failure cycles before it answers, so 90s total. A var so a
// test can shrink it.
var restartSensorWaitTimeout = 90 * time.Second

// restartSensorWait is a seam over waitSensorCount so the verifier's test
// can stub it (a unit test must not poll a real port).
var restartSensorWait = func(db *store.Store, timeout time.Duration) (int, bool, string) {
	return waitSensorCount(db, timeout)
}

// restoreDatabaseFile replaces the live DB with a copy of backup (a
// consistent VACUUM INTO snapshot). The service is STOPPED when this runs,
// so nobody has the DB open. The live -wal/-shm files belong to the live
// DB's last session and must NOT replay over the restored file: remove
// them first (SQLite would replay them on the next open, mixing stale WAL
// pages into the snapshot).
func restoreDatabaseFile(backup, live string) error {
	_ = os.Remove(live + "-wal")
	_ = os.Remove(live + "-shm")
	data, err := os.ReadFile(backup)
	if err != nil {
		return err
	}
	return os.WriteFile(live, data, 0o644)
}

// verifySensorsIntact is the post-restart data-loss check (the
// belt-and-suspenders half of the self-update): the update wrote
// pulsemon.db.preupdate (a VACUUM INTO snapshot) BEFORE swapping the
// binary, so now that the service is back up, compare the live sensor
// count against the pre-update one. If the count DROPPED, restore the
// backup DB and roll the binary back to .prev, then restart the service
// on the known-good pair.
//
// It deliberately does NOT act when it cannot verify (no backup, no usable
// healthz): the update watchdog already owns the "service did not come up"
// case (binary rollback), and double-acting on an unverifiable state risks
// clobbering a healthy install.
//
// logLine is the helper's file logger (this process is detached, no
// console). Exit codes continue the helper's scheme: 0 = verified, or
// nothing to verify; 6..9 = the specific failure that left the service
// as-is for a human (see the log).
func verifySensorsIntact(logLine func(string, ...any)) int {
	dbPath := dbPathFromEnv()
	backup := filepath.Join(filepath.Dir(dbPath), "pulsemon.db.preupdate")
	if _, err := os.Stat(backup); err != nil {
		logLine("no pre-update backup; skipping sensor verification")
		return 0
	}
	bst, err := store.NewStore(backup)
	if err != nil {
		logLine("cannot open pre-update backup (%v); skipping verification", err)
		return 0
	}
	want, err := bst.SensorCount()
	bst.Close()
	if err != nil {
		logLine("cannot count sensors in pre-update backup (%v); skipping verification", err)
		return 0
	}
	live, ok, detail := restartSensorWait(openHealthzDB(), restartSensorWaitTimeout)
	if !ok {
		logLine("service not healthy within %s (%s); leaving it to the watchdog/human", restartSensorWaitTimeout, detail)
		return 6
	}
	rest, reason := sensorRestoreDecision(live, want, true)
	if !rest {
		logLine("verified: %s", reason)
		return 0
	}
	logLine("data loss after update: %s; restoring pre-update DB and previous binary", reason)

	// The update lock keeps this restore from racing the update watchdog
	// (which holds the same lock for its own rollback). The watchdog has
	// already exited by the time the service is healthy, so the lock is
	// normally free; a held lock means it is still working.
	lockFile, err := acquireUpdateLock()
	if err != nil {
		logLine("update lock not available (%v); skipping restore - the watchdog may be handling it", err)
		return 0
	}
	defer lockFile.Close()

	if err := stopWindowsServiceFn(); err != nil {
		logLine("stop service for restore failed: %v", err)
		return 7
	}
	if err := restoreDatabaseFile(backup, dbPath); err != nil {
		logLine("DB restore failed: %v; starting the service on the current DB", err)
	} else {
		logLine("pre-update DB restored")
	}
	exe, err := serviceBinPathFn()
	if err != nil {
		logLine("cannot locate binary for rollback: %v", err)
	} else if rerr := rollbackBinaryFile(exe+".prev", exe); rerr != nil {
		logLine("binary rollback failed: %v", rerr)
	} else {
		logLine("previous binary restored")
	}
	if err := startWindowsServiceFn(); err != nil {
		logLine("start service after restore failed: %v", err)
		return 9
	}
	logLine("service restarted on the pre-update DB and previous binary")
	return 0
}
