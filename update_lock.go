package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// errUpdateLockHeld is the stable sentinel for "another process is updating
// right now".
var errUpdateLockHeld = errors.New("update already in progress (another process holds the update lock)")

// updateLockPath is the cross-process update lock file:
// <binary dir>/.update.lock (F19).
//
// The lock is anchored to the EXECUTABLE's directory — not the DB directory
// — because that is where the race actually lives: installBinary renames the
// new binary over <exe> and keeps the old one at <exe>.prev, so the
// cross-process contention is on files beside the binary. Anchoring there
// also guarantees the CLI (`pulsemon update`) and the server
// (POST /api/update) agree on the SAME lock file, because both resolve the
// binary via runningExecutable() (the same installed path in production).
//
// Anchoring to the DB dir (dbPathFromEnv) was wrong in two ways: in tests
// the DB sits in t.TempDir() while PULSEMON_DB is unset, so the lock landed
// in /data/.update.lock (uncreatable for a non-root test); and in a
// deployment where the DB and the binary live in different directories the
// CLI and the server would lock DIFFERENT files, silently defeating the
// whole point. When the binary can't be located (shouldn't happen — the
// process is running) we fall back to os.TempDir(), which is always
// writable, so a resolution hiccup degrades to a weaker-but-present lock
// rather than a hard update failure.
func updateLockPath() string {
	exe, err := runningExecutable()
	if err != nil || exe == "" {
		return filepath.Join(os.TempDir(), ".update.lock")
	}
	return filepath.Join(filepath.Dir(exe), ".update.lock")
}

// acquireUpdateLock takes the cross-process exclusive update lock
// (non-blocking). The returned *os.File must be kept open until the update
// span ends — closing it releases the lock (flock/LockFileEx locks die
// with the file descriptor, so a crash never leaves a stale lock behind).
//
// Why a file lock in addition to updateMu: the in-process mutex only
// serializes requests within ONE process. The CLI (`pulsemon update
// --restart`) and the dashboard endpoint (POST /api/update, server process)
// are DIFFERENT processes that would race each other on the .prev rename in
// installBinary — two overlapping installs can clobber each other's .prev
// (losing the rollback binary) or interleave a torn pair.
func acquireUpdateLock() (*os.File, error) {
	lockPath := updateLockPath()
	// Create the parent dir before opening. In production the binary dir
	// already exists (the process runs from it); in a throwaway/test
	// environment the stubbed binary may point at a dir we should still be
	// able to create. A missing dir must not turn every update into a hard
	// "no such file or directory" failure (review F19 follow-up).
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return nil, fmt.Errorf("create update lock dir %s: %w", filepath.Dir(lockPath), err)
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open update lock %s: %w", lockPath, err)
	}
	ok, err := tryFlock(f)
	if !ok {
		f.Close()
		if err != nil {
			return nil, err
		}
		return nil, errUpdateLockHeld
	}
	return f, nil
}
