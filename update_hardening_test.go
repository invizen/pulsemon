package main

// Review 2026-10-24 minor/hardening batch — update path:
//   (a) installBinary used to verify the src PATH and then re-read it, so a
//       swap between verifyDownloadedAsset and the staging copy could install
//       unverified bytes. installBinary now hashes the exact bytes it stages
//       and refuses BEFORE touching dst when they drift from the verified
//       digest.
//   (b) the watchdog health budget was a hardcoded 30s, which rolls back a
//       working-but-slow start on huge DBs; PULSEMON_WATCHDOG_TIMEOUT now
//       overrides it (Go duration, clamped 5s..5m, invalid keeps default).
//   (c) the update-lock TMPDIR fallback must say so — CLI and server under
//       systemd private /tmp silently lose mutual exclusion.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestInstallBinaryRefusesHashDrift(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "new.bin")
	dst := filepath.Join(dir, "pulsemon.bin")
	good := []byte("good-binary-bytes")
	if err := os.WriteFile(src, good, 0o755); err != nil {
		t.Fatal(err)
	}
	// A wrong wantSHA models the tamper: the bytes staged differ from what
	// was verified at the src path earlier.
	if err := installBinary(src, dst, strings.Repeat("00", 32)); err == nil {
		t.Fatal("installBinary accepted bytes that do not match the verified digest")
	}
	if _, err := os.Stat(dst); err == nil {
		t.Fatal("dst was created despite the hash refusal")
	}
	// Correct digest installs normally.
	sum := sha256.Sum256(good)
	if err := installBinary(src, dst, hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("installBinary with matching digest: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != string(good) {
		t.Fatalf("installed content mismatch: %q %v", got, err)
	}
	// Empty wantSHA keeps the legacy no-verify contract (documented).
	if err := installBinary(src, filepath.Join(dir, "legacy.bin"), ""); err != nil {
		t.Fatalf("installBinary wantSHA=\"\": %v", err)
	}
}

func TestWatchdogTimeoutEnv(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		t.Setenv("PULSEMON_WATCHDOG_TIMEOUT", "")
		if d := watchdogTimeout(); d != 30*time.Second {
			t.Errorf("default = %v, want 30s", d)
		}
	})
	t.Run("override", func(t *testing.T) {
		t.Setenv("PULSEMON_WATCHDOG_TIMEOUT", "90s")
		if d := watchdogTimeout(); d != 90*time.Second {
			t.Errorf("override = %v, want 90s", d)
		}
	})
	t.Run("below clamp", func(t *testing.T) {
		t.Setenv("PULSEMON_WATCHDOG_TIMEOUT", "1s")
		if d := watchdogTimeout(); d != 30*time.Second {
			t.Errorf("clamped = %v, want 30s default", d)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		t.Setenv("PULSEMON_WATCHDOG_TIMEOUT", "banana")
		if d := watchdogTimeout(); d != 30*time.Second {
			t.Errorf("invalid = %v, want 30s default", d)
		}
	})
}

func TestUpdateLockFallbackWarns(t *testing.T) {
	orig := runningExecutable
	defer func() { runningExecutable = orig }()
	runningExecutable = func() (string, error) { return "", os.ErrNotExist }
	// The warning is a sync.Once for the process; reset it so this test
	// observes its own first fallback regardless of suite ordering.
	lockFallbackOnce = sync.Once{}

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	p1 := updateLockPath()
	if !strings.HasPrefix(filepath.Clean(p1), filepath.Clean(os.TempDir())) {
		t.Fatalf("fallback path %q not under TMPDIR", p1)
	}
	_ = updateLockPath() // must not double-warn
	logs := buf.String()
	if !strings.Contains(logs, "update lock fell back") {
		t.Fatalf("fallback did not warn: %q", logs)
	}
	if strings.Count(logs, "update lock fell back") != 1 {
		t.Fatalf("warning repeated per call: %q", logs)
	}
}
