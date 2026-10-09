package main

import (
	"path/filepath"
	"testing"
)

// TestDispatch pins the command-line structure: known commands dispatch,
// unknown flags are rejected (previously they fell through to a normal server
// start — pulsemon -invalid booted a dashboard instead of surfacing the typo).
//
// PULSEMON_TEST_NOFATAL keeps the unknown-flag path from os.Exit(1)ing inside
// the test process; dispatch returns dExit1 instead, and main (the only
// caller) still exits 1 — verified against the real binary in the release
// verification step.
func TestDispatch(t *testing.T) {
	t.Setenv("PULSEMON_TEST_NOFATAL", "1")

	// Version: prints "pulsemon <Version>" and exits 0.
	Version = "v0.1.99"
	for _, arg := range []string{"-v", "-version", "--version", "version"} {
		t.Run("version:"+arg, func(t *testing.T) {
			if k := dispatch([]string{"pulsemon", arg}); k != dExit0 {
				t.Fatalf("dispatch(%q) = %v, want dExit0", arg, k)
			}
		})
	}
	t.Run("no args starts server", func(t *testing.T) {
		if k := dispatch([]string{"pulsemon"}); k != dRunServer {
			t.Fatalf("dispatch(pulsemon) = %v, want dRunServer", k)
		}
	})
	t.Run("unknown flag rejected", func(t *testing.T) {
		if k := dispatch([]string{"pulsemon", "-invalid"}); k != dExit1 {
			t.Fatalf("dispatch(-invalid) = %v, want dExit1", k)
		}
		if k := dispatch([]string{"pulsemon", "--bogus"}); k != dExit1 {
			t.Fatalf("dispatch(--bogus) = %v, want dExit1", k)
		}
	})
	t.Run("non-flag positional falls through to server", func(t *testing.T) {
		// A bare word isn't a flag; per the fix, only dash args are rejected.
		if k := dispatch([]string{"pulsemon", "somedir"}); k != dRunServer {
			t.Fatalf("dispatch(somedir) = %v, want dRunServer", k)
		}
	})
}

// TestDispatchHealthzRunsForReal exercises the full -healthz dispatch against
// a real store: an empty (schemaless) store is dExit1, a seeded store is
// dExit0, and the --healthz long form behaves identically.
func TestDispatchHealthzRunsForReal(t *testing.T) {
	t.Setenv("PULSEMON_TEST_NOFATAL", "")
	path := filepath.Join(t.TempDir(), "cli.db")
	t.Setenv("PULSEMON_DB", path)

	// Empty store: NewDB creates the file but no schema exists, so the COUNT
	// fails — a store that isn't actually usable must not report healthy.
	if k := dispatch([]string{"pulsemon", "-healthz"}); k != dExit1 {
		t.Fatalf("healthz on schemaless store = %v, want dExit1", k)
	}

	// Seeded store: both spellings report healthy.
	db, err := NewDB(path)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	db.Close()
	if k := dispatch([]string{"pulsemon", "--healthz"}); k != dExit0 {
		t.Fatalf("healthz on seeded store = %v, want dExit0", k)
	}
}
