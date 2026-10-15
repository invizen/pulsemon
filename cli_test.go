package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
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

// setTestStdin points os.Stdin at a pipe carrying s for the duration of the
// test (restored after). A pipe is not a TTY, so the stdin password forms
// read it silently — the same path a `read -s`-style caller would take.
func setTestStdin(t *testing.T, s string) {
	t.Helper()
	old := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, s); err != nil {
		t.Fatal(err)
	}
	w.Close()
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })
}

// TestAuthUserAdd pins the m4 forms of `auth-user add`: the 2-arg form and
// --password-stdin read the password from stdin; the legacy 3-arg form
// still works; empty stdin and bad arg counts are refused. The store is a
// real temp DB (PULSEMON_DB), and each added user is verified by
// authenticating against it — so the stdin password actually landed.
func TestAuthUserAdd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authcli.db")
	t.Setenv("PULSEMON_DB", path)

	t.Run("2-arg form reads password from stdin", func(t *testing.T) {
		setTestStdin(t, "stdin-secret-1\n")
		if k := dispatch([]string{"pulsemon", "auth-user", "add", "alice"}); k != dExit0 {
			t.Fatalf("add alice (stdin) = %v, want dExit0", k)
		}
	})
	t.Run("--password-stdin form reads password from stdin", func(t *testing.T) {
		setTestStdin(t, "stdin-secret-2\n")
		if k := dispatch([]string{"pulsemon", "auth-user", "add", "bob", "--password-stdin"}); k != dExit0 {
			t.Fatalf("add bob --password-stdin = %v, want dExit0", k)
		}
	})
	t.Run("legacy 3-arg form still works", func(t *testing.T) {
		if k := dispatch([]string{"pulsemon", "auth-user", "add", "carol", "argv-secret-3"}); k != dExit0 {
			t.Fatalf("add carol <pass> = %v, want dExit0", k)
		}
	})
	t.Run("empty stdin is refused", func(t *testing.T) {
		setTestStdin(t, "")
		if k := dispatch([]string{"pulsemon", "auth-user", "add", "dave"}); k != dExit1 {
			t.Fatalf("add dave (empty stdin) = %v, want dExit1", k)
		}
	})
	t.Run("missing username is a usage error", func(t *testing.T) {
		if k := dispatch([]string{"pulsemon", "auth-user", "add"}); k != dExit2 {
			t.Fatalf("add (no args) = %v, want dExit2", k)
		}
	})
	t.Run("password plus flag is a usage error", func(t *testing.T) {
		if k := dispatch([]string{"pulsemon", "auth-user", "add", "erin", "x", "--password-stdin"}); k != dExit2 {
			t.Fatalf("add erin <pass> --password-stdin = %v, want dExit2", k)
		}
	})

	// Verify the three users exist and their passwords are exactly the
	// ones supplied (stdin forms included).
	db, err := NewDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	users, err := db.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, u := range users {
		names[u.Username] = true
	}
	for _, want := range []string{"alice", "bob", "carol"} {
		if !names[want] {
			t.Errorf("user %s missing after add (users: %v)", want, names)
		}
	}
	if names["dave"] || names["erin"] {
		t.Errorf("refused adds created users: %v", names)
	}
	a := NewAuthState(db)
	for user, pass := range map[string]string{
		"alice": "stdin-secret-1",
		"bob":   "stdin-secret-2",
		"carol": "argv-secret-3",
	} {
		if _, ok := a.CreateSession(user, pass); !ok {
			t.Errorf("login %s with its added password failed — the stored password is wrong", user)
		}
	}
}

// TestReadPasswordLine pins the stdin reader: strips the trailing newline
// (and CR), and rejects empty input with a clear error.
func TestReadPasswordLine(t *testing.T) {
	if got, err := readPasswordLine(strings.NewReader("hunter2\n")); err != nil || got != "hunter2" {
		t.Errorf("readPasswordLine = %q, %v; want hunter2, nil", got, err)
	}
	if got, err := readPasswordLine(strings.NewReader("win-pass\r\n")); err != nil || got != "win-pass" {
		t.Errorf("CRLF input = %q, %v; want win-pass, nil", got, err)
	}
	// No trailing newline (piped printf without \n) is still fine.
	if got, err := readPasswordLine(strings.NewReader("no-newline")); err != nil || got != "no-newline" {
		t.Errorf("no-newline input = %q, %v; want no-newline, nil", got, err)
	}
	if _, err := readPasswordLine(strings.NewReader("")); err == nil {
		t.Error("empty stdin: expected an error")
	}
	if _, err := readPasswordLine(strings.NewReader("\n")); err == nil {
		t.Error("newline-only stdin: expected an error")
	}
}
