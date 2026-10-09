package main

import (
	"errors"
	"strings"
	"testing"
)

// TestRequestRestartBareNoKillOnReexecFailure locks the Major fix: when
// the bare-process re-exec fails, requestRestart must NOT SIGTERM itself
// (which left the monitor dead with no successor — a TLS settings change
// became a permanent outage on any fork/exec failure). It must instead
// report restarted=false with an actionable hint and leave killSelf
// untouched.
func TestRequestRestartBareNoKillOnReexecFailure(t *testing.T) {
	origReexec, origKill := reexecFn, killSelf
	defer func() { reexecFn, killSelf = origReexec, origKill }()

	killed := false
	killSelf = func() { killed = true }
	reexecFn = func() error { return errors.New("fork: resource temporarily unavailable") }

	// Force the bare-process default branch: not systemd-managed, not a
	// container.
	t.Setenv("SYSTEMD_EXEC_PID", "")

	out := requestRestart()
	if killed {
		t.Fatal("requestRestart SIGTERMed itself despite re-exec failure — the outage bug is back")
	}
	if out.restarted {
		t.Fatal("restarted=true must not be reported when re-exec failed")
	}
	if !strings.Contains(out.hint, "re-exec failed") {
		t.Fatalf("hint should explain the failed re-exec, got: %q", out.hint)
	}
}

// TestRequestRestartBareKillsOnReexecSuccess is the happy-path twin: a
// successful re-exec MUST still self-SIGTERM so the child can bind.
func TestRequestRestartBareKillsOnReexecSuccess(t *testing.T) {
	origReexec, origKill := reexecFn, killSelf
	defer func() { reexecFn, killSelf = origReexec, origKill }()

	killed := false
	killSelf = func() { killed = true }
	reexecFn = func() error { return nil }

	t.Setenv("SYSTEMD_EXEC_PID", "")

	out := requestRestart()
	if !killed {
		t.Fatal("successful re-exec must still self-SIGTERM so the child can take the port")
	}
	if !out.restarted {
		t.Fatal("restarted=true expected on the successful re-exec path")
	}
}
