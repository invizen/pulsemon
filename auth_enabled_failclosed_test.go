package main

import (
	"errors"
	"testing"
	"time"
)

// TestFix_M2_EnabledFailsClosed pins the M2 fix: Enabled() computed
// `enabled = err == nil && n > 0`, so a transient COUNT(*) error (e.g.
// "database is locked") read as "auth disabled" for the 2s cache TTL — the
// auth gate FAILED OPEN on a DB hiccup. The fix keeps the last known value
// on error, and fails CLOSED (enabled) when there is no last known value
// (first-ever read).
func TestFix_M2_EnabledFailsClosed(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	if err := a.AddUser("bob", "longenoughpw"); err != nil {
		t.Fatal(err)
	}
	if !a.Enabled() {
		t.Fatal("baseline: auth must be enabled with one user")
	}

	// Transient DB error after the cache expired: the gate must keep the
	// last known state (enabled), not open.
	a.userCountFn = func() (int, error) { return 0, errors.New("database is locked") }
	a.enabledMu.Lock()
	a.enabledAt = time.Time{} // expire the cache
	a.enabledMu.Unlock()
	if !a.Enabled() {
		t.Error("Enabled() = false after a transient DB error — the gate failed OPEN; it must keep the last known state (enabled)")
	}

	// First-ever read that errors must fail CLOSED (enabled = true): a
	// fresh AuthState has no last known value, so the safe answer is "auth
	// on".
	b := NewAuthState(db)
	b.userCountFn = func() (int, error) { return 5, errors.New("database is locked") }
	if !b.Enabled() {
		t.Error("Enabled() = false on a first-ever count error — must fail CLOSED (enabled)")
	}

	// refreshEnabledNow must apply the same rule: an error while the state
	// is known keeps it; it must not flip a known-enabled state to open.
	a.refreshEnabledNow()
	if !a.Enabled() {
		t.Error("refreshEnabledNow on a DB error flipped a known-enabled state to disabled")
	}
}
