package main

// MAJOR-12 pins: no lock held across synchronous SQLite I/O in the
// per-request auth path, one lock pass for the gate's session work, and a
// lock-free fast path for Enabled(). History: docs/DECISIONS.md →
// auth-lock-io-split.

import (
	"context"
	"testing"
	"time"
)

// newAuthSessionFixture adds one user and mints a live session for it.
func newAuthSessionFixture(t *testing.T) (*AuthState, string) {
	t.Helper()
	db := newTestDB(t)
	a := NewAuthState(db)
	if err := a.AddUser(context.Background(), "admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
	tok, ok, _ := a.CreateSession(context.Background(), "admin", "secretpw", false)
	if !ok {
		t.Fatal("CreateSession")
	}
	return a, tok
}

// expireUserOKCache forces the next session validation to take the live
// users-table query path (a userOKCache miss).
func expireUserOKCache(a *AuthState, user string) {
	a.mu.Lock()
	delete(a.userOKCache, user)
	a.mu.Unlock()
}

// TestSessionUserQueryRunsOutsideMu: while the live user-existence query is
// in flight, a.mu MUST be acquirable. Pre-fix the query ran under the lock,
// so a DB stall (busy_timeout 15s: VACUUM INTO, history wipes, slow SD card)
// blocked a.mu and stalled every concurrent authenticated request. The
// stub probes the lock from a side goroutine with a watchdog so the
// pre-fix shape fails fast instead of hanging the suite.
func TestSessionUserQueryRunsOutsideMu(t *testing.T) {
	a, tok := newAuthSessionFixture(t)
	expireUserOKCache(a, "admin")

	restored := userExistsQuery
	userExistsQuery = func(st *AuthState, u string) bool {
		done := make(chan struct{})
		go func() {
			st.mu.Lock()
			st.mu.Unlock()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("a.mu not acquirable while the user-existence query runs — lock held across I/O")
		}
		return true
	}
	t.Cleanup(func() { userExistsQuery = restored })

	if u, ok := a.SessionUser(tok); !ok || u != "admin" {
		t.Fatalf("SessionUser = %q, %v; want admin, true", u, ok)
	}
}

// TestSessionUserDroppedMidQueryRejected: a logout landing in the I/O
// window must win over the query's "user exists" answer — the
// post-query re-validation is what enforces it (the pre-fix under-lock
// shape had no window, the out-of-lock shape needs the re-check).
func TestSessionUserDroppedMidQueryRejected(t *testing.T) {
	a, tok := newAuthSessionFixture(t)
	expireUserOKCache(a, "admin")

	restored := userExistsQuery
	userExistsQuery = func(st *AuthState, u string) bool {
		st.DropSession(tok) // logout arrives while the query runs
		return true
	}
	t.Cleanup(func() { userExistsQuery = restored })

	if u, ok := a.SessionUser(tok); ok || u != "" {
		t.Fatalf("SessionUser = %q, %v; want empty, false (dropped mid-query)", u, ok)
	}
}

// TestSessionUserDeletedUserRejected: a cache-miss validation whose live
// query answers "user gone" rejects the session AND deletes the entry —
// out-of-band CLI removal is honored within userOKTTL.
func TestSessionUserDeletedUserRejected(t *testing.T) {
	a, tok := newAuthSessionFixture(t)
	expireUserOKCache(a, "admin")

	restored := userExistsQuery
	userExistsQuery = func(st *AuthState, u string) bool { return false }
	t.Cleanup(func() { userExistsQuery = restored })

	if u, ok := a.SessionUser(tok); ok || u != "" {
		t.Fatalf("SessionUser = %q, %v; want empty, false (user gone)", u, ok)
	}
	a.mu.Lock()
	_, live := a.sessions[tok]
	a.mu.Unlock()
	if live {
		t.Fatal("rejected session entry must be deleted from the map")
	}
}

// TestSessionUserAndRenewalOnePass: the gate's combined check decides the
// sliding-cookie renewal in the SAME pass that validates (pre-fix two
// separate a.mu acquisitions), stamps cookieIssued exactly once, and the
// renew=false form (/api/auth/status) never stamps.
func TestSessionUserAndRenewalOnePass(t *testing.T) {
	a, tok := newAuthSessionFixture(t)

	// Age the cookie past half-TTL so a renewal is due.
	a.mu.Lock()
	s := a.sessions[tok]
	s.cookieIssued = time.Now().Add(-authSessionTTL)
	a.sessions[tok] = s
	a.mu.Unlock()

	u, ok, due, pin, maxAge := a.SessionUserAndRenewal(tok, true)
	if !ok || u != "admin" || !due || pin || maxAge != authSessionTTL {
		t.Fatalf("combined = %q, %v, due=%v, pin=%v, maxAge=%v; want admin, true, true, false, %v",
			u, ok, due, pin, maxAge, authSessionTTL)
	}
	// The stamp landed: an immediately-following renewal is NOT due.
	if _, ok, due, _, _ := a.SessionUserAndRenewal(tok, true); !ok || due {
		t.Fatalf("second renewal due=%v; want false (cookieIssued stamped)", due)
	}
	// renew=false must NOT stamp: age again, call with renew=false, then
	// a renew=true call must report due again.
	a.mu.Lock()
	s = a.sessions[tok]
	s.cookieIssued = time.Now().Add(-authSessionTTL)
	a.sessions[tok] = s
	a.mu.Unlock()
	if _, ok, due, _, _ := a.SessionUserAndRenewal(tok, false); !ok || due {
		t.Fatalf("renew=false: due=%v; want false", due)
	}
	if _, ok, due, _, _ := a.SessionUserAndRenewal(tok, true); !ok || !due {
		t.Fatalf("after an un-stamped age: due=%v; want true", due)
	}
}

// TestEnabledFastPathSkipsMutex: with a fresh cache, Enabled() must not
// take enabledMu — the gate calls it 3× per admin request (authGate,
// requireAuth, requireAdmin). Pre-fix every call serialized on the mutex.
func TestEnabledFastPathSkipsMutex(t *testing.T) {
	a, _ := newAuthSessionFixture(t)
	if !a.Enabled() { // populate the cache + the atomic mirror
		t.Fatal("baseline: auth must be enabled with one user")
	}
	a.enabledMu.Lock()
	defer a.enabledMu.Unlock()
	done := make(chan bool, 1)
	go func() { done <- a.Enabled() }()
	select {
	case v := <-done:
		if !v {
			t.Fatal("Enabled() = false on the fast path; want true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Enabled() took enabledMu on a fresh cache — lock-free fast path missing")
	}
}
