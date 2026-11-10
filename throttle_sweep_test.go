package main

// Login-throttle + session-map sweeps are rate-limited (a spray must not pay
// an O(n) walk per login) and the throttle map carries a hard memory cap.

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestThrottleSweepRateLimited(t *testing.T) {
	a := NewAuthState(newTestDB(t))
	now := time.Now()
	stale := now.Add(-2 * loginFailWindow)

	seed := func() {
		a.loginThrottle.Lock()
		a.ensureThrottleMaps()
		for i := 0; i < throttleSweepThreshold+50; i++ {
			a.loginThrottle.fails[fmt.Sprintf("10.%d.%d.%d", (i/65536)%256, (i/256)%256, i%256)] = []time.Time{now}
		}
		a.loginThrottle.fails["9.9.9.9"] = []time.Time{stale}
		a.loginThrottle.Unlock()
	}
	hasStale := func() bool {
		a.loginThrottle.Lock()
		defer a.loginThrottle.Unlock()
		_, ok := a.loginThrottle.fails["9.9.9.9"]
		return ok
	}

	seed()
	a.beginAttempt("1.1.1.1") // first past-threshold call: sweeps
	if hasStale() {
		t.Fatal("first past-threshold attempt should sweep stale entries")
	}
	// Re-seed the stale entry; the next attempt is inside the sweep
	// interval, so the sweep must NOT run (this is the O(n^2) fix).
	a.loginThrottle.Lock()
	a.loginThrottle.fails["9.9.9.9"] = []time.Time{stale}
	a.loginThrottle.Unlock()
	a.beginAttempt("1.1.1.2")
	if !hasStale() {
		t.Fatal("sweep ran again inside the rate-limit window")
	}
	// Force the window open: sweep resumes.
	a.loginThrottle.Lock()
	a.loginThrottle.nextSweep = time.Time{}
	a.loginThrottle.Unlock()
	a.beginAttempt("1.1.1.3")
	if hasStale() {
		t.Fatal("sweep did not run once the interval elapsed")
	}
}

func TestThrottleHardCapResets(t *testing.T) {
	origCap, origThresh := throttleHardCap, throttleSweepThreshold
	defer func() { throttleHardCap, throttleSweepThreshold = origCap, origThresh }()
	throttleSweepThreshold = 10 // sweep gate must open for the cap branch to run
	throttleHardCap = 15
	a := NewAuthState(newTestDB(t))
	now := time.Now()
	a.loginThrottle.Lock()
	a.ensureThrottleMaps()
	for i := 0; i < 20; i++ { // all in-window: the sweep cannot prune
		a.loginThrottle.fails[fmt.Sprintf("10.0.0.%d", i)] = []time.Time{now}
	}
	a.loginThrottle.lockout["10.0.0.3"] = now.Add(loginLockout)
	a.loginThrottle.Unlock()

	if ok, _ := a.beginAttempt("1.2.3.4"); !ok {
		t.Fatal("fresh IP must be allowed")
	}
	a.loginThrottle.Lock()
	n := len(a.loginThrottle.fails)
	l := len(a.loginThrottle.lockout)
	a.loginThrottle.Unlock()
	if n > 20 { // one entry re-added for 1.2.3.4
		t.Fatalf("hard cap did not reset the spray map: %d entries", n)
	}
	if l > 1 {
		t.Fatalf("hard cap did not clear the lockout map: %d entries", l)
	}
}

func TestSessionSweepRateLimited(t *testing.T) {
	a := NewAuthState(newTestDB(t))
	if err := a.AddUserMode(context.Background(), "admin", "secretpw", true); err != nil {
		t.Fatal(err)
	}
	// Isolate from the per-user session cap: this test seeds 68 same-user
	// sessions (all created:now) to exercise the sweep rate-limit. The cap
	// (default 32) would evict one on each CreateSession below, and with all
	// created times equal it could evict "expired2" — flaking the assertion.
	origCap := maxSessionsPerUser
	maxSessionsPerUser = 1000
	t.Cleanup(func() { maxSessionsPerUser = origCap })
	now := time.Now()
	a.mu.Lock()
	for i := 0; i < 68; i++ {
		a.sessions[fmt.Sprintf("tok%03d", i)] = authSession{user: "admin", expiry: now.Add(time.Hour), created: now, cookieIssued: now}
	}
	a.sessions["expired"] = authSession{user: "admin", expiry: now.Add(-time.Minute), created: now, cookieIssued: now}
	a.mu.Unlock()

	if _, ok := a.CreateSession(context.Background(), "admin", "secretpw", false); !ok {
		t.Fatal("CreateSession failed")
	}
	a.mu.Lock()
	_, gone := a.sessions["expired"]
	a.mu.Unlock()
	if gone {
		t.Fatal("first past-threshold CreateSession should sweep the expired session")
	}

	a.mu.Lock()
	a.sessions["expired2"] = authSession{user: "admin", expiry: now.Add(-time.Minute), created: now, cookieIssued: now}
	a.mu.Unlock()
	if _, ok := a.CreateSession(context.Background(), "admin", "secretpw", false); !ok {
		t.Fatal("CreateSession failed")
	}
	a.mu.Lock()
	_, still := a.sessions["expired2"]
	a.mu.Unlock()
	if !still {
		t.Fatal("session sweep ran inside the rate-limit window")
	}
}
