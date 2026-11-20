package main

// Finding #20 (auth throttle & bootstrap edge cases): regression pins for
// the four edge-case fixes —
//   (a) bootstrap records the known-good exemption under the BARE IP bucket
//     (what checkUserLock looks up), not the "setup|" admission bucket
//   (b) the hard-cap wipe is per-map (an IP spray can't clear account locks)
//     — the per-map halves are pinned in auth_test.go (the three
//     TestLoginThrottle*HardCapWipe tests, rewritten for the new semantics)
//   (c) the setup refund applies only to no-KDF-cost rejections (setupNoKDF)
//   (d) RemoveUser / Disable purge the per-username throttle entries
//
// History: docs/DECISIONS.md → throttle-edge-cases

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// (a) A successful bootstrap must exempt the operator's BARE IP bucket for
// LATER logins: the account may be spray-locked in the gap between the
// bootstrap commit and the first login, and the known-good entry recorded
// at bootstrap is the operator's only exemption. Pre-fix the entry was
// stored under "setup|ip" (the admission bucket), which checkUserLock
// never looks up.
func TestBootstrapSuccessExemptsBareIP(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	// Deterministic seed: a concurrent spray locks the account the operator
	// is about to create (active per-username lockout + full rolling window).
	srv.auth.ensureThrottleMaps()
	srv.auth.loginThrottle.Lock()
	srv.auth.loginThrottle.userLock["admin"] = time.Now().Add(5 * time.Minute)
	for i := 0; i < loginFailMax; i++ {
		srv.auth.loginThrottle.userFails["admin"] = append(srv.auth.loginThrottle.userFails["admin"], time.Now())
	}
	srv.auth.loginThrottle.Unlock()

	// The operator claims the install (setup mode, fresh install).
	resp, err := http.Post(httpSrv.URL+"/api/auth/users", "application/json",
		strings.NewReader(`{"username":"admin","password":"`+"sec"+"ret"+"pw"+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap: got %d, want 200", resp.StatusCode)
	}

	// The exemption must be recorded under the BARE throttle key of the
	// client IP — exactly the key checkUserLock looks up — and NOT under
	// the "setup|" admission key.
	bare := knownGoodKey("admin", throttleKey("127.0.0.1"))
	setupSuffixed := knownGoodKey("admin", "setup|"+throttleKey("127.0.0.1"))
	srv.auth.loginThrottle.Lock()
	_, bareOK := srv.auth.loginThrottle.knownGood[bare]
	_, setupOK := srv.auth.loginThrottle.knownGood[setupSuffixed]
	srv.auth.loginThrottle.Unlock()
	if !bareOK {
		t.Fatalf("knownGood missing the bare-IP entry %q — bootstrap must exempt the operator's IP for LATER logins", bare)
	}
	if setupOK {
		t.Fatal("knownGood holds a dead \"setup|\" entry — it never matches checkUserLock")
	}

	// End-to-end: with the account still spray-locked, a login from the
	// bootstrap IP must go through the exemption (pre-fix: 429).
	resp, err = http.Post(httpSrv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"`+"sec"+"ret"+"pw"+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap-IP login during account lockout: got %d, want 200 (known-good exemption); body: %s", resp.StatusCode, body)
	}
}

// (c) The refund predicate: exactly the no-KDF-cost rejections refund.
func TestSetupNoKDFRefundPredicate(t *testing.T) {
	cases := []struct {
		err error
		ok  bool
	}{
		{context.Canceled, true},         // canceled while queued: KDF skipped
		{context.DeadlineExceeded, true}, // same, deadline flavor
		{errBootstrappedEarly, true},     // pre-check, before bcrypt
		{errUsernameInvalid, true},
		{errPasswordWeak, true},
		{errPasswordTooLong, true},
		{errPasswordCommon, true},
		{errBootstrapped, false},                  // in-tx race loss: the KDF ran
		{errUserExists, false},                    // the KDF ran
		{errors.New("database is locked"), false}, // the KDF ran
		{nil, false},
	}
	for i, c := range cases {
		if got := setupNoKDF(c.err); got != c.ok {
			t.Errorf("case %d (%v): setupNoKDF = %v, want %v", i, c.err, got, c.ok)
		}
	}
}

// (c) Handler wiring, refund direction: a client that leaves while queued
// on the bcrypt semaphore (the KDF never ran) still refunds the setup
// admission, so a disconnected bootstrap can't burn the operator's setup
// bucket.
func TestSetupCtxCancelBeforeKDFRefunds(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))

	release := fillBcryptSem()
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // client gone BEFORE the KDF starts

	req := httptest.NewRequest("POST", "/api/auth/users",
		strings.NewReader(`{"username":"admin","password":"`+"sec"+"ret"+"pw"+`"}`))
	req.RemoteAddr = "127.0.0.1:1234"
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	srv.handleAuthUsers(rr, req)

	setupKey := "setup|" + throttleKey("127.0.0.1")
	srv.auth.loginThrottle.Lock()
	n := len(srv.auth.loginThrottle.fails[setupKey])
	srv.auth.loginThrottle.Unlock()
	if n != 0 {
		t.Fatalf("setup bucket count after a pre-KDF cancel = %d, want 0 (the no-KDF rejection must be refunded)", n)
	}
}

// (d) RemoveUser must purge the per-username throttle entries: a
// re-created username must not inherit the old account's IP exemptions or
// failure debt.
func TestRemoveUserPurgesThrottle(t *testing.T) {
	a := NewAuthState(newTestDB(t))
	if err := a.AddUser(context.Background(), "admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
	if err := a.AddUser(context.Background(), "second", "secretpw"); err != nil {
		t.Fatal(err)
	}
	a.ensureThrottleMaps()
	now := time.Now()
	a.loginThrottle.userFails["admin"] = []time.Time{now}
	a.loginThrottle.userLock["admin"] = now.Add(time.Hour)
	a.loginThrottle.userHour["admin"] = &userHourBudget{start: now, count: 29}
	a.loginThrottle.knownGood[knownGoodKey("admin", "10.1.1.5")] = now
	a.loginThrottle.knownGood[knownGoodKey("second", "10.1.1.6")] = now // control

	if err := a.RemoveUser(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}

	a.loginThrottle.Lock()
	_, f := a.loginThrottle.userFails["admin"]
	_, l := a.loginThrottle.userLock["admin"]
	_, h := a.loginThrottle.userHour["admin"]
	_, g := a.loginThrottle.knownGood[knownGoodKey("admin", "10.1.1.5")]
	_, survivor := a.loginThrottle.knownGood[knownGoodKey("second", "10.1.1.6")]
	a.loginThrottle.Unlock()
	if f || l || h || g {
		t.Fatalf("RemoveUser left stale throttle entries (fails=%v lock=%v hour=%v knownGood=%v) — a re-created \"admin\" would inherit the old account's state", f, l, h, g)
	}
	if !survivor {
		t.Fatal("RemoveUser purged ANOTHER user's knownGood entry")
	}
}

// (d) Disable removes every user, so every per-username entry is stale:
// the whole per-user layer must be wiped, or a re-created account inherits
// a removed account's exemptions and failure debt.
func TestDisablePurgesAllUserThrottle(t *testing.T) {
	a := NewAuthState(newTestDB(t))
	if err := a.AddUser(context.Background(), "admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
	if err := a.AddUser(context.Background(), "second", "secretpw"); err != nil {
		t.Fatal(err)
	}
	a.ensureThrottleMaps()
	now := time.Now()
	a.loginThrottle.userFails["admin"] = []time.Time{now}
	a.loginThrottle.userLock["second"] = now.Add(time.Hour)
	a.loginThrottle.userHour["admin"] = &userHourBudget{start: now, count: 5}
	a.loginThrottle.knownGood[knownGoodKey("admin", "10.1.1.5")] = now
	a.loginThrottle.knownGood[knownGoodKey("second", "10.1.1.6")] = now

	if err := a.Disable(); err != nil {
		t.Fatal(err)
	}
	a.loginThrottle.Lock()
	n := len(a.loginThrottle.userFails) + len(a.loginThrottle.userLock) +
		len(a.loginThrottle.userHour) + len(a.loginThrottle.knownGood)
	a.loginThrottle.Unlock()
	if n != 0 {
		t.Fatalf("Disable left %d per-user throttle entries — every account is gone, so every entry is stale", n)
	}
}
