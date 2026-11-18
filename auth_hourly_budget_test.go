package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRecordUserFailHourlyBudgetLocks pins the core of the paced-login fix:
// an attacker who stays UNDER the 60s rolling threshold (7/60s) is still
// capped by the hourly budget. 29 fails spread over the past 50 min (rolling
// window empty — all pruned) + 1 more = the 30th in the hour → a 1-hour
// lockout, not the 5-min rolling one.
func TestRecordUserFailHourlyBudgetLocks(t *testing.T) {
	a := NewAuthState(newTestDB(t))
	a.ensureThrottleMaps()

	// Simulate 29 paced fails over the last 50 min: the rolling window is
	// empty (every entry is outside the 60s cutoff and gets pruned), the
	// hourly budget sits at 29.
	a.loginThrottle.userHour["admin"] = &userHourBudget{
		start: time.Now().Add(-50 * time.Minute),
		count: 29,
	}

	// One more fail: rolling stays at 1 (no 7/60s trip), hourly hits 30.
	a.recordUserFail("admin")

	a.loginThrottle.Lock()
	until, locked := a.loginThrottle.userLock["admin"]
	a.loginThrottle.Unlock()
	if !locked {
		t.Fatal("account not locked after the 30th fail in the hour")
	}
	if rem := until.Sub(time.Now()); rem < 50*time.Minute || rem > time.Hour {
		t.Fatalf("lockout remaining = %v, want ~1h (the hourly lockout, not the 5-min rolling)", rem)
	}
}

// TestHourlyBudgetPersistsAcrossRollingLockout is the discriminating pin for
// the burst-attack vector the finding describes: 7-fail bursts every 6 min
// (~70/hr). The hourly budget must SURVIVE the rolling lockout expiry
// (checkUserLock wipes userFails, not userHour), so a burst + 23 paced fails
// reaches the 30/hr cap and locks for an hour.
func TestHourlyBudgetPersistsAcrossRollingLockout(t *testing.T) {
	a := NewAuthState(newTestDB(t))
	a.ensureThrottleMaps()

	// Burst 1: 7 fails in the window → the 5-min ROLLING lockout (hourly is
	// only at 7, under the cap).
	for i := 0; i < 7; i++ {
		a.recordUserFail("admin")
	}
	a.loginThrottle.Lock()
	firstUntil := a.loginThrottle.userLock["admin"]
	b := a.loginThrottle.userHour["admin"]
	a.loginThrottle.Unlock()
	if b == nil || b.count != 7 {
		t.Fatalf("hourly budget after burst 1 = %+v, want count 7", b)
	}
	if rem := firstUntil.Sub(time.Now()); rem < 4*time.Minute || rem > 5*time.Minute {
		t.Fatalf("first lockout = %v, want ~5min (rolling; hourly is under the cap)", rem)
	}

	// The rolling lockout expires: checkUserLock wipes userFails but NOT
	// userHour, so the hourly budget must survive.
	a.loginThrottle.Lock()
	a.loginThrottle.userLock["admin"] = time.Now().Add(-time.Minute)
	a.loginThrottle.Unlock()
	if ok, _ := a.checkUserLock("admin", ""); !ok {
		t.Fatal("expected the elapsed rolling lockout to lift")
	}
	a.loginThrottle.Lock()
	b = a.loginThrottle.userHour["admin"]
	a.loginThrottle.Unlock()
	if b == nil || b.count != 7 {
		t.Fatalf("hourly budget after rolling-lockout expiry = %+v, want count 7 (must persist)", b)
	}

	// 23 more fails, each in a FRESH 60s window (rolling never re-trips) →
	// the hourly budget climbs 8..30 and the account locks for an hour.
	for i := 0; i < 23; i++ {
		a.loginThrottle.Lock()
		delete(a.loginThrottle.userFails, "admin") // fresh 60s window
		a.loginThrottle.Unlock()
		a.recordUserFail("admin")
	}
	a.loginThrottle.Lock()
	until, locked := a.loginThrottle.userLock["admin"]
	b = a.loginThrottle.userHour["admin"]
	a.loginThrottle.Unlock()
	if !locked {
		t.Fatal("account not locked after burst-1 + 23 paced fails")
	}
	if b.count != 30 {
		t.Fatalf("hourly budget = %d, want 30", b.count)
	}
	if rem := until.Sub(time.Now()); rem < 50*time.Minute {
		t.Fatalf("lockout remaining = %v, want ~1h (hourly), not the 5-min rolling", rem)
	}
}

// TestHourlyBudgetSelfResetsAfterWindow pins the >= (not >) re-anchor: a
// budget from 70 minutes ago (count 30) is reset to 1 on the next fail — it
// does NOT immediately re-lock the account the moment a 1h lockout lifts.
func TestHourlyBudgetSelfResetsAfterWindow(t *testing.T) {
	a := NewAuthState(newTestDB(t))
	a.ensureThrottleMaps()

	// A budget from 70 min ago with the cap reached (the window has elapsed).
	a.loginThrottle.userHour["admin"] = &userHourBudget{
		start: time.Now().Add(-70 * time.Minute),
		count: 30,
	}
	a.recordUserFail("admin")

	a.loginThrottle.Lock()
	b := a.loginThrottle.userHour["admin"]
	_, locked := a.loginThrottle.userLock["admin"]
	a.loginThrottle.Unlock()
	if locked {
		t.Fatal("account locked after a fresh window — the elapsed budget must self-reset")
	}
	if b.count != 1 {
		t.Fatalf("hourly budget after window reset = %d, want 1", b.count)
	}
}

// TestClearUserFailClearsHourlyBudget pins that a successful login resets the
// account's slow budget too (not just the rolling window).
func TestClearUserFailClearsHourlyBudget(t *testing.T) {
	a := NewAuthState(newTestDB(t))
	a.ensureThrottleMaps()

	a.recordUserFail("admin")
	a.loginThrottle.Lock()
	_, had := a.loginThrottle.userHour["admin"]
	a.loginThrottle.Unlock()
	if !had {
		t.Fatal("hourly budget missing after a fail")
	}

	a.clearUserFail("admin") // a successful login
	a.loginThrottle.Lock()
	_, still := a.loginThrottle.userHour["admin"]
	a.loginThrottle.Unlock()
	if still {
		t.Fatal("hourly budget survived clearUserFail (a success must reset the account budget)")
	}
}

// TestKnownGoodExemptFromHourlyLock pins the finding's operator-safety claim:
// the known-good (account, IP) pair is exempt from the WHOLE per-username
// layer, including the new hourly lockout, while a new IP stays hard-locked.
func TestKnownGoodExemptFromHourlyLock(t *testing.T) {
	a := NewAuthState(newTestDB(t))
	a.ensureThrottleMaps()

	// An active hourly lockout.
	a.loginThrottle.userLock["admin"] = time.Now().Add(time.Hour)
	// The operator's known-good (admin, 10.1.1.5) pair.
	a.loginThrottle.knownGood[knownGoodKey("admin", "10.1.1.5")] = time.Now()

	if ok, _ := a.checkUserLock("admin", "10.1.1.5"); !ok {
		t.Fatal("known-good IP should be exempt from the hourly lockout")
	}
	if ok, _ := a.checkUserLock("admin", "10.9.9.9"); ok {
		t.Fatal("a new IP should be locked by the hourly budget")
	}
}

// TestAddUserRejectsCommonPassword pins the creation-time deterrent: a
// common password is refused with errPasswordCommon and no account is created.
func TestAddUserRejectsCommonPassword(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)

	if err := a.AddUser(context.Background(), "admin", "password123"); !errors.Is(err, errPasswordCommon) {
		t.Fatalf("AddUser with a common password = %v, want errPasswordCommon", err)
	}
	if n, _ := db.UserCount(); n != 0 {
		t.Fatalf("user count = %d after a rejected common password, want 0", n)
	}
}

// TestAddUserAcceptsUncommonPassword pins that the blocklist is a deterrent,
// not a wall: a password outside the list is accepted.
func TestAddUserAcceptsUncommonPassword(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)

	if err := a.AddUser(context.Background(), "admin", "correct-horse-battery"); err != nil {
		t.Fatalf("AddUser with an uncommon password = %v, want nil", err)
	}
}

// TestIsCommonPasswordCaseInsensitive pins the case-insensitive lookup.
func TestIsCommonPasswordCaseInsensitive(t *testing.T) {
	if !isCommonPassword("PASSWORD") {
		t.Error("isCommonPassword(uppercase) = false, want true")
	}
	if !isCommonPassword("QwErTy123") {
		t.Error("isCommonPassword(mixed-case qwerty123) = false, want true")
	}
	if isCommonPassword("notacommonpassword") {
		t.Error("isCommonPassword(uncommon) = true, want false")
	}
}

// TestSetupRejectsCommonPassword pins the API contract: a setup-mode (first
// account) POST with a common password is a 400, not a 500, and no account
// is created.
func TestSetupRejectsCommonPassword(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))

	body := `{"username":"admin","password": "***"}`
	req := httptest.NewRequest("POST", "/api/auth/users", strings.NewReader(body))
	req.RemoteAddr = "10.1.1.1"
	rr := httptest.NewRecorder()
	srv.handleAuthUsers(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("setup with a common password: got %d, want 400", rr.Code)
	}
	if n, _ := db.UserCount(); n != 0 {
		t.Fatalf("user count = %d after a rejected common password, want 0", n)
	}
}
