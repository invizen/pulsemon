package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// boundClient returns an http.Client whose connections bind a specific
// loopback source address: on Linux the whole 127.0.0.0/8 is loopback, so
// 127.0.0.2/127.0.0.3/... give distinct per-IP throttle buckets
// (throttleKey maps loopback to /32) against ONE test server listening on
// 127.0.0.1 — the multi-IP shape the per-username layer exists for.
func boundClient(t *testing.T, src string) *http.Client {
	t.Helper()
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 10 * time.Second}
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return d.DialContext(ctx, network, addr)
			},
		},
		Timeout: 60 * time.Second,
	}
}

func postLoginStatus(t *testing.T, c *http.Client, base, user, pw string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": user, "password": pw})
	resp, err := c.Post(base+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/auth/login (%s): %v", user, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestUnknownUsernameLocksLikeKnown pins MINOR-22: the per-username
// failure budget must count unknown names exactly like known ones. Pre-
// fix recordUserFail was gated on s.auth.userExists(userKey), so a
// multi-IP spray of an EXISTING name tripped the per-username lockout
// (request #8 → 429 in <1ms) while the same spray of a phantom name never
// did (request #8 → 401 after bcrypt + loginSlowDown) — a deterministic
// username-enumeration oracle, exactly the leak the dummy-hash equalizer
// and loginSlowDown exist to close.
func TestUnknownUsernameLocksLikeKnown(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	if err := a.AddUserMode(context.Background(), "admin", "pw-enum-test", true); err != nil {
		t.Fatalf("AddUserMode: %v", err)
	}
	srv := NewServer(db, NewProbeWorker(db))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(srv.authGate())
	ts.Listener = ln
	ts.Start()
	defer ts.Close()

	c1 := boundClient(t, "127.0.0.1")
	c2 := boundClient(t, "127.0.0.2")
	c3 := boundClient(t, "127.0.0.3")
	c4 := boundClient(t, "127.0.0.4")

	// Known name: loginFailMax failures from IP 1 fill the per-username
	// budget (and its own per-IP bucket); request #(max+1) from a FRESH IP
	// 2 must 429 on the per-username lockout.
	for i := 0; i < loginFailMax; i++ {
		if code := postLoginStatus(t, c1, ts.URL, "admin", "wrong-pw"); code != http.StatusUnauthorized {
			t.Fatalf("admin fail #%d: %d, want 401", i+1, code)
		}
	}
	if code := postLoginStatus(t, c2, ts.URL, "admin", "wrong-pw"); code != http.StatusTooManyRequests {
		t.Fatalf("admin request %d from a fresh IP: %d, want 429 (per-username lockout)", loginFailMax+1, code)
	}

	// The oracle itself: the identical shape against a name with NO
	// account must land on the same 429 — pre-fix this was a 401 after
	// the KDF, and the 429/401 split named the account.
	for i := 0; i < loginFailMax; i++ {
		if code := postLoginStatus(t, c3, ts.URL, "ghost-user", "wrong-pw"); code != http.StatusUnauthorized {
			t.Fatalf("ghost fail #%d: %d, want 401", i+1, code)
		}
	}
	start := time.Now()
	code := postLoginStatus(t, c4, ts.URL, "ghost-user", "wrong-pw")
	fast := time.Since(start) < loginSlowDown
	if code != http.StatusTooManyRequests {
		t.Fatalf("ghost request %d from a fresh IP: %d, want 429 — unknown names must lock identically to known ones (pre-fix this 401'd: the enumeration oracle)", loginFailMax+1, code)
	}
	if !fast {
		t.Fatalf("ghost 429 took %v (>= loginSlowDown %v) — the per-username lockout did not short-circuit the KDF", time.Since(start), loginSlowDown)
	}
}

// TestUserHourSweptForStaleNames pins the userHour half of MINOR-22's
// fix: now that unknown (attacker-chosen) names are counted, the hourly
// budget map must be swept with userFails — pre-fix it had "no sweep of
// its own" and was bounded only by the account count, so a name-rotation
// spray grew it without bound.
func TestUserHourSweptForStaleNames(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	a.loginThrottle.Lock()
	defer a.loginThrottle.Unlock()
	a.ensureThrottleMaps()
	now := time.Now()
	// Stale name: hourly budget, no in-window failures, no lockout.
	a.loginThrottle.userHour["ghost"] = &userHourBudget{start: now.Add(-2 * time.Hour), count: 30}
	// Active-lockout account: the budget must SURVIVE the sweep (the
	// persist-across-rolling-lockouts contract).
	a.loginThrottle.userFails["admin"] = []time.Time{now}
	a.loginThrottle.userLock["admin"] = now.Add(time.Minute)
	a.loginThrottle.userHour["admin"] = &userHourBudget{start: now, count: 5}

	a.sweepThrottle(now)

	if _, ok := a.loginThrottle.userHour["ghost"]; ok {
		t.Fatal("stale unknown name kept its userHour entry — unbounded growth is back")
	}
	if _, ok := a.loginThrottle.userHour["admin"]; !ok {
		t.Fatal("active-lockout account lost its userHour budget — the persist-across-lockouts contract is broken")
	}
	if _, ok := a.loginThrottle.userFails["admin"]; !ok {
		t.Fatal("active-lockout account lost its userFails — the sweep rule changed")
	}
}

// TestThrottleHardCapWipesUserHour pins the cap side of MINOR-22: the
// per-username hard-cap wipe (the spray backstop) must drop userHour with
// userFails/userLock — pre-fix the cap "never wiped userHour here", so a
// name-rotation spray that tripped the cap left every sprayed name's
// hourly budget behind.
func TestThrottleHardCapWipesUserHour(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	oldSweep, oldCap := throttleSweepThreshold, throttleHardCap
	throttleSweepThreshold, throttleHardCap = 1, 1
	defer func() { throttleSweepThreshold, throttleHardCap = oldSweep, oldCap }()

	now := time.Now()
	a.loginThrottle.Lock()
	a.ensureThrottleMaps()
	a.loginThrottle.nextSweep = time.Time{} // let the opportunistic GC run
	a.loginThrottle.userFails["n1"] = []time.Time{now}
	a.loginThrottle.userFails["n2"] = []time.Time{now}
	a.loginThrottle.userHour["n1"] = &userHourBudget{start: now, count: 1}
	a.loginThrottle.userHour["n2"] = &userHourBudget{start: now, count: 1}
	a.loginThrottle.Unlock()

	if ok, _ := a.beginAttempt("10.0.0.1"); !ok {
		t.Fatal("beginAttempt refused on a fresh bucket")
	}

	a.loginThrottle.Lock()
	defer a.loginThrottle.Unlock()
	if len(a.loginThrottle.userFails) != 0 {
		t.Fatalf("userFails after cap wipe: %d entries, want 0", len(a.loginThrottle.userFails))
	}
	if len(a.loginThrottle.userHour) != 0 {
		t.Fatalf("userHour after cap wipe: %d entries, want 0 — the cap no longer wipes the hourly budget", len(a.loginThrottle.userHour))
	}
}
