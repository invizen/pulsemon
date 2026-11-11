package main

import (
	"context"

	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

// authedStatus fetches /api/auth/status with the given client and returns
// the `authed` flag (false on any transport/parse failure).
func authedStatus(t *testing.T, client *http.Client, baseURL string) bool {
	t.Helper()
	resp, err := client.Get(baseURL + "/api/auth/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Authed bool `json:"authed"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatalf("status payload %q: %v", b, err)
	}
	return st.Authed
}

// TestChangePasswordRequiresCurrentPassword is the repro for the
// 2026-10-23 external review: handleAuthUserPassword accepted a new
// password from ANY valid session without verifying the current one —
// and SetUserPassword drops the user's other sessions, so a stolen
// cookie (or an unlocked browser left on the 30-day session) was a
// permanent account takeover: one request set a new password and the
// real owner's sessions were all logged out, forever.
//
// The scenario below models exactly that: the "attacker" client holds a
// legitimate second session for admin (how a stolen cookie looks to the
// server) and tries to change the password WITHOUT knowing it.
func TestChangePasswordRequiresCurrentPassword(t *testing.T) {
	_, httpSrv := adminFlagServer(t)

	ojar, _ := cookiejar.New(nil)
	owner := &http.Client{Jar: ojar}
	bootstrapAdmin(t, owner, httpSrv.URL)
	if code := postJSONStatus(t, owner, httpSrv.URL+"/api/auth/login",
		`{"username":"admin","password":"secretpw"}`); code != 200 {
		t.Fatalf("owner login: %d", code)
	}

	// The attacker: a second valid session for the SAME account.
	ajar, _ := cookiejar.New(nil)
	attacker := &http.Client{Jar: ajar}
	if code := postJSONStatus(t, attacker, httpSrv.URL+"/api/auth/login",
		`{"username":"admin","password":"secretpw"}`); code != 200 {
		t.Fatalf("attacker login: %d", code)
	}
	const pwPath = "/api/auth/users/admin/password"

	// 1. No current password at all → 400 (malformed; the pre-fix code
	//    answered 200 here — the takeover in one request).
	if code := postJSONStatus(t, attacker, httpSrv.URL+pwPath,
		`{"password":"attackerpw1"}`); code != 400 {
		t.Fatalf("missing current_password: got %d, want 400", code)
	}

	// 2. Wrong current password → 403, and nothing changed: the owner's
	//    session is still live and the old password still logs in.
	if code := postJSONStatus(t, attacker, httpSrv.URL+pwPath,
		`{"current_password":"wrongpw","password":"attackerpw1"}`); code != 403 {
		t.Fatalf("wrong current_password: got %d, want 403", code)
	}
	if !authedStatus(t, owner, httpSrv.URL) {
		t.Fatal("owner session was dropped by a REJECTED password change")
	}
	bare := &http.Client{}
	if code := postJSONStatus(t, bare, httpSrv.URL+"/api/auth/login",
		`{"username":"admin","password":"secretpw"}`); code != 200 {
		t.Fatalf("old password after rejected change: got %d, want 200", code)
	}

	// 3. The OWNER changes the password with the correct current one →
	//    200; old password dead, new one works, the caller's own session
	//    survives (keep-session contract), and the attacker's session is
	//    dropped (dropUserSessionsExcept — the normal, intended effect
	//    of a real password change).
	if code := postJSONStatus(t, owner, httpSrv.URL+pwPath,
		`{"current_password":"secretpw","password":"newpass99"}`); code != 200 {
		t.Fatalf("owner change with correct current: got %d, want 200", code)
	}
	if code := postJSONStatus(t, bare, httpSrv.URL+"/api/auth/login",
		`{"username":"admin","password":"secretpw"}`); code != 401 {
		t.Errorf("old password after change: got %d, want 401", code)
	}
	if code := postJSONStatus(t, bare, httpSrv.URL+"/api/auth/login",
		`{"username":"admin","password":"newpass99"}`); code != 200 {
		t.Errorf("new password after change: got %d, want 200", code)
	}
	if !authedStatus(t, owner, httpSrv.URL) {
		t.Error("owner's own session was dropped by its own password change")
	}
	if authedStatus(t, attacker, httpSrv.URL) {
		t.Error("attacker session survived a legitimate password change")
	}
}

// TestChangePasswordThrottled pins the companion half of the fix: the
// endpoint verifies a real password, so it must carry the login
// throttle — loginFailMax wrong-current attempts in the rolling window
// lock the IP out (429 + Retry-After), closing the online-guessing
// channel the reviewer flagged ("ideally this also runs through
// beginAttempt").
func TestChangePasswordThrottled(t *testing.T) {
	_, httpSrv := adminFlagServer(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	bootstrapAdmin(t, client, httpSrv.URL)
	if code := postJSONStatus(t, client, httpSrv.URL+"/api/auth/login",
		`{"username":"admin","password":"secretpw"}`); code != 200 {
		t.Fatalf("login: %d", code)
	}
	const pwPath = "/api/auth/users/admin/password"
	body := `{"current_password":"wrongpw","password":"newpass99"}`

	locked := 0
	for i := 0; i <= loginFailMax; i++ {
		req, err := http.NewRequest(http.MethodPost, httpSrv.URL+pwPath,
			strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			locked = resp.StatusCode
			if ra := resp.Header.Get("Retry-After"); ra == "" {
				t.Error("429 without Retry-After header")
			}
			break
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("attempt %d: got %d, want 403 (or 429 after %d)", i+1, resp.StatusCode, loginFailMax)
		}
	}
	if locked == 0 {
		t.Fatalf("no 429 after %d wrong-current attempts — the endpoint is not throttled", loginFailMax)
	}
}

// TestChangePasswordPerUsernameLockout (review 2026-11-10) pins the
// per-username layer on the password endpoint: the per-IP throttle
// (beginAttempt) can't see a session holder spraying current_password
// across many IPs — the session is a BEARER token, usable from any
// number of sources — so the account's shared failure budget (the same
// userFails/userLock maps /api/auth/login locks, finding #11) must apply
// here too. Phase A: loginFailMax wrong currents spread across 3 IPs (no
// single IP reaches its per-IP budget) lock the account — the next
// attempt from a FRESH IP is a fast 429 + Retry-After (KDF skipped), and
// a CORRECT login from a fresh IP 429s as well (shared budget). Phase B:
// a successful change CLEARS the budget.
func TestChangePasswordPerUsernameLockout(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	// Trust loopback XFF so the test can vary the SOURCE IP per request
	// (the session is a bearer token — the same cookie from many IPs,
	// exactly the attacker shape). Same trick as TestLoginThrottlePerUsername.
	srv.auth.trustedProxies = parseTrustedProxies("127.0.0.0/8")
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()
	if err := srv.auth.AddUser(context.Background(), "admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
	// The "attacker" holds a legitimate session for the account (the
	// stolen cookie) and plays it from any number of source IPs.
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	if code := postJSONStatus(t, client, httpSrv.URL+"/api/auth/login",
		`{"username":"admin","password":"secretpw"}`); code != 200 {
		t.Fatalf("login: %d", code)
	}
	pw := func(xff, current string) (int, string) {
		body := fmt.Sprintf(`{"current_password":%q,"password":"newpass99"}`, current)
		req, err := http.NewRequest(http.MethodPost, httpSrv.URL+"/api/auth/users/admin/password", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		ra := resp.Header.Get("Retry-After")
		resp.Body.Close()
		return resp.StatusCode, ra
	}

	// Phase A: 7 wrong currents across 3 IPs (3/3/1) — under every
	// per-IP budget, over the shared per-username budget.
	for i, ip := range []string{"10.1.1.10", "10.1.1.11", "10.1.1.12"} {
		for j := 0; j < []int{3, 3, 1}[i]; j++ {
			if code, _ := pw(ip, "wrongpw"); code != http.StatusForbidden {
				t.Fatalf("IP %s attempt %d: got %d, want 403 (before account lockout)", ip, j, code)
			}
		}
	}
	// Fresh IP, same session: fast 429 + Retry-After (per-username
	// lockout; the KDF was skipped, the counter untouched).
	if code, ra := pw("10.1.1.20", "wrongpw"); code != http.StatusTooManyRequests {
		t.Fatalf("fresh IP after %d cross-IP failures: got %d, want 429 (per-username lockout)", loginFailMax, code)
	} else if ra == "" {
		t.Error("429 without a Retry-After header")
	}
	// The budget is SHARED with /api/auth/login: a CORRECT login from a
	// fresh IP also 429s while the account is locked.
	bare := &http.Client{}
	lreq, err := http.NewRequest(http.MethodPost, httpSrv.URL+"/api/auth/login",
		strings.NewReader(`{"username":"admin","password":"secretpw"}`))
	if err != nil {
		t.Fatal(err)
	}
	lreq.Header.Set("X-Forwarded-For", "10.1.1.30")
	lresp, err := bare.Do(lreq)
	if err != nil {
		t.Fatal(err)
	}
	lresp.Body.Close()
	if lresp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("correct login while the account is locked: got %d, want 429 (shared per-username budget)", lresp.StatusCode)
	}

	// Phase B (fresh server): a successful change CLEARS the budget —
	// typos that eventually succeed don't accumulate.
	db2 := newTestDB(t)
	srv2 := NewServer(db2, NewProbeWorker(db2))
	srv2.auth.trustedProxies = parseTrustedProxies("127.0.0.0/8")
	httpSrv2 := httptest.NewServer(srv2.authGate())
	defer httpSrv2.Close()
	if err := srv2.auth.AddUser(context.Background(), "admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
	jar2, _ := cookiejar.New(nil)
	client2 := &http.Client{Jar: jar2}
	if code := postJSONStatus(t, client2, httpSrv2.URL+"/api/auth/login",
		`{"username":"admin","password":"secretpw"}`); code != 200 {
		t.Fatalf("login (phase B): %d", code)
	}
	pw2 := func(xff, current string) (int, string) {
		body := fmt.Sprintf(`{"current_password":%q,"password":"newpass99"}`, current)
		req, err := http.NewRequest(http.MethodPost, httpSrv2.URL+"/api/auth/users/admin/password", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		resp, err := client2.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		ra := resp.Header.Get("Retry-After")
		resp.Body.Close()
		return resp.StatusCode, ra
	}
	if code, _ := pw2("10.2.2.1", "wrongpw"); code != http.StatusForbidden {
		t.Fatalf("pre-success failure: got %d, want 403", code)
	}
	if code, _ := pw2("10.2.2.2", "secretpw"); code != http.StatusOK {
		t.Fatalf("success with correct current: got %d, want 200", code)
	}
	srv2.auth.loginThrottle.Lock()
	nf, nl := len(srv2.auth.loginThrottle.userFails), len(srv2.auth.loginThrottle.userLock)
	srv2.auth.loginThrottle.Unlock()
	if nf != 0 || nl != 0 {
		t.Fatalf("after a successful change: userFails=%d userLock=%d, want 0/0 (success must clear the account budget)", nf, nl)
	}
}

// TestChangePasswordLockout429RefundsFreshIP is the password endpoint's
// mirror of TestLoginThrottleAccountLockoutRefundsFreshIP (review
// 2026-11-11): the per-username lockout 429 runs BEFORE the KDF, so it
// must refund the per-IP admission. A session holder on a fresh IP that
// fires loginFailMax+ password changes while the account is locked must
// not trip its own per-IP lockout — those requests ran zero KDFs.
func TestChangePasswordLockout429RefundsFreshIP(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	srv.auth.trustedProxies = parseTrustedProxies("127.0.0.0/8")
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()
	if err := srv.auth.AddUser(context.Background(), "admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	if code := postJSONStatus(t, client, httpSrv.URL+"/api/auth/login",
		`{"username":"admin","password":"secretpw"}`); code != 200 {
		t.Fatalf("login: %d", code)
	}
	pw := func(xff, current, newpw string) int {
		body := fmt.Sprintf(`{"current_password":%q,"password":%q}`, current, newpw)
		req, err := http.NewRequest(http.MethodPost, httpSrv.URL+"/api/auth/users/admin/password", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	// Lock the account: 7 wrong currents spread across 3 IPs.
	for i, ip := range []string{"10.1.1.10", "10.1.1.11", "10.1.1.12"} {
		for j := 0; j < []int{3, 3, 1}[i]; j++ {
			if code := pw(ip, "wrongpw", "newpass99"); code != http.StatusForbidden {
				t.Fatalf("IP %s attempt %d: got %d, want 403 (before account lockout)", ip, j, code)
			}
		}
	}
	// Fresh IP, valid session, WHILE the account is locked: every attempt
	// fast-429s (KDF skipped) and refunds its per-IP admission.
	for j := 0; j < loginFailMax+2; j++ {
		if code := pw("10.2.2.40", "secretpw", "newpass99"); code != http.StatusTooManyRequests {
			t.Fatalf("locked-account change attempt %d from fresh IP: got %d, want 429", j, code)
		}
	}
	// Lift the account lockout: the valid change from the fresh IP must
	// go through. Pre-fix the 429-only requests had accumulated past
	// loginFailMax and beginAttempt's IP lockout answers 429 here.
	srv.auth.clearUserFail("admin")
	if code := pw("10.2.2.40", "secretpw", "newpass99"); code != http.StatusOK {
		t.Fatalf("valid change from fresh IP after lockout lifted = %d, want 200: 429-only requests burned the IP's budget", code)
	}
}
