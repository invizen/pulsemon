package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
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
