package main

// Review 2026-10-24 minor batch — auth & tags:
//   (a) setup-mode account creation paid bcrypt BEFORE losing the
//       single-shot bootstrap check, making unauthenticated setup mode an
//       unlimited bcrypt-CPU endpoint once any user exists. A cheap pre-count
//       now rejects before the hash; the authoritative in-tx check stays.
//   (b) the login throttle bucketed CGNAT/overlay space (100.64.0.0/10) by
//       /24 — collateral lockout of up to 256 individually trusted tailnet
//       peers behind one device's bad guesses. Overlay space is bucketed
//       per-IP, like RFC1918.
//   (c) DELETE /api/tags is a fleet-wide destructive rewrite (strips a tag
//       from every sensor and respawns every affected loop) but sat on the
//       session-only tier. Now admin-gated like DELETE /api/history.

import (
	"net/http"
	"net/http/cookiejar"
	"testing"
)

func TestSetupModeRejectsBeforeBcrypt(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	if err := a.AddUserMode("first", "bootstrap-pw-1", true); err != nil {
		t.Fatalf("bootstrap AddUserMode: %v", err)
	}
	// With a user present, setup mode is guaranteed to lose the in-tx
	// race — the pre-check must return the same errBootstrapped verdict
	// WITHOUT hashing, and must not add the account.
	if err := a.AddUserMode("second", "another-pw-2", true); err != errBootstrapped {
		t.Fatalf("setup-mode with existing user: err = %v, want errBootstrapped", err)
	}
	if n, err := a.db.UserCount(); err != nil || n != 1 {
		t.Fatalf("user count = %d (err %v), want 1 — loser must not be created", n, err)
	}
	// Non-setup path unaffected: a normal admin add still works.
	if err := a.AddUserMode("helper", "helper-pw-3", false); err != nil {
		t.Fatalf("non-setup AddUserMode: %v", err)
	}
}

func TestThrottleKeyBuckets(t *testing.T) {
	cases := []struct {
		in, want string
		why      string
	}{
		{"100.64.5.6", "100.64.5.6", "CGNAT/overlay is per-IP, not /24"},
		{"100.127.255.9", "100.127.255.9", "top of 100.64.0.0/10 still per-IP"},
		{"100.128.0.1", "100.128.0.0", "just above /10 returns to /24 bucketing"},
		{"192.168.1.5", "192.168.1.5", "RFC1918 per-IP (unchanged)"},
		{"8.8.8.8", "8.8.8.0", "public /24 (unchanged)"},
		{"203.0.113.77", "203.0.113.0", "public /24 (unchanged)"},
	}
	for _, c := range cases {
		if got := throttleKey(c.in); got != c.want {
			t.Errorf("throttleKey(%s) = %s, want %s (%s)", c.in, got, c.want, c.why)
		}
	}
}

func TestNonAdminCannotDeleteTags(t *testing.T) {
	_, httpSrv := adminFlagServer(t)

	jar, _ := cookiejar.New(nil)
	admin := &http.Client{Jar: jar}
	bootstrapAdmin(t, admin, httpSrv.URL)
	if code := postJSONStatus(t, admin, httpSrv.URL+"/api/auth/login",
		`{"username":"admin","password":"secretpw"}`); code != 200 {
		t.Fatalf("admin login: %d", code)
	}
	if code := postJSONStatus(t, admin, httpSrv.URL+"/api/auth/users",
		`{"username":"helper","password":"helperpw1"}`); code != 200 {
		t.Fatalf("admin add helper: %d", code)
	}
	hjar, _ := cookiejar.New(nil)
	helper := &http.Client{Jar: hjar}
	if code := postJSONStatus(t, helper, httpSrv.URL+"/api/auth/login",
		`{"username":"helper","password":"helperpw1"}`); code != 200 {
		t.Fatalf("helper login: %d", code)
	}

	if code := requestStatus(t, helper, http.MethodDelete, httpSrv.URL+"/api/tags?tag=alerting", ""); code != http.StatusForbidden {
		t.Fatalf("non-admin DELETE /api/tags: code = %d, want 403", code)
	}
	// Admin still reaches the handler (unknown tag is a benign no-op).
	if code := requestStatus(t, admin, http.MethodDelete, httpSrv.URL+"/api/tags?tag=alerting", ""); code != http.StatusOK {
		t.Fatalf("admin DELETE /api/tags: code = %d, want 200", code)
	}
}
