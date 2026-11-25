package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// --- AuthState-level pins (the cache invariant) ---

// TestBootstrappedLatchRefreshesEnabledCache proves the torn-read fix at the
// source: the first in-process latch of Bootstrapped() must refresh the
// Enabled() cache. An out-of-band CLI first-user add commits the user row
// and auth_bootstrapped='1' together; without the refresh, a stale
// Enabled()=='false' (enabledTTL = 2s) plus a live Bootstrapped()=='true'
// reads as "operator disabled auth", and the gate AND the requireAuth /
// requireAdmin handler guards (which stand down on Enabled()==false) would
// open the dashboard to any LAN host for up to 2s — at the exact moment
// authentication is being enabled.
func TestBootstrappedLatchRefreshesEnabledCache(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	n := 0
	counts := 0
	a.userCountFn = func() (int, error) { counts++; return n, nil }
	a.bootstrappedFn = func() string { return "1" }

	if a.Enabled() {
		t.Fatal("Enabled() = true on a fresh install, want false (this primes the stale cache)")
	}
	if counts != 1 {
		t.Fatalf("counts = %d, want 1 (the priming read)", counts)
	}
	// The CLI add commits: user row and flag land in the same transaction.
	n = 1
	if !a.Bootstrapped() {
		t.Fatal("Bootstrapped() = false, want true (auth_bootstrapped=1)")
	}
	if counts != 2 {
		t.Fatalf("counts = %d, want 2 (the latching read must refresh the Enabled() cache — the torn pair must not survive)", counts)
	}
	if !a.Enabled() {
		t.Fatal("Enabled() = false right after the latch with a user present, want true — the torn pair (Enabled=false, Bootstrapped=true) would read as 'auth off' and open the dashboard")
	}
}

// TestBootstrappedLatchRefreshesExactlyOnce pins the Swap guard: the
// refresh fires on the FIRST latch only. A per-call refresh would put a
// COUNT(*) on every request once the flag is latched — and the latch
// ratchets true and never moves, so one refresh is all the state change
// there is.
func TestBootstrappedLatchRefreshesExactlyOnce(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	n := 0
	counts := 0
	a.userCountFn = func() (int, error) { counts++; return n, nil }
	a.bootstrappedFn = func() string { return "1" }
	a.Enabled() // prime
	n = 1
	if !a.Bootstrapped() {
		t.Fatal("Bootstrapped() = false, want true (the latch)")
	}
	want := counts
	for i := 0; i < 5; i++ {
		if !a.Bootstrapped() {
			t.Fatalf("call %d: Bootstrapped() = false, want true (latched)", i)
		}
	}
	if counts != want {
		t.Fatalf("counts = %d, want %d (no refresh after the latch — no per-request COUNT in the latched state)", counts, want)
	}
}

// TestEnabledNowBypassesTheTTL proves the force refresh the gate relies on:
// EnabledNow() re-reads the count even inside the TTL window, while
// Enabled() keeps serving the cached value (the 5s dashboard poll must not
// pay a COUNT per request).
func TestEnabledNowBypassesTheTTL(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	n := 0
	a.userCountFn = func() (int, error) { return n, nil }
	if a.Enabled() {
		t.Fatal("Enabled() = true on a fresh install, want false")
	}
	n = 1 // out-of-band add
	if a.Enabled() {
		t.Fatal("Enabled() = true within the TTL — the cache must hold")
	}
	if !a.EnabledNow() {
		t.Fatal("EnabledNow() = false, want true (the force refresh must bypass the TTL)")
	}
}

// --- Gate-level pins (the 2s window, end to end) ---

// newTornWindowServer builds the exact torn state: the Enabled() cache holds
// a stale 'false' (primed with zero users, still inside enabledTTL), the
// bootstrapped flag is set, and a FRESH user count returns 1 — the moment an
// out-of-band `pulsemon auth-user add` has committed but the 2s TTL has not
// expired.
func newTornWindowServer(t *testing.T) *Server {
	t.Helper()
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	// The CLI commit: flag and user row land together, out-of-band.
	if err := db.SetSetting("auth_bootstrapped", "1"); err != nil {
		t.Fatal(err)
	}
	srv.auth.Enabled() // prime: zero users → stale 'false' in the cache
	// The user row is now in the DB; the cache does not know it.
	srv.auth.userCountFn = func() (int, error) { return 1, nil }
	return srv
}

// TestGateTornWindowIsNotOpen is the load-bearing pin: in the torn state a
// sessionless request for a data endpoint must be refused (401), not served
// open. Pre-fix the gate read (Enabled=false, Bootstrapped=true) as "auth
// off = fully open" and forwarded to s.mux, where requireAuth/requireAdmin
// also stood down on the same stale cache — full admin access (sensor CRUD,
// settings, TLS upload, history wipes) for up to 2s at the moment auth is
// enabled.
func TestGateTornWindowIsNotOpen(t *testing.T) {
	srv := newTornWindowServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/sensors", nil)
	req.Host = "10.99.99.5:9299"
	rr := httptest.NewRecorder()
	srv.authGate().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("torn-window read: %d, want 401 (the 2s unauthenticated admin window must not exist)", rr.Code)
	}
}

// newTornReEnableServer builds the TORN RE-ENABLE state — the scenario the
// gate guard alone must close: an older install that already had an account
// (flag set) whose users were later deleted (auth off), where the latch
// fired at BOOT with zero users. The operator then re-adds a user via CLI.
// The latch is already true, so Bootstrapped() does NOT refresh on this
// read (the Swap guard fires once, at boot) — the only defense against the
// stale Enabled()=='false' is the gate's fresh-count guard.
func newTornReEnableServer(t *testing.T) *Server {
	t.Helper()
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	// Older install: the flag was set long ago; the users were deleted
	// (auth off). The latch fires at "boot" with zero users.
	if err := db.SetSetting("auth_bootstrapped", "1"); err != nil {
		t.Fatal(err)
	}
	srv.auth.Bootstrapped() // latch: refresh runs once, sees 0 users
	srv.auth.Enabled()      // stale 'false' in the cache
	// The operator re-adds a user via CLI (out-of-band).
	srv.auth.userCountFn = func() (int, error) { return 1, nil }
	return srv
}

// TestGateTornReEnableIsNotOpen pins the re-enable variant end to end: with
// the latch already latched, a sessionless data read in the 2s window after
// a CLI re-add must be 401. Pre-fix (and without the gate guard) the open
// branch forwards to s.mux and requireAuth stands down on the same stale
// cache — the dashboard is wide open to any LAN host for up to 2s.
func TestGateTornReEnableIsNotOpen(t *testing.T) {
	srv := newTornReEnableServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/sensors", nil)
	req.Host = "10.99.99.5:9299"
	rr := httptest.NewRecorder()
	srv.authGate().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("torn re-enable read: %d, want 401 (the gate guard is the only defense here — the latch already fired at boot)", rr.Code)
	}
}

// TestGateRealAuthOffStaysOpen is the control: a GENUINE "operator disabled
// auth" state (zero users, flag set, and a fresh count of zero) must remain
// fully open — the torn-read guard must not lock a trusted-LAN install that
// chose auth off. (auth_off_rebinding_test.go pins the same branch with an
// allowlist; this pins the no-allowlist default through the new guard.)
func TestGateRealAuthOffStaysOpen(t *testing.T) {
	srv := newAuthOffServer(t) // zero users + flag, no seams
	req := httptest.NewRequest(http.MethodGet, "/api/sensors", nil)
	req.Host = "10.99.99.5:9299"
	rr := httptest.NewRecorder()
	srv.authGate().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("real auth-off read: %d, want 200 (documented 'auth off = fully open' — the guard must not over-fire)", rr.Code)
	}
}
