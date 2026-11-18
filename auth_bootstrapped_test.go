package main

import (
	"testing"
)

// TestAuthBootstrappedLatchesTrue proves the finding-6 fix: Bootstrapped()
// stops issuing the per-request GetSetting once it has seen "1". The flag
// (auth_bootstrapped) never goes back to false, so caching only the true
// value is safe — the latch ratchets false→true and a not-yet-latched read
// always re-queries, picking up an out-of-band CLI add on the next call.
// bootstrappedFn is a per-instance counting seam (the userCountFn pattern).
func TestAuthBootstrappedLatchesTrue(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	reads := 0
	val := ""
	a.bootstrappedFn = func() string {
		reads++
		return val
	}

	// Not bootstrapped: no latch yet, so every call re-queries.
	if a.Bootstrapped() {
		t.Fatal("Bootstrapped() = true, want false (auth_bootstrapped unset)")
	}
	if reads != 1 {
		t.Fatalf("reads = %d, want 1 (no latch yet — must query)", reads)
	}

	// The install gets its first account: the read sees "1" and latches.
	val = "1"
	if !a.Bootstrapped() {
		t.Fatal("Bootstrapped() = false, want true (auth_bootstrapped=1)")
	}
	if reads != 2 {
		t.Fatalf("reads = %d, want 2 (the latching read)", reads)
	}

	// Latched: further calls return true with NO further query.
	for i := 0; i < 5; i++ {
		if !a.Bootstrapped() {
			t.Fatalf("call %d: Bootstrapped() = false, want true (latched)", i)
		}
	}
	if reads != 2 {
		t.Fatalf("reads = %d, want 2 (latched — no further queries)", reads)
	}
}

// TestAuthBootstrappedPicksUpCLIAdd pins the one-way-ratchet safety: a fresh
// AuthState that has NOT latched (auth off, no account created in this
// process) must still observe an account created out-of-band — the CLI writes
// the setting in the DB without touching this process's memory. The latch only
// ever ratchets true, never false, so it can't mask a real bootstrap.
func TestAuthBootstrappedPicksUpCLIAdd(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)

	// Not bootstrapped in this process: queries the DB each time.
	if a.Bootstrapped() {
		t.Fatal("Bootstrapped() = true, want false (fresh install)")
	}
	// An out-of-band `pulsemon auth-user add` sets the setting in the DB.
	db.SetSetting("auth_bootstrapped", "1")
	if !a.Bootstrapped() {
		t.Fatal("Bootstrapped() = false, want true (a CLI add must be picked up — the latch never caches false)")
	}
}
