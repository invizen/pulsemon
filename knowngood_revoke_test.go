package main

// MAJOR-13 pins: the knownGood (30-day) exemption must not let a
// bucket-sharer (NAT / Docker bridge / VPN gateway collapses clients into
// one throttleKey bucket) pace the per-IP 7/60s cap — 6 guesses / 61s ≈
// 8,500 guesses/day — past the account's 30/hr budget. knownGood is
// revoked after knownGoodRevokeFails failed checks from the bucket
// itself. History: docs/DECISIONS.md → knowngood-revoke-on-bucket-fails.

import "testing"
import "time"

// lockAccountFromBurns the account's hourly budget from a NON-exempt
// bucket so the difference between "exempt" and "not exempt" is observable
// through checkUserLock.
func lockAccountFromBurns(t *testing.T, a *AuthState, user, bucket string) {
	t.Helper()
	for i := 0; i < loginHourFailMax; i++ {
		a.recordUserFail(user, bucket)
	}
	a.loginThrottle.Lock()
	_, locked := a.loginThrottle.userLock[user]
	a.loginThrottle.Unlock()
	if !locked {
		t.Fatalf("setup: account not locked after %d fails from %s", loginHourFailMax, bucket)
	}
}

// TestKnownGoodRevokedAfterBucketFails: the core security property. With
// the account locked (burned from another bucket), an exempt bucket passes
// — and after knownGoodRevokeFails failed checks from THAT bucket, the
// exemption is gone and the bucket sees the account lockout like any other
// attacker. Pre-fix the exemption ran the full knownGoodTTL (30 days) no
// matter how many failures the bucket itself produced.
func TestKnownGoodRevokedAfterBucketFails(t *testing.T) {
	a := NewAuthState(newTestDB(t))
	a.ensureThrottleMaps()

	// The operator's known-good pair (admin, 10.1.1.5).
	a.loginSuccess("admin", "10.1.1.5")
	// The account budget is burned by an attacker in ANOTHER bucket.
	lockAccountFromBurns(t, a, "admin", "10.2.2.2")

	// While the exemption is active, the exempt bucket passes despite the
	// account lockout; a fresh bucket is locked.
	if ok, _ := a.checkUserLock("admin", "10.1.1.5"); !ok {
		t.Fatal("exempt bucket must pass while knownGood is active")
	}
	if ok, _ := a.checkUserLock("admin", "10.2.2.2"); ok {
		t.Fatal("non-exempt bucket must be locked by the account budget")
	}
	// knownGoodRevokeFails failed checks from the exempt bucket itself →
	// the exemption is revoked.
	for i := 0; i < knownGoodRevokeFails; i++ {
		a.recordUserFail("admin", "10.1.1.5")
	}
	if ok, _ := a.checkUserLock("admin", "10.1.1.5"); ok {
		t.Fatal("bucket must lose the knownGood exemption after N fails of its own")
	}
}

// TestKnownGoodReMintResetsFailCount: the revocation count is "since
// mint" — a successful login (re-mint) resets it, so an operator who typos
// N-1 times, logs in, and typos N-1 more times keeps the exemption.
func TestKnownGoodReMintResetsFailCount(t *testing.T) {
	a := NewAuthState(newTestDB(t))
	a.ensureThrottleMaps()

	a.loginSuccess("admin", "10.1.1.5")
	for i := 0; i < knownGoodRevokeFails-1; i++ {
		a.recordUserFail("admin", "10.1.1.5")
	}
	// Operator logs in again: the exemption re-mints, the count resets.
	a.loginSuccess("admin", "10.1.1.5")
	for i := 0; i < knownGoodRevokeFails-1; i++ {
		a.recordUserFail("admin", "10.1.1.5")
	}
	a.loginThrottle.Lock()
	_, exempt := a.loginThrottle.knownGood[knownGoodKey("admin", "10.1.1.5")]
	count := a.loginThrottle.knownGoodFails[knownGoodKey("admin", "10.1.1.5")]
	a.loginThrottle.Unlock()
	if !exempt {
		t.Fatal("re-mint must reset the revocation count — the exemption is gone")
	}
	if count != knownGoodRevokeFails-1 {
		t.Fatalf("revocation count = %d, want %d (reset by the re-mint)", count, knownGoodRevokeFails-1)
	}
}

// TestKnownGoodRevocationScopedToPair: revoking (admin, bucketA) must not
// touch (admin, bucketB) — the exemption is keyed per pair, and a blanket
// per-user revoke would drop the operator's exemption in every other bucket
// (VPN home + office) on one bad stretch in one of them.
func TestKnownGoodRevocationScopedToPair(t *testing.T) {
	a := NewAuthState(newTestDB(t))
	a.ensureThrottleMaps()

	a.loginSuccess("admin", "10.1.1.5")
	a.loginSuccess("admin", "10.1.2.5")
	a.loginThrottle.userLock["admin"] = time.Now().Add(time.Hour)

	for i := 0; i < knownGoodRevokeFails; i++ {
		a.recordUserFail("admin", "10.1.1.5")
	}
	a.loginThrottle.Lock()
	_, aExempt := a.loginThrottle.knownGood[knownGoodKey("admin", "10.1.1.5")]
	_, bExempt := a.loginThrottle.knownGood[knownGoodKey("admin", "10.1.2.5")]
	a.loginThrottle.Unlock()
	if aExempt {
		t.Fatal("bucket A's exemption must be revoked after N fails")
	}
	if !bExempt {
		t.Fatal("bucket B's exemption must survive bucket A's revocation")
	}
	if ok, _ := a.checkUserLock("admin", "10.1.1.5"); ok {
		t.Fatal("revoked bucket A must see the account lockout")
	}
	if ok, _ := a.checkUserLock("admin", "10.1.2.5"); !ok {
		t.Fatal("bucket B must stay exempt from the account lockout")
	}
}

// TestKnownGoodFailsNotMintedWithoutExemption: the revocation counter must
// stay bounded by knownGood's key space — fails for a pair with NO active
// exemption mint no counter entry (a username-rotation spray must not grow
// knownGoodFails unboundedly).
func TestKnownGoodFailsNotMintedWithoutExemption(t *testing.T) {
	a := NewAuthState(newTestDB(t))
	a.ensureThrottleMaps()

	for i := 0; i < knownGoodRevokeFails+5; i++ {
		a.recordUserFail("admin", "10.9.9.9")
	}
	a.loginThrottle.Lock()
	n := len(a.loginThrottle.knownGoodFails)
	a.loginThrottle.Unlock()
	if n != 0 {
		t.Fatalf("knownGoodFails grew to %d for a non-exempt pair; want 0", n)
	}
}
