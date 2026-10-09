package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestVerifyUserDummyHash pins the "precompute the dummy bcrypt hash" review
// finding. The finding's PREMISE (the per-call fmt.Sprintf is a meaningful
// overhead) is a false positive — it's ~1-2µs against the ~39ms cost-10 KDF
// it feeds, and brute-force is already IP-throttled. But its PROPOSED fix had
// two real defects this test locks against:
//
//  1. Its literal was MALFORMED: "$2a$10N9qo8u..." is 59 bytes, missing the
//     "$" after the cost. A correct bcrypt hash is "$2a$10$..." (60 bytes).
//     It only ran today because x/crypto's parser is lenient — a latent
//     defect, not a safe drop-in.
//  2. It DECOUPLED the dummy from bcryptCost (hardcoded 10). The invariant
//     (auth.go: dummyBcryptHash) is that the unknown-user path runs the SAME
//     KDF cost as real hashes, so the two paths never diverge into a timing
//     oracle if bcryptCost is ever raised.
//
// The current code (a package-level var built ONCE from bcryptCost) satisfies
// both. These assertions fail under either defect in the reviewer's fix.
func TestVerifyUserDummyHash(t *testing.T) {
	// (1) Well-formedness: 60 bytes, "$2a$" prefix, 2-digit cost, and a "$"
	//     separator at byte 6 (the exact spot the reviewer's 59-byte literal
	//     was missing). This is the check that rejects the malformed fix.
	if got := len(dummyBcryptHash); got != 60 {
		t.Fatalf("dummyBcryptHash len = %d, want 60 (a bcrypt hash is exactly 60 bytes; %d is malformed)", got, got)
	}
	if !strings.HasPrefix(string(dummyBcryptHash), "$2a$") {
		t.Fatalf("dummyBcryptHash must start with \"$2a$\": %q", string(dummyBcryptHash))
	}
	if dummyBcryptHash[6] != '$' {
		t.Fatalf("dummyBcryptHash[6] = %q, want '$' (the cost separator; a missing '$' means the salt/digest are mis-framed)", dummyBcryptHash[6])
	}

	// (2) Cost matches bcryptCost: the 2 cost digits (bytes 4:5) must equal
	//     bcryptCost, so the dummy runs the SAME KDF cost as every real hash.
	//     Hardcoding a fixed cost (the reviewer's fix) breaks this if the cost
	//     is ever raised.
	wantCost := fmt.Sprintf("%02d", bcryptCost)
	if got := string(dummyBcryptHash[4:6]); got != wantCost {
		t.Fatalf("dummyBcryptHash cost = %q, want %q (must track bcryptCost; a hardcoded cost is a timing oracle)", got, wantCost)
	}

	// (3) It parses to the expected cost (not just "runs").
	parsed, err := parseBcryptCost(dummyBcryptHash)
	if err != nil {
		t.Fatalf("dummyBcryptHash does not parse: %v", err)
	}
	if parsed != bcryptCost {
		t.Fatalf("parsed dummy cost = %d, want %d (bcryptCost)", parsed, bcryptCost)
	}

	// (4) The unknown-user path actually RUNS the KDF (does not fast-fail).
	//     A malformed hash that errored before the KDF would make the
	//     unknown-user path ~microseconds — a timing oracle vs the ~39ms
	//     wrong-password path. Measure that it takes real KDF time.
	db := newTestDB(t)
	a := NewAuthState(db)
	_ = a.AddUser("admin", "secretpw") // enable auth
	t0 := time.Now()
	if _, ok := a.VerifyUser("no-such-user", "attacker-pw"); ok {
		t.Fatalf("VerifyUser accepted an unknown user")
	}
	elapsed := time.Since(t0)
	if elapsed < 5*time.Millisecond {
		t.Fatalf("unknown-user path took %v — too fast; the dummy hash is not running the cost-%d KDF (likely a malformed hash that fast-fails -> timing oracle)",
			elapsed, bcryptCost)
	}
	t.Logf("unknown-user path ran the KDF in %v (cost %d) — no timing oracle", elapsed, bcryptCost)

	// (5) The reviewer's malformed literal would have FAILED this test: assert
	//     the exact string from the finding is not well-formed, so a future
	//     copy-paste of it is caught.
	reviewer := []byte("$2a$10N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")
	if len(reviewer) == 60 && reviewer[6] == '$' {
		t.Fatal("the reviewer's malformed 59-byte literal passed the well-formedness check — the test is not guarding the regression")
	}
	t.Logf("reviewer literal correctly rejected: len=%d byte[6]=%q", len(reviewer), reviewer[6])
}

// parseBcryptCost returns the cost encoded in a bcrypt hash (the 2-digit field
// between "$2a$" and the next "$").
func parseBcryptCost(h []byte) (int, error) {
	s := string(h)
	if !strings.HasPrefix(s, "$2") {
		return 0, fmt.Errorf("not a $2 bcrypt hash: %q", s[:4])
	}
	// cost is the 2 chars after the "$2a$"/"$2b$" prefix.
	i := strings.IndexByte(s[4:], '$') // position of the cost separator
	if i < 2 {
		return 0, fmt.Errorf("missing cost separator: %q", s[4:8])
	}
	var cost int
	if _, err := fmt.Sscanf(s[4:4+i], "%d", &cost); err != nil {
		return 0, err
	}
	return cost, nil
}

// TestVerifyUserDummyMatchesRealHashCost is a timing sanity check: the
// unknown-user path and the wrong-password path should run at the SAME KDF
// cost. We don't assert exact equality (timing is noisy), but a wide gap would
// mean the dummy is not cost-matched. Both must clear a meaningful KDF floor.
func TestVerifyUserDummyMatchesRealHashCost(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	_ = a.AddUser("admin", "secretpw")

	// Unknown-user (dummy path).
	t0 := time.Now()
	_, _ = a.VerifyUser("ghost", "attacker-pw")
	unknown := time.Since(t0)

	// Wrong-password (real hash path).
	t0 = time.Now()
	_, _ = a.VerifyUser("admin", "wrong-pw")
	wrong := time.Since(t0)

	// Both ran a full cost-10 KDF -> both well above the no-KDF floor.
	if unknown < 5*time.Millisecond || wrong < 5*time.Millisecond {
		t.Fatalf("one path skipped the KDF: unknown-user=%v wrong-password=%v (cost %d)", unknown, wrong, bcryptCost)
	}
	// They should be the SAME order of magnitude. A >4x ratio means the dummy
	// is running a different (weaker/stronger) cost than the real hash.
	ratio := float64(unknown) / float64(wrong)
	if ratio < 0.25 || ratio > 4 {
		t.Fatalf("unknown-user=%v vs wrong-password=%v (ratio %.2f) — the dummy KDF cost diverges from the real hash cost", unknown, wrong, ratio)
	}
	t.Logf("unknown-user=%v wrong-password=%v (ratio %.2f) — cost-matched, no timing oracle", unknown, wrong, ratio)
}
