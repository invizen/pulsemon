package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// sigTestSetup generates a fresh ed25519 keypair, points the embedded
// trusted-key set (releasePubkeys) at the new public key, and returns a fake
// release binary. The override is restored in t.Cleanup so the real embedded
// keys are intact for every other test.
func sigTestSetup(t *testing.T) (pub ed25519.PublicKey, priv ed25519.PrivateKey, binBytes []byte) {
	t.Helper()
	var err error
	pub, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	orig := releasePubkeys
	releasePubkeys = []byte(hex.EncodeToString(pub) + "\n")
	t.Cleanup(func() { releasePubkeys = orig })
	binBytes = []byte("fake pulsemon release binary bytes for the signature test")
	return
}

// serveSig stands up an httptest server that serves the given signature bytes
// (hex-encoded, one line) — the shape a .sig release asset takes.
func serveSig(t *testing.T, sig []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, hex.EncodeToString(sig))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestVerifyReleaseSignature_Valid(t *testing.T) {
	_, priv, binBytes := sigTestSetup(t)
	sig := ed25519.Sign(priv, binBytes)
	srv := serveSig(t, sig)

	if err := verifyReleaseSignature(srv.Client(), releaseSelection{sigURL: srv.URL}, binBytes); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestVerifyReleaseSignature_WrongKey(t *testing.T) {
	// The embedded trusted key is the one from sigTestSetup; a signature from
	// a DIFFERENT key must be refused.
	_, _, binBytes := sigTestSetup(t)
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = otherPub
	sig := ed25519.Sign(otherPriv, binBytes)
	srv := serveSig(t, sig)

	if err := verifyReleaseSignature(srv.Client(), releaseSelection{sigURL: srv.URL}, binBytes); err == nil {
		t.Fatal("signature from an untrusted key was accepted")
	}
}

func TestVerifyReleaseSignature_MissingSig(t *testing.T) {
	_, _, binBytes := sigTestSetup(t)
	// No .sig asset in the release (sel.sigURL == "") -> fail-closed refusal.
	if err := verifyReleaseSignature(&http.Client{}, releaseSelection{}, binBytes); err == nil {
		t.Fatal("an unsigned release (no .sig) was accepted")
	}
}

func TestVerifyReleaseSignature_CorruptSig(t *testing.T) {
	_, priv, binBytes := sigTestSetup(t)
	sig := ed25519.Sign(priv, binBytes)
	// Flip a bit: a valid-length signature that verifies against nothing.
	sig[0] ^= 0xff
	srv := serveSig(t, sig)

	if err := verifyReleaseSignature(srv.Client(), releaseSelection{sigURL: srv.URL}, binBytes); err == nil {
		t.Fatal("a corrupted signature was accepted")
	}
}

func TestVerifyReleaseSignature_WrongLength(t *testing.T) {
	_, _, binBytes := sigTestSetup(t)
	// 50 bytes, not 64 -> refused before any key is tried.
	srv := serveSig(t, make([]byte, 50))
	if err := verifyReleaseSignature(srv.Client(), releaseSelection{sigURL: srv.URL}, binBytes); err == nil {
		t.Fatal("a mis-sized signature was accepted")
	}
}

func TestVerifyReleaseSignature_Rotation(t *testing.T) {
	// Two trusted keys in the set: a signature from EITHER must verify. This
	// is what makes key rotation a normal update (add the new key, sign with
	// it, retire the old one later).
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)
	orig := releasePubkeys
	releasePubkeys = []byte(hex.EncodeToString(pubA) + "\n" + hex.EncodeToString(pubB) + "\n")
	t.Cleanup(func() { releasePubkeys = orig })

	binBytes := []byte("binary signed during a rotation window")
	for name, priv := range map[string]ed25519.PrivateKey{"A": privA, "B": privB} {
		sig := ed25519.Sign(priv, binBytes)
		srv := serveSig(t, sig)
		if err := verifyReleaseSignature(srv.Client(), releaseSelection{sigURL: srv.URL}, binBytes); err != nil {
			t.Fatalf("rotation: signature from key %s rejected: %v", name, err)
		}
	}
}

func TestParseReleasePubkeys(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	orig := releasePubkeys
	releasePubkeys = []byte("# a comment line\n\n" + hex.EncodeToString(pub) + "\n")
	t.Cleanup(func() { releasePubkeys = orig })

	keys, err := parseReleasePubkeys()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1 (comments/blank lines must be skipped)", len(keys))
	}
	if !ed25519.PublicKey(keys[0]).Equal(pub) {
		t.Fatal("parsed key does not match the embedded one")
	}
}

// End-to-end: a signed binary whose SHA matches is accepted.
func TestVerifyDownloadedAsset_Signed(t *testing.T) {
	_, priv, binBytes := sigTestSetup(t)
	sig := ed25519.Sign(priv, binBytes)
	sum := sha256.Sum256(binBytes)
	shaHex := hex.EncodeToString(sum[:])

	tmp := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(tmp, binBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	srv := serveSig(t, sig)

	got, err := verifyDownloadedAsset(srv.Client(), releaseSelection{sigURL: srv.URL, sha: shaHex}, tmp)
	if err != nil {
		t.Fatalf("signed + matching-SHA release rejected: %v", err)
	}
	if got != shaHex {
		t.Errorf("digest = %q, want %q", got, shaHex)
	}
}

// End-to-end: a release with NO .sig is refused even though its SHA matches.
// This is the whole point — SHA alone (integrity) is not enough; the
// authenticity gate must fail closed.
func TestVerifyDownloadedAsset_Unsigned(t *testing.T) {
	_, _, binBytes := sigTestSetup(t)
	sum := sha256.Sum256(binBytes)
	shaHex := hex.EncodeToString(sum[:])

	tmp := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(tmp, binBytes, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := verifyDownloadedAsset(&http.Client{}, releaseSelection{sha: shaHex}, tmp); err == nil {
		t.Fatal("an unsigned release (matching SHA, no .sig) was installed")
	}
}

// End-to-end: a foreign-signed binary is refused even though its SHA matches.
func TestVerifyDownloadedAsset_ForeignSig(t *testing.T) {
	_, _, binBytes := sigTestSetup(t) // trusted key embedded
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	sig := ed25519.Sign(otherPriv, binBytes)
	sum := sha256.Sum256(binBytes)
	shaHex := hex.EncodeToString(sum[:])

	tmp := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(tmp, binBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	srv := serveSig(t, sig)

	if _, err := verifyDownloadedAsset(srv.Client(), releaseSelection{sigURL: srv.URL, sha: shaHex}, tmp); err == nil {
		t.Fatal("a foreign-signed release (matching SHA) was installed")
	}
}
