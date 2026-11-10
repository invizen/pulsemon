package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// signManifest signs the release MANIFEST (tag + asset + sha256 of binBytes)
// with priv — the 2026-11-05 signature form that binds a .sig to one specific
// release, so an old signed binary replayed under a new tag no longer
// verifies (the raw-bytes form bound nothing but the bytes).
func signManifest(t *testing.T, priv ed25519.PrivateKey, tag, asset string, binBytes []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(binBytes)
	return ed25519.Sign(priv, releaseManifestMessage(tag, asset, hex.EncodeToString(sum[:])))
}

// manifestSel builds a releaseSelection with the manifest-binding fields
// (tag + asset) set — the shape selectAssets produces in production.
func manifestSel(tag, asset, sigURL string) releaseSelection {
	return releaseSelection{sigURL: sigURL, tag: tag, asset: asset}
}

// TestVerifyReleaseSignature_ManifestValid pins the new happy path: a
// manifest signature for exactly (tag, asset, sha) verifies.
func TestVerifyReleaseSignature_ManifestValid(t *testing.T) {
	_, priv, binBytes := sigTestSetup(t)
	srv := serveSig(t, signManifest(t, priv, "v0.4.5", "pulsemon-linux-amd64", binBytes))
	if err := verifyReleaseSignature(srv.Client(), manifestSel("v0.4.5", "pulsemon-linux-amd64", srv.URL), binBytes); err != nil {
		t.Fatalf("valid manifest signature rejected: %v", err)
	}
}

// TestVerifyReleaseSignature_ManifestReplayWrongTag is the replay attack
// itself: a signature that is GENUINELY valid (right key, right bytes) for
// v0.3.11 must not verify for a release published as v9.9.9. Under the old
// raw-bytes form this passed — the bytes and the key were all authentic.
func TestVerifyReleaseSignature_ManifestReplayWrongTag(t *testing.T) {
	_, priv, binBytes := sigTestSetup(t)
	srv := serveSig(t, signManifest(t, priv, "v0.3.11", "pulsemon-linux-amd64", binBytes))
	if err := verifyReleaseSignature(srv.Client(), manifestSel("v9.9.9", "pulsemon-linux-amd64", srv.URL), binBytes); err == nil {
		t.Fatal("a v0.3.11 manifest signature was accepted for a v9.9.9 release")
	}
}

// TestVerifyReleaseSignature_ManifestWrongAsset: a signature for the amd64
// asset must not verify for the arm64 asset (the old form bound no platform
// at all — a linux-amd64 .sig copied onto the arm64 asset would install).
func TestVerifyReleaseSignature_ManifestWrongAsset(t *testing.T) {
	_, priv, binBytes := sigTestSetup(t)
	srv := serveSig(t, signManifest(t, priv, "v0.4.5", "pulsemon-linux-amd64", binBytes))
	if err := verifyReleaseSignature(srv.Client(), manifestSel("v0.4.5", "pulsemon-linux-arm64", srv.URL), binBytes); err == nil {
		t.Fatal("an amd64 manifest signature was accepted for the arm64 asset")
	}
}

// TestVerifyReleaseSignature_ManifestWrongSHA: the manifest binds the
// digest, so a binary that differs from the signed one is refused even with
// the right tag and asset (defense in depth on top of the SHA gate).
func TestVerifyReleaseSignature_ManifestWrongSHA(t *testing.T) {
	_, priv, binBytes := sigTestSetup(t)
	srv := serveSig(t, signManifest(t, priv, "v0.4.5", "pulsemon-linux-amd64", binBytes))
	other := []byte("different binary bytes — same tag, same asset, different sha")
	if err := verifyReleaseSignature(srv.Client(), manifestSel("v0.4.5", "pulsemon-linux-amd64", srv.URL), other); err == nil {
		t.Fatal("a manifest signature verified against bytes with a different sha256")
	}
}

// TestVerifyReleaseSignature_RawBytesReplayRejected is the replay attack the
// legacy fallback left open: a RAW-BYTES signature (pre-manifest form) that
// is genuinely valid for the bytes must NOT verify for a release published
// under a tag. The raw-bytes form bound nothing but the bytes, so a
// compromised release account (no signing key) could re-upload an old signed
// binary under a newer-looking tag and the signature would still verify — a
// replay the anti-downgrade floor can't catch (the tag is attacker-chosen).
// The manifest is now the ONLY accepted form, so a raw-bytes .sig over a tag
// is refused. (The one transition release that needed the raw-bytes fallback
// is long past; see verifyReleaseSignature.)
func TestVerifyReleaseSignature_RawBytesReplayRejected(t *testing.T) {
	_, priv, binBytes := sigTestSetup(t)
	// A raw-bytes signature: valid for the bytes, bound to no tag/asset.
	srv := serveSig(t, ed25519.Sign(priv, binBytes))
	if err := verifyReleaseSignature(srv.Client(), manifestSel("v9.9.9", "pulsemon-linux-amd64", srv.URL), binBytes); err == nil {
		t.Fatal("a raw-bytes (pre-manifest) signature was accepted for a tagged release — replay hole not closed")
	}
}

// TestVerifyReleaseSignature_MissingBindingRefused pins the fail-closed
// behavior on missing binding fields: a signature (even a valid manifest
// one) is refused when the selection carries no tag/asset to bind it to —
// a signature with nothing to bind to is unverifiable.
func TestVerifyReleaseSignature_MissingBindingRefused(t *testing.T) {
	_, priv, binBytes := sigTestSetup(t)
	srv := serveSig(t, signManifest(t, priv, "v0.4.5", "pulsemon-linux-amd64", binBytes))
	if err := verifyReleaseSignature(srv.Client(), releaseSelection{sigURL: srv.URL}, binBytes); err == nil {
		t.Fatal("a signature was accepted with no tag/asset to bind it to")
	}
}

// TestVerifyReleaseSignature_ManifestExactBytes pins the signed message
// format byte-for-byte (versioned prefix, three \n-separated fields,
// trailing newline) so a future "harmless" reformat re-keys every release.
func TestVerifyReleaseSignature_ManifestExactBytes(t *testing.T) {
	got := releaseManifestMessage("v0.4.5", "pulsemon-linux-amd64", "abc123")
	want := "pulsemon-release-v1\nv0.4.5\npulsemon-linux-amd64\nabc123\n"
	if string(got) != want {
		t.Fatalf("manifest message = %q, want %q", got, want)
	}
}

// End-to-end through verifyDownloadedAsset (the real pre-install gate): the
// same replay the unit tests pin — a binary manifest-signed for v0.3.11,
// served as v9.9.9 with a matching SHA sidecar, must be refused.
func TestVerifyDownloadedAsset_ManifestReplay(t *testing.T) {
	_, priv, binBytes := sigTestSetup(t)
	sum := sha256.Sum256(binBytes)
	shaHex := hex.EncodeToString(sum[:])
	srv := serveSig(t, signManifest(t, priv, "v0.3.11", targetAsset(), binBytes))

	tmp := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(tmp, binBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	sel := releaseSelection{sigURL: srv.URL, sha: shaHex, tag: "v9.9.9", asset: targetAsset()}
	if _, err := verifyDownloadedAsset(srv.Client(), sel, tmp); err == nil {
		t.Fatal("an old release's binary (manifest-signed for v0.3.11) was installed as v9.9.9")
	}
}
