package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// releaseCheckRedirect is the updater client's redirect policy. The bare
// http.DefaultTransport follows up to 10 redirects of ANY scheme and ANY
// host, so a compromised GitHub asset (or a MITM that wins the initial
// TLS handshake) could 302 the release download to http:// (cleartext) or
// to an internal host — and the swap would proceed to install those bytes
// before the signature check ever ran. Every redirect is re-validated:
// it must stay on HTTPS and land on a GitHub release host. The initial
// request is already pinned to api.github.com by the callers, so only the
// hops after it reach here.
func releaseCheckRedirect(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing non-https redirect to %s", req.URL)
	}
	host := req.URL.Hostname()
	switch host {
	case "api.github.com", "github.com", "objects.githubusercontent.com", "codeload.github.com":
		return nil
	}
	return fmt.Errorf("refusing redirect to non-GitHub host %s", host)
}

func fetchRelease(client *http.Client, version string) (*ghRelease, error) {
	url := releaseBase + "/latest"
	if version != "latest" {
		if !strings.HasPrefix(version, "v") {
			version = "v" + version
		}
		if !validVersionToken(version) {
			return nil, fmt.Errorf("invalid version %q: expected a release tag like v0.2.2", version)
		}
		url = releaseBase + "/tags/" + version
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid request for %q: %v", url, err)
	}
	req.Header.Set("User-Agent", userAgent())
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned HTTP %d for %s", resp.StatusCode, url)
	}
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

// releaseSelection is the (binary, digest, sidecar, signature) quad resolved
// from a release's asset list for the running platform. tag + asset are the
// manifest-binding fields: the release signature covers the manifest
// (releaseManifestMessage), which binds it to THIS tag and THIS asset so a
// signature for one release can never verify against another (replay).
type releaseSelection struct {
	assetURL   string
	sha        string
	sidecarURL string
	sigURL     string
	tag        string
	asset      string
}

// selectAssets picks the release assets for this platform: the binary
// (targetAsset()), its GitHub-computed digest if present, and the
// targetAsset()+".sha256" sidecar URL used when no API digest exists. URLs
// prefer the browser download URL; the API asset endpoint only works with
// Accept: application/octet-stream and carries no asset name.
func selectAssets(rel *ghRelease) releaseSelection {
	sel := releaseSelection{tag: rel.TagName, asset: targetAsset()}
	for _, a := range rel.Assets {
		switch a.Name {
		case targetAsset():
			sel.sha = strings.TrimPrefix(a.Digest, "sha256:")
			if a.BrowserDownloadURL != "" {
				sel.assetURL = a.BrowserDownloadURL
			} else {
				sel.assetURL = a.URL
			}
		case targetAsset() + ".sha256":
			if a.BrowserDownloadURL != "" {
				sel.sidecarURL = a.BrowserDownloadURL
			} else {
				sel.sidecarURL = a.URL
			}
		case targetAsset() + ".sig":
			if a.BrowserDownloadURL != "" {
				sel.sigURL = a.BrowserDownloadURL
			} else {
				sel.sigURL = a.URL
			}
		}
	}
	return sel
}

// fetchChecksumSidecar downloads the published .sha256 sidecar asset and
// returns the bare 64-hex digest, normalized to lowercase (uppercase hex
// from checksum tools is accepted). Accepts both "sha256sum" format
// ("<hex>  <name>") and a bare hex line.
func fetchChecksumSidecar(client *http.Client, url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent())
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errReleaseFetch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: HTTP %d for %s", errReleaseFetch, resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	fields := strings.Fields(strings.TrimSpace(string(body)))
	if len(fields) == 0 {
		return "", fmt.Errorf("empty sidecar")
	}
	hexd := fields[0]
	if len(hexd) != 64 {
		return "", fmt.Errorf("malformed sidecar: %q", hexd)
	}
	// Some pipelines and checksum tools emit uppercase hex (sha256sum -b on
	// some distros, hand-typed digests). Normalize before validating so an
	// uppercase sidecar is accepted and still compares equal to the
	// lowercase digest computed by fileSHA256.
	hexd = strings.ToLower(hexd)
	for _, c := range hexd {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", fmt.Errorf("sidecar digest is not hex: %q", hexd)
		}
	}
	return hexd, nil
}

func downloadAsset(client *http.Client, url, dir string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	// Request the identity (uncompressed) form and the octet-stream content
	// type explicitly. A CDN edge that serves a gzip-encoded object without
	// the Content-Encoding header would otherwise hand us compressed bytes
	// that fail the SHA-256 check with no obvious cause; the Accept header
	// makes an API asset URL (fallback path) return the binary instead of
	// its JSON metadata.
	req.Header.Set("User-Agent", userAgent())
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Accept", "application/octet-stream")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && ce != "identity" {
		return "", fmt.Errorf("unexpected Content-Encoding %q from release CDN (refusing to verify compressed bytes)", ce)
	}
	// Stage on the DESTINATION volume, not /tmp: a cross-device move would
	// force a full up-to-512 MiB copy into the binary dir anyway (and a
	// small /tmp — common on embedded boxes — could fill mid-download).
	f, err := os.CreateTemp(dir, "pulsemon-update-*")
	if err != nil {
		return "", err
	}
	defer f.Close()
	// Hard byte cap: the Content-Length cross-check below only catches
	// truncation, not a lying CDN that streams an enormous body (or a
	// mismatched-but-claimed-large one), which would fill the temp
	// filesystem before any verification could fail. 512 MiB is far past
	// any plausible pulsemon release.
	const maxAssetBytes = 512 << 20
	var got int64
	if got, err = io.Copy(f, io.LimitReader(resp.Body, maxAssetBytes+1)); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	if got > maxAssetBytes {
		os.Remove(f.Name())
		return "", fmt.Errorf("release asset exceeds %d bytes", maxAssetBytes)
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if want, perr := strconv.ParseInt(cl, 10, 64); perr == nil && got != want {
			os.Remove(f.Name())
			return "", fmt.Errorf("downloaded %d bytes, header said %d (connection truncated?)", got, want)
		}
	}
	return f.Name(), nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// errReleaseFetch marks a failure to FETCH a release artifact (the .sig or
// .sha256 asset download) as distinct from a verification VERDICT (bad or
// missing signature, SHA mismatch, missing sidecar asset). Fetch failures
// embed upstream detail — asset URLs, DNS names, proxy config — which the
// API layer must not echo into a response body (handleUpdate splits on
// this sentinel); verdicts are operator-actionable and are surfaced
// verbatim. The CLI path (runUpdate) shows the full error either way.
var errReleaseFetch = errors.New("release asset fetch failed")

// verifyDownloadedAsset enforces the mandatory authenticity + integrity
// checks on a downloaded release asset. It runs TWO gates, in order:
//
//  1. AUTHENTICITY (the load-bearing one): the binary's detached ed25519
//     signature (targetAsset()+".sig", resolved by name in selectAssets)
//     must verify against at least one of the embedded trusted release
//     pubkeys (release_pubkeys). This is FAIL-CLOSED — a missing .sig, an
//     undecodable signature, or one that verifies against no trusted key is
//     a refusal. A compromised release pipeline can publish a trojaned
//     binary and a matching SHA-256 (both come from the same release), but
//     it cannot sign the binary without the private key, so it cannot pass
//     this gate.
//
//  2. INTEGRITY (defense in depth): the SHA-256 must match the release's
//     published digest (GitHub API digest, or the .sha256 sidecar when that
//     is absent — pre-2025 uploads; when NEITHER exists it refuses). A
//     valid signature already pins the exact bytes the key holder signed, so
//     this is a redundant integrity net; it is kept because it is cheap and
//     catches a sig/bytes skew.
//
// Shared by the CLI (runUpdate) and the dashboard endpoint (handleUpdate) so
// the verification contract lives in one place. Returns the verified digest.
func verifyDownloadedAsset(client *http.Client, sel releaseSelection, tmp string) (string, error) {
	// Stream the digest ONCE: the asset is up to 512 MiB (maxAssetBytes)
	// and a low-RAM SBC must not page the whole binary in just to hash it.
	// Both gates below consume this one digest.
	digest, err := fileSHA256(tmp)
	if err != nil {
		return "", fmt.Errorf("verify: %v", err)
	}

	// Gate 1: authenticity. Fail-closed — see verifyReleaseSignature.
	if err := verifyReleaseSignature(client, sel, digest); err != nil {
		return "", err
	}

	// Gate 2: integrity (defense in depth on top of the signature).
	verifySHA := strings.TrimPrefix(sel.sha, "sha256:")
	if verifySHA == "" {
		if sel.sidecarURL == "" {
			return "", fmt.Errorf("no trusted SHA-256 sidecar asset found in release")
		}
		sidecar, err := fetchChecksumSidecar(client, sel.sidecarURL)
		if err != nil {
			return "", fmt.Errorf("no trusted SHA-256 available (sidecar fetch failed: %v)", err)
		}
		verifySHA = sidecar
	}
	if digest != verifySHA {
		return "", fmt.Errorf("SHA-256 MISMATCH — expected %s, got %s", verifySHA, digest)
	}
	return digest, nil
}

// parseReleasePubkeys decodes the embedded trusted release-signing pubkeys
// (release_pubkeys: hex ed25519 pubkeys, one per line; '#' comments and
// blank lines ignored) into ed25519 public keys.
func parseReleasePubkeys() ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for _, line := range strings.Split(string(releasePubkeys), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		b, err := hex.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("release_pubkeys: bad hex key: %v", err)
		}
		if len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("release_pubkeys: key is %d bytes, want %d", len(b), ed25519.PublicKeySize)
		}
		keys = append(keys, ed25519.PublicKey(b))
	}
	if len(keys) == 0 {
		return nil, errors.New("release_pubkeys: no trusted keys embedded")
	}
	return keys, nil
}

// fetchReleaseSignature downloads the detached .sig asset for the release
// binary and returns the decoded ed25519 signature bytes. The .sig is the
// hex-encoded 64-byte signature (one line), produced by `pulsemon sign
// release`. The read is capped far below any real signature to bound it.
func fetchReleaseSignature(client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent())
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errReleaseFetch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d for %s", errReleaseFetch, resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return nil, err
	}
	sig, err := hex.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		return nil, fmt.Errorf("malformed .sig (not hex): %v", err)
	}
	return sig, nil
}

// releaseManifestMessage is the exact byte string a release signature
// covers: a versioned manifest binding the signature to the release TAG,
// the ASSET NAME, and the binary's SHA-256. A signature made for one
// (tag, asset, sha) triple cannot verify against any other — a compromised
// account (no signing key) can no longer replay an old signed binary under
// a new tag, and a wrong-arch .sig (linux-amd64 asset verified as
// linux-arm64) is refused too. The format is versioned (line 1) so a
// future field can be added without silently re-keying old signatures.
//
// The raw-bytes form (v0.4.4 and earlier) signed the RAW BINARY BYTES
// instead; it is no longer accepted by verifyReleaseSignature (it bound
// nothing but the bytes, leaving a replay hole — see the comment there). It
// is retained in the `sign` maintainer tool (2/4-arg forms) for historical
// verification only.
func releaseManifestMessage(tag, asset, sha256Hex string) []byte {
	return []byte(fmt.Sprintf("pulsemon-release-v1\n%s\n%s\n%s\n", tag, asset, sha256Hex))
}

// verifyReleaseSignature checks the downloaded binary's detached ed25519
// signature against the embedded trusted pubkey set. FAIL-CLOSED: a missing
// .sig asset, an undecodable/oversized signature, or a signature that
// verifies against none of the trusted keys is a refusal — an unsigned or
// foreign-signed release must never install. This is the authenticity root
// the SHA-256 check cannot provide.
//
// The signature is checked against the MANIFEST (tag + asset + sha256). The
// digest is passed in by the caller (verifyDownloadedAsset streams it once
// via fileSHA256) so the multi-hundred-MiB binary is never held in memory
// just to build the manifest message.
func verifyReleaseSignature(client *http.Client, sel releaseSelection, sha256Hex string) error {
	if sel.sigURL == "" {
		return errors.New("release has no .sig signature asset — refusing to install an unsigned release")
	}
	sig, err := fetchReleaseSignature(client, sel.sigURL)
	if err != nil {
		return fmt.Errorf("release signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("release signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	keys, err := parseReleasePubkeys()
	if err != nil {
		return err
	}
	// The signature must verify against the MANIFEST (tag + asset + sha256).
	// The legacy raw-bytes form (pre-manifest releases, v0.4.4 and earlier)
	// is NO LONGER accepted: it bound the signature to the bytes only, so a
	// compromised release account (no signing key) could re-upload an old
	// signed binary under a newer-looking tag and the signature would still
	// verify — a replay the anti-downgrade floor cannot catch, because the
	// tag is attacker-chosen (it sits above the floor). The fallback existed
	// for ONE transition release (the first carrying this manifest verifier,
	// cut v0.4.4→v0.4.5 era) so v0.4.4-era clients could install it; that is
	// long past (VERSION is well beyond it), and no client running this
	// verifier can self-update to a pre-manifest release anyway (downgrades
	// are refused by the floor), so the fallback was dead weight that
	// re-opened the replay hole. Fail closed if the binding fields are
	// missing — a signature with no tag/asset to bind to is unverifiable.
	if sel.tag == "" || sel.asset == "" {
		return errors.New("release signature: missing tag or asset — the manifest-bound signature cannot be verified")
	}
	msg := releaseManifestMessage(sel.tag, sel.asset, sha256Hex)
	for _, pub := range keys {
		if ed25519.Verify(pub, msg, sig) {
			return nil
		}
	}
	return errors.New("release signature invalid — the binary is not signed by a trusted release key for this release tag and asset")
}
