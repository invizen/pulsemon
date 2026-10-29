package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// tempLeakBefore snapshots the set of pulsemon-update-* files in the temp dir so
// a test can assert that a runUpdate exit path leaves nothing behind.
func tempLeakBefore() map[string]bool {
	entries, _ := os.ReadDir(os.TempDir())
	seen := map[string]bool{}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "pulsemon-update-") {
			seen[e.Name()] = true
		}
	}
	return seen
}

// tempLeakAfter reports any pulsemon-update-* file not present in before.
func tempLeakAfter(before map[string]bool) []string {
	entries, _ := os.ReadDir(os.TempDir())
	var leaked []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "pulsemon-update-") && !before[e.Name()] {
			leaked = append(leaked, e.Name())
		}
	}
	return leaked
}

// signFixture signs bin with a fresh ed25519 test key, points the embedded
// trusted-key set (releasePubkeys) at that key for the test's duration
// (restored in t.Cleanup), and returns the hex signature. Inline fixtures that
// build their own release (rather than using serveRelease) use this to satisfy
// the fail-closed authenticity gate in verifyDownloadedAsset.
func signFixture(t *testing.T, bin []byte) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test signing key: %v", err)
	}
	oldPubkeys := releasePubkeys
	releasePubkeys = []byte(hex.EncodeToString(pub) + "\n")
	t.Cleanup(func() { releasePubkeys = oldPubkeys })
	return hex.EncodeToString(ed25519.Sign(priv, bin))
}

// serveRelease spins up a fake GitHub releases API that hands out one asset.
// digest is the advertised sha256 (with or without the "sha256:" prefix); when
// it's empty the asset carries no digest, forcing the sidecar path. It returns
// the releases base URL (to point releaseBase at — fetchRelease appends
// "/latest") and the real sha256 of the served binary bytes.
//
// Every fixture is SIGNED: the payload is signed with a fresh ed25519 test key
// and the embedded trusted-key set (releasePubkeys) is pointed at that key for
// the test's duration. This satisfies the fail-closed authenticity gate in
// verifyDownloadedAsset so the tests exercise the update flow (sidecar
// resolution, user-agent, mismatch, install) now that a release without a valid
// .sig is refused. Tests that specifically want the UNSIGNED-refusal behavior
// use the dedicated sig tests in update_sig_test.go.
func serveRelease(t *testing.T, tag, digest string) (string, string) {
	t.Helper()
	bin := []byte("fake pulsemon binary payload\n")
	real := sha256.Sum256(bin)
	realHex := hex.EncodeToString(real[:])

	// Sign the payload (see signFixture) so the authenticity gate passes.
	sigHex := signFixture(t, bin)

	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		rel := ghRelease{
			TagName: tag,
			Assets: []releaseAsset{
				{
					Name: targetAsset(),
					// r.Host carries the 127.0.0.1:port of the test server.
					BrowserDownloadURL: "http://" + r.Host + "/releases/bin",
					Digest:             digest,
				},
				{
					Name:               targetAsset() + ".sig",
					BrowserDownloadURL: "http://" + r.Host + "/releases/bin.sig",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rel)
	})
	mux.HandleFunc("/releases/bin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(bin)
	})
	mux.HandleFunc("/releases/bin.sig", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(sigHex))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL + "/releases", realHex
}

// serveReleaseVerified is serveRelease with the advertised digest set to the
// payload's REAL sha256, so verification passes and the install path is
// exercised. Returns the releases base URL and the real digest.
func serveReleaseVerified(t *testing.T, tag string) (string, string) {
	t.Helper()
	bin := []byte("fake pulsemon binary payload\n")
	real := sha256.Sum256(bin)
	realHex := hex.EncodeToString(real[:])
	base, _ := serveRelease(t, tag, "sha256:"+realHex)
	return base, realHex
}

// TestRunUpdateCheckOnlyNoLeak pins the check-only contract: `pulsemon update
// check` reports a newer release with exit code 2 WITHOUT downloading or
// installing anything, so no temp file may be left behind.
func TestRunUpdateCheckOnlyNoLeak(t *testing.T) {
	base, _ := serveRelease(t, "v9.9.9", "")
	oldBase := releaseBase
	releaseBase = base
	oldVer := Version
	Version = "v0.0.1"
	t.Cleanup(func() {
		releaseBase = oldBase
		Version = oldVer
	})

	before := tempLeakBefore()
	if got := runUpdate([]string{"check"}); got != 2 {
		t.Fatalf("runUpdate(check) = %d, want 2 (newer available)", got)
	}
	if leaked := tempLeakAfter(before); len(leaked) != 0 {
		t.Fatalf("check-only run orphaned temp files: %v", leaked)
	}
}

// TestRunUpdateSHARefusedNoLeak is the direct regression for the os.Exit bug:
// a download that verifies against the WRONG sha256 must be refused (exit 1)
// and its multi-megabyte temp binary must not be orphaned. Before the fix this
// path called os.Exit(1), skipping the deferred os.Remove and leaking the file.
func TestRunUpdateSHARefusedNoLeak(t *testing.T) {
	// Advertise a digest that is valid 64-hex but does not match the payload,
	// so verification fails and the install is refused.
	base, _ := serveRelease(t, "v9.9.9", "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	oldBase := releaseBase
	releaseBase = base
	oldVer := Version
	Version = "v0.0.1"
	t.Cleanup(func() {
		releaseBase = oldBase
		Version = oldVer
	})

	before := tempLeakBefore()
	if got := runUpdate([]string{}); got != 1 {
		t.Fatalf("runUpdate on sha mismatch = %d, want 1 (refused)", got)
	}
	if leaked := tempLeakAfter(before); len(leaked) != 0 {
		t.Fatalf("sha-mismatch run orphaned temp files: %v", leaked)
	}
}

// TestRunUpdateUpToDate pins the already-current path: a release no newer than
// the running version is a no-op with exit 0 and no download.
func TestRunUpdateUpToDate(t *testing.T) {
	// Advertise a digest matching nothing is fine — we never download here.
	base, _ := serveRelease(t, "v9.9.9", "")
	oldBase := releaseBase
	releaseBase = base
	oldVer := Version
	Version = "v9.9.9" // same as the release → not newer
	t.Cleanup(func() {
		releaseBase = oldBase
		Version = oldVer
	})

	before := tempLeakBefore()
	if got := runUpdate([]string{}); got != 0 {
		t.Fatalf("runUpdate up to date = %d, want 0", got)
	}
	if leaked := tempLeakAfter(before); len(leaked) != 0 {
		t.Fatalf("up-to-date run orphaned temp files: %v", leaked)
	}
}

// TestRunUpdateMissingAsset pins the "release has no matching asset" failure:
// it must return 1, not panic or leak.
func TestRunUpdateMissingAsset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := ghRelease{TagName: "v9.9.9", Assets: []releaseAsset{{Name: "pulsemon-windows-amd64"}}}
		json.NewEncoder(w).Encode(rel)
	}))
	t.Cleanup(srv.Close)
	oldBase := releaseBase
	releaseBase = srv.URL
	oldVer := Version
	Version = "v0.0.1"
	t.Cleanup(func() {
		releaseBase = oldBase
		Version = oldVer
	})

	if got := runUpdate([]string{}); got != 1 {
		t.Fatalf("runUpdate missing asset = %d, want 1", got)
	}
}

// TestRunUpdateHelpNoLeak pins that -h/--help prints usage and returns 0
// without doing any network or filesystem work.
func TestRunUpdateHelpNoLeak(t *testing.T) {
	before := tempLeakBefore()
	if got := runUpdate([]string{"--help"}); got != 0 {
		t.Fatalf("runUpdate(--help) = %d, want 0", got)
	}
	if leaked := tempLeakAfter(before); len(leaked) != 0 {
		t.Fatalf("help run orphaned temp files: %v", leaked)
	}
}

// TestInstallBinarySuccess pins the happy path: content round-trips, the
// destination ends up 0755, and no .pulsemon-swap-* file is left in the dir.
func TestInstallBinarySuccess(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "newbin")
	dst := filepath.Join(dir, "oldbin")
	payload := []byte("new binary bytes\n")
	if err := os.WriteFile(src, payload, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("old binary bytes\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := installBinary(src, dst, ""); err != nil {
		t.Fatalf("installBinary: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("dst content = %q, want the source payload", got)
	}
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	// Contract change (review 2026-10-24): dst mode is PRESERVED (forced
	// 0755 widened e.g. 0750), with owner-exec always guaranteed — this
	// legacy 0600 dst comes back as 0700, not 0755.
	if fi.Mode().Perm() != 0700 {
		t.Fatalf("dst mode = %o, want 0600 preserved to 0700", fi.Mode().Perm())
	}
	for _, e := range entries(dir, t) {
		if strings.HasPrefix(e, ".pulsemon-swap-") {
			t.Fatalf("leftover swap file %q in %s", e, dir)
		}
	}
}

func entries(dir string, t *testing.T) []string {
	t.Helper()
	ls, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ls {
		out = append(out, e.Name())
	}
	return out
}

// TestInstallBinaryBadSource pins the old mustOpen failure mode: an
// unreadable/nonexistent source must surface a formatted error — not a panic
// (raw runtime trace) — and leave the destination untouched.
func TestInstallBinaryBadSource(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "bin")
	original := []byte("original\n")
	if err := os.WriteFile(dst, original, 0755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "does-not-exist")

	err := installBinary(src, dst, "")
	if err == nil {
		t.Fatal("installBinary with missing source: want error, got nil")
	}
	if !strings.Contains(err.Error(), "open source binary") {
		t.Fatalf("error = %q, want it to carry the formatted 'open source binary' prefix", err)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != string(original) {
		t.Fatalf("dst modified on failed install: %q", got)
	}
	for _, e := range entries(dir, t) {
		if strings.HasPrefix(e, ".pulsemon-swap-") {
			t.Fatalf("failed install left swap file %q", e)
		}
	}
}

// captureOutput runs fn with os.Stdout and os.Stderr captured and returns
// its exit code plus everything it printed (uInfo -> stdout; uWarn/uErr ->
// stderr).
func captureOutput(t *testing.T, fn func() int) (int, string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = wOut, wErr
	code := fn()
	wOut.Close()
	wErr.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, rOut)
	rOut.Close()
	_, _ = io.Copy(&buf, rErr)
	rErr.Close()
	return code, buf.String()
}

// captureStderr is a thin alias kept for the earlier tests that only care
// about stderr; it captures both streams (uInfo happens to write stdout).
func captureStderr(t *testing.T, fn func() int) (int, string) {
	return captureOutput(t, fn)
}

// TestRunUpdateSidecarViaAPIURL pins the fix for the fragile sidecar URL:
// a release whose binary asset carries no browser_download_url (so the
// binary URL is the API endpoint ".../assets/N" — which never ends with the
// asset name) and no API digest must still resolve the sidecar by looking it
// up in rel.Assets. The old string-munged URL
// (".../assets/N" + "pulsemon-linux-amd64.sha256") 404'd and the update was
// refused with "no trusted SHA-256" — so the test asserts the run got PAST
// sidecar resolution all the way to the SHA-256 mismatch (the served sidecar
// deliberately advertises a wrong digest).
func TestRunUpdateSidecarViaAPIURL(t *testing.T) {
	bin := "sidecar-path binary payload\n"
	sigHex := signFixture(t, []byte(bin))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/releases/latest"):
			// Binary asset: no BrowserDownloadURL → assetURL falls back to
			// a.URL (no asset name in it, like a real ".../assets/N").
			json.NewEncoder(w).Encode(ghRelease{TagName: "v9.9.9", Assets: []releaseAsset{
				{Name: targetAsset(), URL: "http://" + r.Host + "/releases/bin"},
				{Name: targetAsset() + ".sha256", URL: "http://" + r.Host + "/releases/sum"},
				{Name: targetAsset() + ".sig", URL: "http://" + r.Host + "/releases/bin.sig"},
			}})
		case strings.HasSuffix(r.URL.Path, "/releases/sum"):
			// Valid 64-hex but wrong on purpose: verification must fail
			// with a MISMATCH, which proves the sidecar was found.
			io.WriteString(w, "0000000000000000000000000000000000000000000000000000000000000000")
		case strings.HasSuffix(r.URL.Path, "/releases/bin.sig"):
			io.WriteString(w, sigHex)
		default:
			w.Header().Set("Content-Type", "application/octet-stream")
			io.WriteString(w, bin)
		}
	}))
	t.Cleanup(srv.Close)

	oldBase := releaseBase
	releaseBase = srv.URL + "/releases"
	oldVer := Version
	Version = "v0.0.1"
	t.Cleanup(func() {
		releaseBase = oldBase
		Version = oldVer
	})

	before := tempLeakBefore()
	code, out := captureStderr(t, func() int { return runUpdate([]string{}) })
	if code != 1 {
		t.Fatalf("runUpdate = %d, want 1 (mismatch refusal): %s", code, out)
	}
	if !strings.Contains(out, "SHA-256 MISMATCH") {
		t.Fatalf("stderr did not reach the mismatch check (sidecar not resolved?): %s", out)
	}
	if strings.Contains(out, "no trusted SHA-256") {
		t.Fatalf("stderr shows the old refusal path: %s", out)
	}
	if leaked := tempLeakAfter(before); len(leaked) != 0 {
		t.Fatalf("sidecar path run orphaned temp files: %v", leaked)
	}
}

// TestRunUpdateNoSidecarRefused pins the "no sidecar asset at all" refusal:
// exit 1 with a formatted diagnostic naming the missing sidecar asset — not
// the old "sidecar fetch failed: HTTP 404" from a munged URL.
func TestRunUpdateNoSidecarRefused(t *testing.T) {
	sigHex := signFixture(t, []byte("payload\n"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/releases/latest") {
			json.NewEncoder(w).Encode(ghRelease{TagName: "v9.9.9", Assets: []releaseAsset{
				{Name: targetAsset(), URL: "http://" + r.Host + "/releases/bin"},
				{Name: targetAsset() + ".sig", URL: "http://" + r.Host + "/releases/bin.sig"},
			}})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/releases/bin.sig") {
			io.WriteString(w, sigHex)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		io.WriteString(w, "payload\n")
	}))
	t.Cleanup(srv.Close)

	oldBase := releaseBase
	releaseBase = srv.URL + "/releases"
	oldVer := Version
	Version = "v0.0.1"
	t.Cleanup(func() {
		releaseBase = oldBase
		Version = oldVer
	})

	code, out := captureStderr(t, func() int { return runUpdate([]string{}) })
	if code != 1 {
		t.Fatalf("runUpdate = %d, want 1 (refused): %s", code, out)
	}
	if !strings.Contains(out, "no trusted SHA-256 sidecar asset found") {
		t.Fatalf("stderr missing the missing-sidecar diagnostic: %s", out)
	}
}

// TestRunUpdateOlderPinCheck pins the check-semantics fix: running v0.1.16
// and checking against an explicit OLDER pin (v0.1.5) must report "target
// version ... is not newer" and exit 0 — NOT "new version available" (exit
// 2), which would mislead automation into treating a downgrade as an update.
func TestRunUpdateOlderPinCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/tags/v0.1.5") {
			json.NewEncoder(w).Encode(ghRelease{TagName: "v0.1.5", Assets: []releaseAsset{
				{Name: targetAsset(), BrowserDownloadURL: "http://" + r.Host + "/releases/bin"},
			}})
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		io.WriteString(w, "payload\n")
	}))
	t.Cleanup(srv.Close)

	oldBase := releaseBase
	releaseBase = srv.URL
	oldVer := Version
	Version = "v0.1.16" // running a NEWER version than the pin
	t.Cleanup(func() {
		releaseBase = oldBase
		Version = oldVer
	})

	code, out := captureStderr(t, func() int { return runUpdate([]string{"check", "v0.1.5"}) })
	if code != 0 {
		t.Fatalf("check older pin = %d, want 0 (not an update): %s", code, out)
	}
	if strings.Contains(out, "new version available") {
		t.Fatalf("older pin wrongly advertised as an available update: %s", out)
	}
	if !strings.Contains(out, "is not newer than running") {
		t.Fatalf("stderr missing the not-newer diagnostic: %s", out)
	}
}

// TestRunUpdateNewerPinCheck pins the positive side: checking an explicit
// pin that IS newer than the running version still exits 2 with the
// "new version available" warning.
func TestRunUpdateNewerPinCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/tags/v9.9.9") {
			json.NewEncoder(w).Encode(ghRelease{TagName: "v9.9.9", Assets: []releaseAsset{
				{Name: targetAsset(), BrowserDownloadURL: "http://" + r.Host + "/releases/bin"},
			}})
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		io.WriteString(w, "payload\n")
	}))
	t.Cleanup(srv.Close)

	oldBase := releaseBase
	releaseBase = srv.URL
	oldVer := Version
	Version = "v0.0.1"
	t.Cleanup(func() {
		releaseBase = oldBase
		Version = oldVer
	})

	code, out := captureStderr(t, func() int { return runUpdate([]string{"check", "v9.9.9"}) })
	if code != 2 {
		t.Fatalf("check newer pin = %d, want 2: %s", code, out)
	}
	if !strings.Contains(out, "new version available") {
		t.Fatalf("stderr missing the new-version warning: %s", out)
	}
}

// TestTargetAssetFollowsRuntime pins that the asset name is derived from the
// running platform (pulsemon-<GOOS>-<GOARCH>) instead of being hardcoded to
// linux-amd64 — otherwise pulsemon update on an ARM SBC (Pi 4/5, RK3588) fails
// with "release has no pulsemon-linux-amd64 asset" or, worse, would fetch the
// wrong architecture. GOARCH is honored so a host can deliberately fetch a
// different architecture's asset.
func TestTargetAssetFollowsRuntime(t *testing.T) {
	t.Setenv("GOARCH", "")
	if got, want := targetAsset(), targetAssetName(runtime.GOOS, runtime.GOARCH); got != want {
		t.Fatalf("targetAsset() = %q, want %q", got, want)
	}
	t.Setenv("GOARCH", "arm64")
	if got, want := targetAsset(), targetAssetName(runtime.GOOS, "arm64"); got != want {
		t.Fatalf("targetAsset() with GOARCH=arm64 = %q, want %q", got, want)
	}
}

// TestTargetAssetNameWindowsExe pins the 2026-10-19 fix: Windows release
// assets carry the .exe extension (the workflow uploads
// pulsemon-windows-amd64.exe + .exe.sha256), so the updater must request
// that exact name. The old bare os/arch join made the first real Windows
// self-update (zendev) fail with "release has no pulsemon-windows-amd64
// asset" even though the asset was on the release.
func TestTargetAssetNameWindowsExe(t *testing.T) {
	if got := targetAssetName("windows", "amd64"); got != "pulsemon-windows-amd64.exe" {
		t.Errorf("windows/amd64 = %q, want pulsemon-windows-amd64.exe", got)
	}
	if got := targetAssetName("linux", "arm64"); got != "pulsemon-linux-arm64" {
		t.Errorf("linux/arm64 = %q, want pulsemon-linux-arm64", got)
	}
}

// TestSelectAssetsARM64 pins the end-to-end selection: with the release
// publishing BOTH amd64 and arm64 assets, GOARCH=arm64 must select the arm64
// binary AND arm64 sidecar — not the hardcoded amd64 ones. The old code
// looked for "pulsemon-linux-amd64" unconditionally, so on an ARM SBC the
// lookup missed and the update was refused with "release has no ... asset".
func TestSelectAssetsARM64(t *testing.T) {
	t.Setenv("GOARCH", "arm64")
	amdName := "pulsemon-" + runtime.GOOS + "-amd64"
	armName := "pulsemon-" + runtime.GOOS + "-arm64"
	rel := &ghRelease{TagName: "v9.9.9", Assets: []releaseAsset{
		{Name: amdName, BrowserDownloadURL: "http://x/amd64", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{Name: amdName + ".sha256", BrowserDownloadURL: "http://x/amd64.sha256"},
		{Name: armName, BrowserDownloadURL: "http://x/arm64", Digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		{Name: armName + ".sha256", BrowserDownloadURL: "http://x/arm64.sha256"},
	}}

	sel := selectAssets(rel)
	if sel.assetURL != "http://x/arm64" {
		t.Fatalf("assetURL = %q, want the arm64 binary URL", sel.assetURL)
	}
	if sel.sha != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("sha = %q, want the arm64 digest", sel.sha)
	}
	if sel.sidecarURL != "http://x/arm64.sha256" {
		t.Fatalf("sidecarURL = %q, want the arm64 sidecar URL", sel.sidecarURL)
	}
}

// TestSelectAssetsMissing reports when the platform's asset is absent from
// the release (e.g. an arm64 host and an amd64-only release) so runUpdate can
// surface a clear diagnostic instead of downloading the wrong binary.
func TestSelectAssetsMissing(t *testing.T) {
	t.Setenv("GOARCH", "arm64")
	amdName := "pulsemon-" + runtime.GOOS + "-amd64"
	rel := &ghRelease{TagName: "v9.9.9", Assets: []releaseAsset{
		{Name: amdName, BrowserDownloadURL: "http://x/amd64"},
	}}
	sel := selectAssets(rel)
	if sel.assetURL != "" {
		t.Fatalf("assetURL = %q, want empty for a release missing the arm64 asset", sel.assetURL)
	}
}

// TestFetchReleaseSendsUserAgent pins the GitHub API etiquette fix: the
// releases lookup must carry an app-specific User-Agent, not the stdlib
// default (Go-http-client/1.1), which GitHub throttles/403s aggressively.
func TestFetchReleaseSendsUserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ghRelease{TagName: "v9.9.9"})
	}))
	t.Cleanup(srv.Close)
	oldBase := releaseBase
	releaseBase = srv.URL
	oldVer := Version
	Version = "v1.2.3"
	t.Cleanup(func() {
		releaseBase = oldBase
		Version = oldVer
	})

	if _, err := fetchRelease(srv.Client(), "latest"); err != nil {
		t.Fatalf("fetchRelease: %v", err)
	}
	if gotUA != "pulsemon-updater/v1.2.3" {
		t.Fatalf("User-Agent = %q, want %q (got %q means the stdlib default or no header)", gotUA, "pulsemon-updater/v1.2.3", gotUA)
	}
}

// TestRunUpdateSendsUserAgentOnAllRequests pins that EVERY outbound request
// on a real update path (the releases lookup AND the asset download) carries
// the app-specific User-Agent — not just the API call. The run goes through
// the SHA-mismatch refusal (exit 1), which is the last network step before
// install, so both request sites are exercised.
func TestRunUpdateSendsUserAgentOnAllRequests(t *testing.T) {
	var mu sync.Mutex
	seenUA := map[string]string{} // path -> User-Agent
	sigHex := signFixture(t, []byte("binary bytes\n"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenUA[r.URL.Path] = r.Header.Get("User-Agent")
		mu.Unlock()
		switch r.URL.Path {
		case "/releases/latest":
			// No digest on the asset -> forces the sidecar path too, so
			// fetchChecksumSidecar's request is covered as well.
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ghRelease{
				TagName: "v9.9.9",
				Assets: []releaseAsset{
					{Name: targetAsset(), BrowserDownloadURL: "http://" + r.Host + "/bin"},
					{Name: targetAsset() + ".sha256", BrowserDownloadURL: "http://" + r.Host + "/bin.sha256"},
					{Name: targetAsset() + ".sig", BrowserDownloadURL: "http://" + r.Host + "/bin.sig"},
				},
			})
		case "/bin":
			// Wrong payload so verification fails -> exit 1 after the download.
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write([]byte("binary bytes\n"))
		case "/bin.sha256":
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("0000000000000000000000000000000000000000000000000000000000000000  pulsemon\n"))
		case "/bin.sig":
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(sigHex))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	oldBase := releaseBase
	releaseBase = srv.URL + "/releases"
	oldVer := Version
	Version = "v0.0.1"
	t.Cleanup(func() {
		releaseBase = oldBase
		Version = oldVer
	})

	before := tempLeakBefore()
	if got := runUpdate([]string{}); got != 1 {
		t.Fatalf("runUpdate = %d, want 1 (sha mismatch)", got)
	}
	if leaked := tempLeakAfter(before); len(leaked) != 0 {
		t.Fatalf("orphaned temp files: %v", leaked)
	}

	want := "pulsemon-updater/v0.0.1"
	mu.Lock()
	defer mu.Unlock()
	for path, ua := range seenUA {
		if ua != want {
			t.Errorf("request %s sent User-Agent %q, want %q", path, ua, want)
		}
	}
	for _, path := range []string{"/releases/latest", "/bin", "/bin.sha256", "/bin.sig"} {
		if _, ok := seenUA[path]; !ok {
			t.Errorf("expected request to %s was not observed", path)
		}
	}
}

// TestFetchChecksumSidecarHexCase pins the strict-lowercase fix: an
// uppercase (or mixed-case) 64-hex digest must be accepted and returned
// normalized to lowercase; non-hex or wrong-length digests are still
// refused. Cases: lowercase; uppercase; mixed-case; uppercase in
// sha256sum format ("digest  name"); a digest containing 'g' (not hex);
// 63 chars; 65 chars; empty body.
func TestFetchChecksumSidecarHexCase(t *testing.T) {
	const lower = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const upper = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
	const mixed = "0123456789AbCdEf0123456789AbCdEf0123456789AbCdEf0123456789AbCdEf"
	cases := []struct {
		body   string
		want   string
		errore bool
	}{
		{lower + "\n", lower, false},
		{upper + "\n", lower, false},
		{mixed + "\n", lower, false},
		{upper + "  pulsemon-linux-amd64\n", lower, false},
		{"0123456789abcdefg123456789abcdef0123456789abcdef0123456789abcdef\n", "", true},
		{lower[:63] + "\n", "", true},
		{lower + "0\n", "", true},
		{"\n", "", true},
	}
	for i, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, tc.body)
		}))
		got, err := fetchChecksumSidecar(srv.Client(), srv.URL)
		srv.Close()
		if tc.errore {
			if err == nil {
				t.Errorf("case %d (%q): got digest %q, want error", i, tc.body, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("case %d (%q): error = %v", i, tc.body, err)
			continue
		}
		if got != tc.want {
			t.Errorf("case %d (%q): digest = %q, want %q", i, tc.body, got, tc.want)
		}
	}
}

// TestRunUpdateUppercaseSidecarAccepted pins the fix end-to-end: a sidecar
// asset whose digest is the correct 64-hex length but uppercase must be
// accepted, normalized, and used for verification. Pre-fix,
// fetchChecksumSidecar rejected it ("not lowercase hex") and the update was
// refused with "no trusted SHA-256 available" — the run never reached the
// mismatch check. Post-fix, the same run reaches "SHA-256 MISMATCH" with
// the expected digest printed in lowercase (the sidecar's normalized value).
// The sidecar digest is the uppercase hash of a DIFFERENT payload, so the
// mismatch fires before any install happens.
func TestRunUpdateUppercaseSidecarAccepted(t *testing.T) {
	bin := "uppercase sidecar binary payload\n"
	other := sha256.Sum256([]byte("some other payload\n"))
	upperHex := strings.ToUpper(hex.EncodeToString(other[:]))
	sigHex := signFixture(t, []byte(bin))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/releases/latest":
			json.NewEncoder(w).Encode(ghRelease{TagName: "v9.9.9", Assets: []releaseAsset{
				{Name: targetAsset(), BrowserDownloadURL: "http://" + r.Host + "/bin"},
				{Name: targetAsset() + ".sha256", BrowserDownloadURL: "http://" + r.Host + "/bin.sha256"},
				{Name: targetAsset() + ".sig", BrowserDownloadURL: "http://" + r.Host + "/bin.sig"},
			}})
		case "/bin":
			w.Header().Set("Content-Type", "application/octet-stream")
			io.WriteString(w, bin)
		case "/bin.sha256":
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, upperHex+"\n")
		case "/bin.sig":
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, sigHex)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	oldBase := releaseBase
	releaseBase = srv.URL + "/releases"
	oldVer := Version
	Version = "v0.0.1"
	t.Cleanup(func() {
		releaseBase = oldBase
		Version = oldVer
	})

	before := tempLeakBefore()
	code, out := captureStderr(t, func() int { return runUpdate([]string{}) })
	if code != 1 {
		t.Fatalf("runUpdate = %d, want 1 (mismatch refusal): %s", code, out)
	}
	if strings.Contains(out, "no trusted SHA-256") {
		t.Fatalf("uppercase sidecar was refused instead of accepted: %s", out)
	}
	if !strings.Contains(out, "SHA-256 MISMATCH") {
		t.Fatalf("run did not reach the mismatch check: %s", out)
	}
	// The mismatch line prints "expected <digest>" — it must be the
	// sidecar's digest normalized to lowercase.
	wantLine := "expected " + hex.EncodeToString(other[:])
	if !strings.Contains(out, wantLine) {
		t.Fatalf("mismatch did not use the normalized uppercase sidecar: %s", out)
	}
	if leaked := tempLeakAfter(before); len(leaked) != 0 {
		t.Fatalf("orphaned temp files: %v", leaked)
	}
}

// TestUnitEnvVarFakeUnit pins the F16 fallback (2026-10-19 review): with an
// empty shell env, the CLI reads PULSEMON_ADDR / PULSEMON_DB from the
// pulsemon unit's Environment= lines (user unit first), and shell env still
// wins when set.
func TestUnitEnvVarFakeUnit(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PULSEMON_ADDR", "")
	t.Setenv("PULSEMON_DB", "")

	u := filepath.Join(home, ".config/systemd/user")
	if err := os.MkdirAll(u, 0o755); err != nil {
		t.Fatal(err)
	}
	unit := "[Unit]\nDescription=pulsemon\n[Service]\nEnvironment=\"PULSEMON_ADDR=:9333\"\nEnvironment=PULSEMON_DB=/tmp/pm/fake.db OTHER=1\nExecStart=/usr/bin/pulsemon\n"
	if err := os.WriteFile(filepath.Join(u, "pulsemon.service"), []byte(unit), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := unitEnvVar("PULSEMON_ADDR"); got != ":9333" {
		t.Errorf("unitEnvVar(PULSEMON_ADDR) = %q, want %q (quoted form)", got, ":9333")
	}
	if got := unitEnvVar("PULSEMON_DB"); got != "/tmp/pm/fake.db" {
		t.Errorf("unitEnvVar(PULSEMON_DB) = %q, want %q (space-separated list)", got, "/tmp/pm/fake.db")
	}
	if got := unitEnvVar("OTHER"); got != "1" {
		t.Errorf("unitEnvVar(OTHER) = %q, want %q", got, "1")
	}

	// healthzHostPort must reflect the unit's port when the shell env is empty.
	if h, p := healthzHostPort(); h != "localhost" || p != "9333" {
		t.Errorf("healthzHostPort = (%q, %q), want (localhost, 9333)", h, p)
	}

	// Shell env wins over the unit.
	t.Setenv("PULSEMON_ADDR", "127.0.0.1:9444")
	if h, p := healthzHostPort(); h != "127.0.0.1" || p != "9444" {
		t.Errorf("shell-env precedence broken: (%q, %q)", h, p)
	}

	// healthzDBPath: unit fallback when the shell env is empty.
	if got := healthzDBPath(); got != "/tmp/pm/fake.db" {
		t.Errorf("healthzDBPath = %q, want the unit's path", got)
	}
}

// TestNewerReleasePreReleaseOrdering pins the F17 semver ordering: a final
// release is newer than its own pre-release, pre-releases order among
// themselves, and plain version ordering is unchanged.
func TestNewerReleasePreReleaseOrdering(t *testing.T) {
	cases := []struct {
		release, running string
		want             bool
	}{
		{"v0.4.0", "v0.4.0-rc1", true},  // final beats its own rc (the F17 bug)
		{"v0.4.0-rc1", "v0.3.19", true}, // rc is still newer than the prior release
		{"v0.4.0-rc1", "v0.4.0", false}, // never a "newer" downgrade
		{"v0.4.0-rc2", "v0.4.0-rc1", true},
		{"v0.4.0-rc1", "v0.4.0-rc2", false},
		{"v0.4.0-beta.2", "v0.4.0-beta.10", false}, // numeric ids compare as integers
		{"v0.4.0-alpha", "v0.4.0-1", true},         // numeric sorts below alphanumeric
		{"v0.4.1", "v0.4.0-rc9", true},
		{"v0.4.0", "v0.4.0", false},
		{"v0.4.0", "dev", true},
		{"v0.4.0", "not-a-version", true},
	}
	for _, c := range cases {
		if got := newerRelease(c.release, c.running); got != c.want {
			t.Errorf("newerRelease(%q, %q) = %v, want %v", c.release, c.running, got, c.want)
		}
	}
}

// TestUpdateLockSecondAcquireRejected pins F19: the cross-process update
// lock is exclusive — a second acquire (another process, or a second
// in-process handle) gets errUpdateLockHeld, and releasing the first
// allows the next acquire.
func TestUpdateLockSecondAcquireRejected(t *testing.T) {
	t.Setenv("PULSEMON_DB", filepath.Join(t.TempDir(), "pulsemon.db"))

	f1, err := acquireUpdateLock()
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	_, err = acquireUpdateLock()
	if !errors.Is(err, errUpdateLockHeld) {
		t.Fatalf("second acquire = %v, want errUpdateLockHeld", err)
	}
	f1.Close()

	f2, err := acquireUpdateLock()
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	f2.Close()
}

// TestWatchdogRestoresPrevOnUnhealthy pins I2: with no healthy service
// answering, the watchdog restores <prev> over <dst>.
func TestWatchdogRestoresPrevOnUnhealthy(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("PULSEMON_DB", filepath.Join(tmp, "x.db"))
	// Port 1 is closed: every healthz candidate fails fast.
	t.Setenv("PULSEMON_ADDR", "127.0.0.1:1")

	prev := filepath.Join(tmp, "pulsemon.prev")
	dst := filepath.Join(tmp, "pulsemon")
	if err := os.WriteFile(prev, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("NEW"), 0o755); err != nil {
		t.Fatal(err)
	}

	oD, oP := detectRestart, performRestart
	detectRestart = func() string { return "" } // no live service in the test
	performRestart = func(string) error { return nil }
	defer func() { detectRestart, performRestart = oD, oP }()

	code := runWatchdog(prev, dst, 2*time.Second, 0)
	if code != 0 {
		t.Fatalf("runWatchdog exit = %d, want 0 (rollback succeeded)", code)
	}
	b, _ := os.ReadFile(dst)
	if string(b) != "OLD" {
		t.Errorf("dst = %q, want the previous binary (OLD) restored", b)
	}
}

// TestWatchdogNoopWhenHealthy pins I2's success path: a healthy service
// means the watchdog leaves the new binary in place.
func TestWatchdogNoopWhenHealthy(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("PULSEMON_DB", filepath.Join(tmp, "x.db"))

	hz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","version":"v9.9.9"}`))
	}))
	defer hz.Close()
	t.Setenv("PULSEMON_ADDR", strings.TrimPrefix(hz.URL, "http://"))

	prev := filepath.Join(tmp, "pulsemon.prev")
	dst := filepath.Join(tmp, "pulsemon")
	if err := os.WriteFile(prev, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("NEW"), 0o755); err != nil {
		t.Fatal(err)
	}

	oD := detectRestart
	detectRestart = func() string { return "" }
	defer func() { detectRestart = oD }()

	code := runWatchdog(prev, dst, 3*time.Second, 0)
	if code != 0 {
		t.Fatalf("runWatchdog exit = %d, want 0 (healthy)", code)
	}
	b, _ := os.ReadFile(dst)
	if string(b) != "NEW" {
		t.Errorf("dst = %q, want the new binary untouched (NEW)", b)
	}
}
