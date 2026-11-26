package main

// NIT-28 pins: updater transport hardening (redirect guard), staged-file
// Chown before the swap, destination-volume staging, and private modes for
// the /tmp lock fallback and the watchdog log.
// History: docs/DECISIONS.md → updater-transport-and-lock-hardening.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestReleaseCheckRedirectPolicy: the updater's redirect guard accepts only
// HTTPS on GitHub release hosts — a 302 to cleartext or to an internal
// host (a compromised CDN edge / MITM vector) must be refused before any
// bytes are installed.
func TestReleaseCheckRedirectPolicy(t *testing.T) {
	allowed := []string{
		"https://api.github.com/repos/x/y/releases/latest",
		"https://github.com/invizen/pulsemon/releases/download/v1/pulsemon",
		"https://objects.githubusercontent.com/assets/123",
		"https://codeload.github.com/invizen/pulsemon/legacy.zip",
	}
	for _, u := range allowed {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := releaseCheckRedirect(req, []*http.Request{{}}); err != nil {
			t.Errorf("releaseCheckRedirect(%s) = %v; want nil", u, err)
		}
	}
	refused := []string{
		"http://api.github.com/repos/x/y/releases/latest", // cleartext downgrade
		"https://evil.example.com/steal",                  // off-GitHub host
		"https://192.168.1.1/internal",                    // internal host
		"https://github.com.evil.com/lookalike",           // lookalike suffix
		"http://objects.githubusercontent.com/assets/123", // cleartext CDN
	}
	for _, u := range refused {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := releaseCheckRedirect(req, []*http.Request{{}}); err == nil {
			t.Errorf("releaseCheckRedirect(%s) = nil; want refusal", u)
		}
	}
}

// TestUpdaterClientWiresRedirectGuard: the runUpdate client literal must
// carry the guard (a bare http.Client silently means DefaultTransport,
// which follows any redirect).
func TestUpdaterClientWiresRedirectGuard(t *testing.T) {
	fn, ok := funcBody(stripGoComments(readSource(t, "update.go")), "runUpdate")
	if !ok {
		t.Fatal("runUpdate not found in update.go")
	}
	if !strings.Contains(fn, "CheckRedirect: releaseCheckRedirect") {
		t.Fatal("runUpdate's http.Client must set CheckRedirect: releaseCheckRedirect")
	}
}

// TestDownloadAssetStagesInTargetDir: the asset must land in the caller's
// staging dir (the binary's own volume) — not /tmp — so the install is not
// a second full copy of a up-to-512 MiB file across devices.
func TestDownloadAssetStagesInTargetDir(t *testing.T) {
	payload := []byte("fake release binary bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, string(payload))
	}))
	defer srv.Close()

	dir := t.TempDir()
	client := &http.Client{CheckRedirect: releaseCheckRedirect}
	got, err := downloadAsset(client, srv.URL+"/asset", dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(got)
	if filepath.Dir(got) != dir {
		t.Fatalf("staged in %s; want %s (destination volume, not /tmp)", filepath.Dir(got), dir)
	}
	b, err := os.ReadFile(got)
	if err != nil || string(b) != string(payload) {
		t.Fatalf("staged content = %q, err=%v; want the payload", b, err)
	}
}

// TestInstallBinaryChownsStagedBeforeSwap: ownership must be restored on
// the STAGED file before the rename (a failed post-swap chown leaves a live
// binary with the wrong owner), and the post-swap os.Chown(dst) must be gone.
func TestInstallBinaryChownsStagedBeforeSwap(t *testing.T) {
	fn, ok := funcBody(stripGoComments(readSource(t, "update.go")), "installBinary")
	if !ok {
		t.Fatal("installBinary not found in update.go")
	}
	chownAt := strings.Index(fn, "tmp.Chown(")
	swapAt := strings.Index(fn, "swapBinary(")
	if chownAt < 0 || swapAt < 0 || chownAt > swapAt {
		t.Fatalf("installBinary: tmp.Chown at %d, swapBinary at %d; want the staged chown BEFORE the swap", chownAt, swapAt)
	}
	if strings.Contains(fn, "os.Chown(dst") {
		t.Fatal("installBinary still chowns the destination AFTER the swap — must chown the staged file before the rename")
	}
}

// TestUpdateLockAndWatchdogLogModes: the /tmp lock fallback and the
// watchdog log must be created 0600 (a 0644 lock in world-writable /tmp is
// probeable/tamperable by local users; the log carries update findings).
func TestUpdateLockAndWatchdogLogModes(t *testing.T) {
	lockSrc := readSource(t, "update_lock.go")
	if !regexp.MustCompile(`os\.OpenFile\(lockPath, os\.O_CREATE\|os\.O_RDWR, 0o600\)`).MatchString(lockSrc) {
		t.Fatal("update lock must be opened 0o600 (world-writable /tmp fallback)")
	}
	updSrc := readSource(t, "update.go")
	if !regexp.MustCompile(`pulsemon-watchdog\.log"\),\s*os\.O_CREATE\|os\.O_APPEND\|os\.O_WRONLY, 0o600\)`).MatchString(updSrc) {
		t.Fatal("pulsemon-watchdog.log must be created 0o600")
	}
}
