package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestHotReloadCertSizeFingerprint pins the size half of finding #7: a repair
// that lands with the SAME mtime as the broken state (in-place write inside
// one coarse mtime tick) must be picked up as soon as the file SIZE differs.
// mtime-only fingerprinting (the old code) pins the last-good pair forever
// here — the half-written stat and the final write share a tick, so the
// "retry on change" trigger never fires.
func TestHotReloadCertSizeFingerprint(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeTestCertPEM(t, certPath, keyPath)

	get := hotReloadCert(certPath, keyPath)
	c1, err := get(nil)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	keyMT := statMT(t, keyPath)

	// Break the cert at a fixed mtime T.
	broken := time.Now().Add(time.Hour)
	if err := os.WriteFile(certPath, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(certPath, time.Time{}, broken); err != nil {
		t.Fatal(err)
	}
	if c, err := get(nil); err != nil || !sameCert(c, c1) {
		t.Fatalf("broken reload must keep the last good pair, got err=%v", err)
	}

	// Repair in place: new pair, cert mtime forced back to the SAME tick,
	// key rewritten (writeTestCertPEM) then its mtime + content fingerprint
	// restored. Only the cert SIZE changed.
	writeTestCertPEM(t, certPath, keyPath)
	if err := os.Chtimes(certPath, time.Time{}, broken); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(keyPath, time.Time{}, keyMT); err != nil {
		t.Fatal(err)
	}
	c2, err := get(nil)
	if err != nil {
		t.Fatalf("reload after same-tick repair: %v", err)
	}
	if sameCert(c1, c2) {
		t.Fatal("same-tick repair (size changed, mtime unchanged) was not picked up — the fingerprint must include size")
	}
}

// TestHotReloadCertBackoffRecoversSameTickSameSize pins the backoff half of
// finding #7: a repair that lands in the same mtime tick AND keeps the same
// file size is invisible to the (mtime, size) fingerprint. certReloadRetry
// must re-attempt the reload on the backoff even with an unchanged
// fingerprint, so a renewal cannot be pinned out forever.
func TestHotReloadCertBackoffRecoversSameTickSameSize(t *testing.T) {
	oldRetry := certReloadRetry
	certReloadRetry = 30 * time.Millisecond
	defer func() { certReloadRetry = oldRetry }()

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeTestCertPEM(t, certPath, keyPath)

	get := hotReloadCert(certPath, keyPath)
	c1, err := get(nil)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	keyMT := statMT(t, keyPath)

	// Generate the renewal pair in a sibling dir and capture its bytes.
	dir2 := t.TempDir()
	c2Path := filepath.Join(dir2, "cert.pem")
	k2Path := filepath.Join(dir2, "key.pem")
	writeTestCertPEM(t, c2Path, k2Path)
	newCert, err := os.ReadFile(c2Path)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := os.ReadFile(k2Path)
	if err != nil {
		t.Fatal(err)
	}

	// Break the cert IN PLACE with content padded to the renewal's exact
	// size, at a fixed mtime T. The failed reload records fp(T, len(newCert)).
	tick := time.Now().Add(time.Hour)
	garbage := "garbage" + strings.Repeat("\n", len(newCert)-len("garbage"))
	if err := os.WriteFile(certPath, []byte(garbage), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(certPath, time.Time{}, tick); err != nil {
		t.Fatal(err)
	}
	if c, err := get(nil); err != nil || !sameCert(c, c1) {
		t.Fatalf("broken reload must keep the last good pair, got err=%v", err)
	}

	// The renewal lands INSIDE THE SAME TICK, same size: the fingerprint
	// cannot see it.
	if err := os.WriteFile(certPath, newCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, newKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(certPath, time.Time{}, tick); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(keyPath, time.Time{}, keyMT); err != nil {
		t.Fatal(err)
	}

	// Inside the backoff: fast cached path (no reload churn per handshake).
	if c, err := get(nil); err != nil || !sameCert(c, c1) {
		t.Fatal("inside the backoff window the cached pair must be served without reload")
	}

	// After the backoff: the renewal is picked up even though the
	// fingerprint NEVER changed.
	time.Sleep(50 * time.Millisecond)
	c2, err := get(nil)
	if err != nil {
		t.Fatalf("reload after backoff: %v", err)
	}
	if sameCert(c1, c2) {
		t.Fatal("same-tick, same-size repair pinned the old pair forever — the failed reload must be re-attempted on the certReloadRetry backoff")
	}
}

func statMT(t *testing.T, path string) time.Time {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.ModTime()
}
