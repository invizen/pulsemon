//go:build linux

package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"pulsemon/internal/store"
)

// newTLSTestServer builds a Server whose PULSEMON_DB (and therefore
// tlsDir) points at a fresh temp dir, with the restart side effects
// stubbed so the handlers' delayed `go requestRestart()` is inert.
func newTLSTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "pulsemon.db")
	t.Setenv("PULSEMON_DB", dbPath)
	db, err := store.NewStore(dbPath)
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	setRestartFnsForTest(func() error { return nil }, func() {})
	return NewServer(db, NewProbeWorker(db)), tlsDir(db)
}

func tlsPut(srv *Server, t *testing.T, cert, key string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"cert": cert, "key": key})
	req := httptest.NewRequest(http.MethodPost, "/api/settings/tls", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	srv.handleTLSSettingsPut(rec, req)
	return rec.Code
}

func tlsDelete(srv *Server, t *testing.T) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/api/settings/tls", nil)
	rec := httptest.NewRecorder()
	srv.handleTLSSettingsDelete(rec, req)
	return rec.Code
}

// TestTLSConcurrentInstallAndRemoveStayConsistent is the F15 regression:
// concurrent POST/DELETE /api/settings/tls were unsynchronized — a
// DELETE's os.Remove interleaved with a PUT's renames left a mismatched
// or half-installed pair on disk (certFatal at the next boot). The
// deterministic round stops the install between the key and cert
// renames (tlsInstallBetweenRenames barrier) and runs a DELETE in that
// window: without the mutex the DELETE proceeds and the resumed install
// leaves exactly ONE of cert.pem/key.pem behind; with the mutex the
// DELETE blocks until the install is atomic and complete. Randomized
// rounds add coverage for other interleavings.
func TestTLSConcurrentInstallAndRemoveStayConsistent(t *testing.T) {
	srv, tlsDirPath := newTLSTestServer(t)
	certA, keyA, _ := makeTestCert(t, "rsa")
	certB, keyB, _ := makeTestCert(t, "ec")

	certName, keyName := filepath.Join(tlsDirPath, "cert.pem"), filepath.Join(tlsDirPath, "key.pem")
	assertConsistent := func(round string) {
		t.Helper()
		certOnDisk, certErr := os.ReadFile(certName)
		keyOnDisk, keyErr := os.ReadFile(keyName)
		switch {
		case certErr == nil && keyErr == nil:
			if _, err := tls.X509KeyPair(certOnDisk, keyOnDisk); err != nil {
				t.Fatalf("%s: mismatched pair on disk (certA+keyB would certFatal at boot): %v", round, err)
			}
		case (certErr == nil) != (keyErr == nil):
			t.Fatalf("%s: exactly one of cert.pem/key.pem present (cert: %v, key: %v)", round, certErr, keyErr)
		}
	}

	if code := tlsPut(srv, t, certA, keyA); code != http.StatusOK {
		t.Fatalf("seed PUT: status %d", code)
	}

	// Deterministic interleave: pause the install between the two
	// renames, run a DELETE in that window, resume.
	//
	// Locked code: the DELETE blocks on tlsSettingsMu until the install
	// finishes and releases it, so it always removes the COMPLETE pair →
	// both files absent. Unlocked code: the DELETE's two non-atomic
	// removes (cert then key) straddle the resumed cert rename → exactly
	// ONE of cert.pem/key.pem is left behind.
	keySwapped, proceed := make(chan struct{}), make(chan struct{})
	origBetween := tlsInstallBetweenRenames
	tlsInstallBetweenRenames = func() {
		close(keySwapped)
		<-proceed
	}
	t.Cleanup(func() { tlsInstallBetweenRenames = origBetween })
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); tlsPut(srv, t, certB, keyB) }()
	<-keySwapped // keyB is on disk, certB is not — the window is open
	go func() { defer wg.Done(); tlsDelete(srv, t) }()
	// Consume the window before resuming the install. Unlocked code: the
	// DELETE runs its cert-removal DURING the window, so cert.pem
	// disappears and the poll breaks fast. Locked code: the DELETE is
	// blocked on tlsSettingsMu, cert.pem stays, and the poll times out.
	// Either way, close(proceed) only fires AFTER the DELETE has (unlocked)
	// or has not (locked) removed the cert — making the outcome
	// deterministic per build.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, e := os.Stat(certName); e != nil {
			break // unlocked: the DELETE removed cert.pem in the window
		}
		time.Sleep(2 * time.Millisecond)
	}
	close(proceed) // resume the install (or let the blocked DELETE finish)
	wg.Wait()
	assertConsistent("deterministic round")
	// The barrier is single-shot (close of closed channel on a second
	// install): restore before the randomized rounds.
	tlsInstallBetweenRenames = origBetween

	// Randomized rounds: race a re-install against a removal.
	for round := 0; round < 15; round++ {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); tlsPut(srv, t, certB, keyB) }()
		go func() { defer wg.Done(); tlsDelete(srv, t) }()
		wg.Wait()
		assertConsistent(fmt.Sprintf("round %d", round))
	}
}

// openFileLinks returns the target of every open fd of this process
// (Linux /proc/self/fd) — used to observe "file is still open" from the
// remove interceptor.
func openFileLinks() map[string]bool {
	links := make(map[string]bool)
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return links
	}
	for _, e := range entries {
		if link, err := os.Readlink("/proc/self/fd/" + e.Name()); err == nil {
			links[link] = true
		}
	}
	return links
}

// TestTLSInstallFailureClosesTempBeforeRemove is the F15 Windows
// temp-key-leak regression: the install-failure cleanup used to call
// os.Remove while the temp files were still open (deferred Close) — on
// Windows that Remove is a sharing violation and the .key.pem.tmp
// residue (PRIVATE KEY material) is left on disk. The creator is
// injected to return a read-only file (so the install's Write fails,
// driving the cleanup path), and the remover records whether the file
// is still open when it is removed.
func TestTLSInstallFailureClosesTempBeforeRemove(t *testing.T) {
	srv, tlsDirPath := newTLSTestServer(t)

	origCreateTemp, origRemoveTemp := tlsCreateTemp, tlsRemoveTemp
	var mu sync.Mutex
	var violations []string
	tlsCreateTemp = func(dir, pattern string) (*os.File, error) {
		f, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		name := f.Name()
		f.Close()
		// Read-only: the install's Write fails, so the cleanup path
		// runs with the file handle still open (the Windows failure
		// mode).
		return os.OpenFile(name, os.O_RDONLY, 0)
	}
	tlsRemoveTemp = func(name string) error {
		mu.Lock()
		if openFileLinks()[name] {
			violations = append(violations, name)
		}
		mu.Unlock()
		return os.Remove(name)
	}
	t.Cleanup(func() { tlsCreateTemp, tlsRemoveTemp = origCreateTemp, origRemoveTemp })

	cert, key, _ := makeTestCert(t, "rsa")
	if code := tlsPut(srv, t, cert, key); code != http.StatusInternalServerError {
		t.Fatalf("expected 500 from failing install, got %d", code)
	}

	if len(violations) > 0 {
		t.Fatalf("temp file(s) removed while still open: %v — on Windows this is a sharing violation and the residue is left on disk", violations)
	}
	entries, err := os.ReadDir(tlsDirPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("temp residue left in tls dir: %s", e.Name())
		}
	}
}

// TestAuthUserHardensDataDirBeforeFirstBoot is the F15 umask-bypass
// regression: runAuthUser opened the store before runServer's
// ensureDataDir ran, skipping the umask(0o077) + file-tightening pass —
// `pulsemon auth-user add` before first boot (or while the service is
// stopped) created 0644 world-readable pulsemon.db/-wal/-shm holding
// bcrypt hashes and webhook/SMTP secrets on multi-user Linux hosts.
func TestAuthUserHardensDataDirBeforeFirstBoot(t *testing.T) {
	// Simulate a typical interactive umask; restore it after (the fix
	// sets the process umask to 0o077).
	prev := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(prev) })

	dbPath := filepath.Join(t.TempDir(), "pulsemon.db")
	t.Setenv("PULSEMON_DB", dbPath)

	if rc := dispatch([]string{"pulsemon", "auth-user", "add", "umaskpin", "secret-umask-1"}); rc != dExit0 {
		t.Fatalf("auth-user add rc=%v, want dExit0", rc)
	}
	fi, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("pulsemon.db mode = %o, want 0600 (a world-readable secret store)", got)
	}
}
