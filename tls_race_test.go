//go:build linux

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
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
	origTestBind := tlsTestBind
	tlsTestBind = func(network, addr string) error { return nil }
	t.Cleanup(func() { tlsTestBind = origTestBind })
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

func tlsPutWithPort(srv *Server, t *testing.T, cert, key string, port int) int {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"cert": cert, "key": key, "port": port})
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

// makeExpiredCertPEM generates a self-signed RSA pair whose validity
// window is entirely in the past (the MAJOR-10 expiry pin input).
func makeExpiredCertPEM(t *testing.T) (string, string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "expired.pulsemon"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	return certPEM, keyPEM
}

// TestTLSUploadExpiredCertRejected is the MAJOR-10 expiry pin:
// tlsValidatePair parsed the cert and matched the key but never checked
// NotAfter, so an already-expired pair was installed, the process
// restarted, and every TLS client failed the handshake while the
// dashboard showed a confident cert_expiry in the past.
func TestTLSUploadExpiredCertRejected(t *testing.T) {
	certPEM, keyPEM := makeExpiredCertPEM(t)

	if _, err := tlsValidatePair(certPEM, keyPEM); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired cert accepted (err=%v), want an 'expired' rejection", err)
	}

	srv, tlsDirPath := newTLSTestServer(t)
	if code := tlsPutWithPort(srv, t, certPEM, keyPEM, 8443); code != http.StatusBadRequest {
		t.Fatalf("expired-cert PUT = %d, want 400", code)
	}
	for _, n := range []string{"cert.pem", "key.pem"} {
		if _, err := os.Stat(filepath.Join(tlsDirPath, n)); err == nil {
			t.Errorf("%s written for an expired cert", n)
		}
	}
	if p := srv.db.GetSetting("listener_https_port"); p != "" {
		t.Errorf("listener_https_port = %q, want unset", p)
	}
}

// TestTLSUploadEnvSourceConflict is the MAJOR-10 env-guard pin: DELETE
// refused to clobber an env-provided pair (409), but PUT had no such
// guard — it wrote an UNUSED key to disk and restarted the process
// while PULSEMON_CERT kept winning at boot.
func TestTLSUploadEnvSourceConflict(t *testing.T) {
	srv, tlsDirPath := newTLSTestServer(t)
	t.Setenv("PULSEMON_CERT", filepath.Join(t.TempDir(), "env-cert.pem"))
	t.Setenv("PULSEMON_KEY", filepath.Join(t.TempDir(), "env-key.pem"))

	cert, key, _ := makeTestCert(t, "rsa")
	if code := tlsPutWithPort(srv, t, cert, key, 8443); code != http.StatusConflict {
		t.Fatalf("env-source PUT = %d, want 409", code)
	}
	for _, n := range []string{"cert.pem", "key.pem"} {
		if _, err := os.Stat(filepath.Join(tlsDirPath, n)); err == nil {
			t.Errorf("%s written while the env source is active", n)
		}
	}
	if p := srv.db.GetSetting("listener_https_port"); p != "" {
		t.Errorf("listener_https_port = %q, want unset", p)
	}
}

// TestTLSUploadUnprivilegedPortRejected is the MAJOR-10 pre-flight pin:
// the default port 443 pre-filled in Settings is unbindable on
// unprivileged installs (Docker USER 1000:1000 cap_drop ALL, install.sh
// systemd user unit) — pre-fix the PUT wrote the pair, stored 443, and
// restarted into a `bind: permission denied` crash loop. The probe must
// refuse BEFORE any file is written, for EACCES and EADDRINUSE alike.
func TestTLSUploadUnprivilegedPortRejected(t *testing.T) {
	simulate := func(cause error, wantSubstr string) {
		t.Helper()
		srv, tlsDirPath := newTLSTestServer(t)
		orig := tlsTestBind
		tlsTestBind = func(network, addr string) error {
			return &net.OpError{Op: "listen", Net: "tcp", Err: &os.SyscallError{Syscall: "bind", Err: cause}}
		}
		t.Cleanup(func() { tlsTestBind = orig })

		cert, key, _ := makeTestCert(t, "rsa")
		body, _ := json.Marshal(map[string]any{"cert": cert, "key": key, "port": 443})
		req := httptest.NewRequest(http.MethodPost, "/api/settings/tls", strings.NewReader(string(body)))
		rec := httptest.NewRecorder()
		srv.handleTLSSettingsPut(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("unbindable-port PUT (cause=%v) = %d, want 409", cause, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), wantSubstr) {
			t.Errorf("response %q does not explain the cause (%q)", rec.Body.String(), wantSubstr)
		}
		for _, n := range []string{"cert.pem", "key.pem"} {
			if _, err := os.Stat(filepath.Join(tlsDirPath, n)); err == nil {
				t.Errorf("%s written despite the unbindable port", n)
			}
		}
		if p := srv.db.GetSetting("listener_https_port"); p != "" {
			t.Errorf("listener_https_port = %q, want unset", p)
		}
	}
	simulate(syscall.EACCES, "CAP_NET_BIND_SERVICE")
	simulate(syscall.EADDRINUSE, "already in use")
}

// TestTLSUploadPreflightSkipsLivePort is the positive control for the
// MAJOR-10 pre-flight: when the process already serves HTTPS on the
// target port, the probe must NOT run (it would report EADDRINUSE by
// us and refuse a legitimate same-port re-upload).
func TestTLSUploadPreflightSkipsLivePort(t *testing.T) {
	srv, _ := newTLSTestServer(t)
	certA, keyA, _ := makeTestCert(t, "rsa")
	if code := tlsPutWithPort(srv, t, certA, keyA, 8443); code != http.StatusOK {
		t.Fatalf("seed PUT: %d", code)
	}

	orig := tlsTestBind
	probed := 0
	tlsTestBind = func(network, addr string) error { probed++; return nil }
	t.Cleanup(func() { tlsTestBind = orig })

	certB, keyB, _ := makeTestCert(t, "ec")
	if code := tlsPutWithPort(srv, t, certB, keyB, 8443); code != http.StatusOK {
		t.Fatalf("same-port re-upload = %d, want 200", code)
	}
	if probed != 0 {
		t.Fatalf("preflight probed the port the process already serves (probes=%d)", probed)
	}
}

// TestTLSUploadPortOnlyChangePreflights pins that a PORT-ONLY change
// (no pair in the body) is pre-flighted too when TLS is active: the
// restart binds the new port, so an unbindable one must be refused
// before the setting is persisted.
func TestTLSUploadPortOnlyChangePreflights(t *testing.T) {
	srv, _ := newTLSTestServer(t)
	cert, key, _ := makeTestCert(t, "rsa")
	if code := tlsPutWithPort(srv, t, cert, key, 8443); code != http.StatusOK {
		t.Fatalf("seed PUT: %d", code)
	}

	orig := tlsTestBind
	tlsTestBind = func(network, addr string) error {
		return &net.OpError{Op: "listen", Net: "tcp", Err: &os.SyscallError{Syscall: "bind", Err: syscall.EACCES}}
	}
	t.Cleanup(func() { tlsTestBind = orig })

	body, _ := json.Marshal(map[string]any{"port": 443})
	req := httptest.NewRequest(http.MethodPost, "/api/settings/tls", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	srv.handleTLSSettingsPut(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("port-only change to an unbindable port = %d, want 409", rec.Code)
	}
	if p := srv.db.GetSetting("listener_https_port"); p != "8443" {
		t.Errorf("listener_https_port = %q, want 8443 (unchanged)", p)
	}
}
