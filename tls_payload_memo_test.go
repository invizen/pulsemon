package main

// 2026-10-24 review (n3): tlsPayload re-read and re-parsed the cert file
// on EVERY GET /api/settings. The parse result is now memoized keyed on
// (path, mtime, size): an upload rewrites the file with a new mtime, so
// the cache self-invalidates, while repeated settings reads stay free.
// This test pins the mtime contract: unchanged mtime ⇒ the cached cert
// is served even if the content changed underneath; newer mtime ⇒
// re-parse.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testCertWithCN generates a self-signed cert PEM with the given CN
// (makeTestCert in tls_validate_test.go pins the CN to test.pulsemon).
func testCertWithCN(t *testing.T, cn string) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
}

func TestTlsPayloadMemoizesOnMtime(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pulsemon.db")
	t.Setenv("PULSEMON_DB", dbPath)
	db, err := NewDB(dbPath)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	srv := NewServer(db, NewProbeWorker(db))

	certPath := filepath.Join(filepath.Dir(dbPath), "tls", "cert.pem")
	keyPath := filepath.Join(filepath.Dir(dbPath), "tls", "key.pem")
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, []byte(testCertWithCN(t, "alpha.lan")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("test-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(certPath)
	if err != nil {
		t.Fatal(err)
	}
	origMTime := fi.ModTime()

	if info := srv.tlsPayload(); info.Subject != "alpha.lan" {
		t.Fatalf("initial payload subject = %q, want alpha.lan", info.Subject)
	}

	// Swap in a different cert but restore the original mtime: a
	// memoized reader must keep serving the cached cert — the mtime is
	// the invalidation key, and a real upload would set a new one.
	if err := os.WriteFile(certPath, []byte(testCertWithCN(t, "bravo.lan")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(certPath, origMTime, origMTime); err != nil {
		t.Fatal(err)
	}
	if info := srv.tlsPayload(); info.Subject != "alpha.lan" {
		t.Fatalf("memoized payload re-read the file despite unchanged mtime: subject = %q, want alpha.lan", info.Subject)
	}

	// Advance the mtime (what an upload does) → the cache must be
	// invalidated and the new cert served.
	if err := os.Chtimes(certPath, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if info := srv.tlsPayload(); info.Subject != "bravo.lan" {
		t.Fatalf("payload after mtime change = %q, want bravo.lan", info.Subject)
	}
}
