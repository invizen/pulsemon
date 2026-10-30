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
	"pulsemon/internal/store"
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

// padPEM pads a PEM string with trailing newlines to exactly targetLen bytes.
// The PEM parser (tlsX509Cert) reads the first CERTIFICATE block and ignores
// trailing data, so padding is safe. It lets a test hold the (path, mtime,
// size) memo key's size constant across two different certs — the two random
// certs otherwise differ in ECDSA signature length by a byte or two, which
// made TestTlsPayloadMemoizesOnMtime flaky in CI (2026-10-25).
func padPEM(t *testing.T, pem string, targetLen int) []byte {
	t.Helper()
	if len(pem) > targetLen {
		t.Fatalf("PEM is %d bytes, exceeds target %d (padding cannot shrink)", len(pem), targetLen)
	}
	b := []byte(pem)
	for len(b) < targetLen {
		b = append(b, '\n')
	}
	return b
}

func TestTlsPayloadMemoizesOnMtime(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pulsemon.db")
	t.Setenv("PULSEMON_DB", dbPath)
	db, err := store.NewStore(dbPath)
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
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

	// Two different certs, padded to a common size so the (path, mtime, size)
	// memo key's size is identical for both — this isolates the mtime
	// dimension. (The raw certs differ in ECDSA signature length by a byte or
	// two, which used to make this test flaky in CI.)
	alphaPEM := testCertWithCN(t, "alpha.lan")
	bravoPEM := testCertWithCN(t, "bravo.lan")
	targetLen := len(alphaPEM)
	if len(bravoPEM) > targetLen {
		targetLen = len(bravoPEM)
	}
	if err := os.WriteFile(certPath, padPEM(t, alphaPEM, targetLen), 0o600); err != nil {
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

	// Swap in the other cert (same size) and restore the original mtime:
	// unchanged mtime+size ⇒ the cached cert is served (a real upload sets a
	// new mtime AND size).
	if err := os.WriteFile(certPath, padPEM(t, bravoPEM, targetLen), 0o600); err != nil {
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
