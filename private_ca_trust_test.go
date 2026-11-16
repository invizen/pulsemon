package main

// Private-CA trust for HTTPS sensors: the documented SSL_CERT_FILE path.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestProbeHTTPPrivateCAFile pins the supported private-CA path
// end-to-end: a CA-signed (NOT self-signed) leaf reads as a loss by
// default, and PULSEMON_CA_FILE pointing at the CA bundle flips the
// verdict to UP — the mechanism README documents for step-ca-style
// internal roots, including inside the FROM scratch image (no /etc/ssl
// at all: the bundle IS the probe trust store). The same test asserts
// both directions, so only the bundle can be what flipped it.
func TestProbeHTTPPrivateCAFile(t *testing.T) {
	notAfter := time.Now().Add(48 * time.Hour)

	// CA + CA-signed leaf valid for 127.0.0.1 (mirrors testTLSChain, plus
	// the CA PEM we need on disk).
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pulsemon private CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "pulsemon private-CA leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	srv.StartTLS()
	defer srv.Close()

	// 1. Without the bundle: CA-signed, not self-signed -> loss (the
	// exact path step-ca users hit today).
	if r := probeHTTP(context.Background(), srv.URL, 5*time.Second); !r.Lost {
		t.Fatal("CA-signed cert without a trust bundle read UP; the default probe trust store must not know this CA")
	}

	// 2. Same probe, CA bundle published via SSL_CERT_FILE -> UP.
	bundle := filepath.Join(t.TempDir(), "ca-bundle.pem")
	if err := os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PULSEMON_CA_FILE", bundle)
	if err := initProbeCA(); err != nil {
		t.Fatalf("initProbeCA: %v", err)
	}
	t.Cleanup(func() { probeCAPool = nil })
	if r := probeHTTP(context.Background(), srv.URL, 5*time.Second); r.Lost {
		t.Fatalf("private-CA sensor with PULSEMON_CA_FILE=%s read lost (err=%v): the documented trust path is broken", bundle, r.Err)
	}
	// Loud failure on a bundle with no certificates (fail-loud contract).
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PULSEMON_CA_FILE", empty)
	if err := initProbeCA(); err == nil {
		t.Fatal("initProbeCA accepted a bundle with no certificates")
	}
}
