package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// makeTestCert generates a self-signed cert + key for tests.
func makeTestCert(t *testing.T, keyType string) (certPEM, keyPEM string, keyTypePEM string) {
	t.Helper()
	var (
		priv any
		der  []byte
		kt   string
	)
	switch keyType {
	case "rsa":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		priv = k
		der, err = x509.MarshalPKCS8PrivateKey(k)
		kt = "PRIVATE KEY"
	case "ec":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		priv = k
		der, err = x509.MarshalPKCS8PrivateKey(k)
		kt = "PRIVATE KEY"
	default:
		t.Fatalf("unknown key type %q", keyType)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.pulsemon"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pubKeyFromAny(priv), priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: kt, Bytes: der}))
	return certPEM, keyPEM, kt
}

func TestTLSValidatePair(t *testing.T) {
	certPEM, keyPEM, _ := makeTestCert(t, "rsa")

	// 1. Happy path: PEM with headers.
	if _, err := tlsValidatePair(certPEM, keyPEM); err != nil {
		t.Errorf("PEM pair: %v", err)
	}

	// 2. Raw base64 DER (no headers) — the user's format.
	certBlock, _ := pem.Decode([]byte(certPEM))
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if _, err := tlsValidatePair(base64.StdEncoding.EncodeToString(certBlock.Bytes), base64.StdEncoding.EncodeToString(keyBlock.Bytes)); err != nil {
		t.Errorf("raw base64 pair: %v", err)
	}

	// 3. Base64 of the PEM text.
	if _, err := tlsValidatePair(base64.StdEncoding.EncodeToString([]byte(certPEM)), base64.StdEncoding.EncodeToString([]byte(keyPEM))); err != nil {
		t.Errorf("base64-of-PEM pair: %v", err)
	}

	// 4. Mismatched pair: cert from one key, key from another.
	otherCert, otherKey, _ := makeTestCert(t, "ec")
	if _, err := tlsValidatePair(certPEM, otherKey); err == nil {
		t.Error("mismatched pair: expected error, got nil")
	}
	_ = otherCert

	// 5. Garbage input.
	if _, err := tlsValidatePair("not a cert", keyPEM); err == nil {
		t.Error("garbage cert: expected error")
	}
	if _, err := tlsValidatePair(certPEM, "not a key"); err == nil {
		t.Error("garbage key: expected error")
	}
}

func TestParsePort(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
		err  bool
	}{
		{"443", 443, false}, {"80", 80, false}, {"65535", 65535, false},
		{"0", 0, true}, {"65536", 0, true}, {"abc", 0, true}, {"", 0, true},
	} {
		got, err := parsePort(tc.in)
		if tc.err && err == nil {
			t.Errorf("parsePort(%q): expected error", tc.in)
		}
		if !tc.err && (err != nil || got != tc.want) {
			t.Errorf("parsePort(%q) = %d, %v; want %d", tc.in, got, err, tc.want)
		}
	}
}
