package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fixSelfSignedCert builds a self-signed cert for ip with the given
// BasicConstraints / KeyUsage shape (the 9-shape matrix from the review).
func fixSelfSignedCert(t *testing.T, bcValid, isCA bool, ku x509.KeyUsage, ip net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "pulsemon-fix"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: ku, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{ip}, BasicConstraintsValid: bcValid, IsCA: isCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestFix_M6_SelfSignedShapes pins the M6(a) fix: the old gate
// (leaf.CheckSignatureFrom(leaf)) demanded CA:TRUE plus a certSign-able key
// usage, so only 2 of the 9 real-world self-signed shapes were accepted —
// the common homelab shapes (CA:FALSE, digSig+keyEnc) got FALSE DOWN. The
// fix accepts a cert when issuer==subject AND the signature verifies with
// the leaf's OWN key, then the existing exact-hostname verify runs.
func TestFix_M6_SelfSignedShapes(t *testing.T) {
	ip := net.ParseIP("192.168.1.50")
	type bcv struct {
		n    string
		v    bool
		isCA bool
	}
	type kuv struct {
		n  string
		ku x509.KeyUsage
	}
	for _, b := range []bcv{
		{"no-BC-ext", false, false},
		{"CA:FALSE", true, false},
		{"CA:TRUE", true, true},
	} {
		for _, k := range []kuv{
			{"no-KU", 0},
			{"KU=digSig+keyEnc", x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment},
			{"KU=digSig+certSign", x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign},
		} {
			crt := fixSelfSignedCert(t, b.v, b.isCA, k.ku, ip)
			leaf, err := x509.ParseCertificate(crt.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyHTTPCert([]*x509.Certificate{leaf}, ip.String()); err != nil {
				t.Errorf("SELFSIGNED %-10s %-20s => REJECT (%v), want ACCEPT (real self-signed server cert shape)", b.n, k.n, err)
			}
		}
	}

	// Forged cert: the SAME subject/issuer names as a self-signed cert for
	// the target, but signed by a DIFFERENT key. issuer==subject holds, so
	// the name equality alone must not be enough — the signature must verify
	// with the leaf's own key. REJECT.
	name := pkix.Name{CommonName: "pulsemon-fix"}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: name, Issuer: name,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: name,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{ip},
	}
	forgedDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := x509.ParseCertificate(forgedDER)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(forged.RawIssuer, forged.RawSubject) {
		t.Fatalf("test setup: forged cert must have issuer==subject names")
	}
	if err := verifyHTTPCert([]*x509.Certificate{forged}, ip.String()); err == nil {
		t.Error("FORGED cert (same names, signed by a different key) was ACCEPTED — the self-signed gate must verify the signature with the leaf's own key")
	}

	// The exact-hostname rule on the self-signed path must stay: a
	// self-signed cert for a DIFFERENT ip is still a reject.
	other := fixSelfSignedCert(t, true, false, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, net.ParseIP("10.1.2.3"))
	otherLeaf, _ := x509.ParseCertificate(other.Certificate[0])
	if err := verifyHTTPCert([]*x509.Certificate{otherLeaf}, ip.String()); err == nil {
		t.Error("self-signed cert for a different ip was ACCEPTED for this target — exact match must be preserved")
	}
}

// fixLanIP returns this machine's private IPv4, or skips the test.
func fixLanIP(t *testing.T) net.IP {
	t.Helper()
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() && ipn.IP.IsPrivate() {
			return ipn.IP.To4()
		}
	}
	t.Skip("no private LAN ip available")
	return nil
}

// TestFix_M6_CrossHostRedirectVerifiesFinalHost pins the M6(b) fix: after a
// redirect, the presented cert belongs to the FINAL hop, but the old code
// verified it against the ORIGINAL target host — a valid self-signed cert
// for the final host was a FALSE DOWN (repro: http://127.0.0.1:A -> 302 ->
// https://<lan-ip>:B, cert valid for <lan-ip>, Lost=true). The fix verifies
// against the final request's host.
func TestFix_M6_CrossHostRedirectVerifiesFinalHost(t *testing.T) {
	lan := fixLanIP(t)

	// B: HTTPS on the LAN ip, cert valid for exactly that IP.
	b := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	b.Listener = ln
	b.TLS = &tls.Config{Certificates: []tls.Certificate{
		fixSelfSignedCert(t, true, true, x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign, lan),
	}}
	b.StartTLS()
	defer b.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	bURL := fmt.Sprintf("https://%s:%d/", lan, port)

	// Control: probing B directly works (cert is valid for B).
	r0 := probeHTTP(context.Background(), bURL, 5*time.Second)
	if r0.Lost {
		t.Fatalf("control: direct probe of B lost: %v", r0.Err)
	}

	// A: plain HTTP on loopback that 302s to B (a different host — the
	// redirect guard allows RFC1918 cross-host hops).
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, bURL, 302)
	}))
	defer a.Close()
	r1 := probeHTTP(context.Background(), a.URL+"/", 5*time.Second)
	if r1.Lost {
		t.Errorf("redirect A(127.0.0.1) -> B(https, valid self-signed cert for %s): lost=%v status=%v err=%v — the cert must be verified against the FINAL host, not the original",
			lan, r1.Lost, r1.Status, r1.Err)
	}
}
