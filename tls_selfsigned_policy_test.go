package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// selfSignedIPCert builds a genuinely self-signed cert (issuer == subject)
// whose ONLY SAN is ip, expiring 48h out — the shape an on-path attacker
// mints in milliseconds when spoofing target ip.
func selfSignedIPCert(t *testing.T, ip net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkixName("pulsemon self-signed policy test"),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IPAddresses:           []net.IP{ip},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-signed cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestVerifyHTTPCertRefusesSelfSignedWithUserinfo pins the MITM-credential
// gate: a target carrying userinfo (https://user:pass@host) must NOT be
// served by an unpinned self-signed cert. An on-path attacker minting a
// matching self-signed cert takes milliseconds, passes the exact-SAN check,
// and would harvest the Authorization: Basic *** header — the exact threat
// probeDialTLS's pre-request verification exists to stop. The control (same
// cert, same private host, NO userinfo) must stay accepted: that is the
// homelab pattern the self-signed allowance exists for.
func TestVerifyHTTPCertRefusesSelfSignedWithUserinfo(t *testing.T) {
	cert := selfSignedIPCert(t, net.ParseIP("192.168.1.50"))
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	// Control: no userinfo, private IP, valid self-signed -> accepted.
	if err := verifyHTTPCert([]*x509.Certificate{leaf}, "192.168.1.50", false); err != nil {
		t.Fatalf("control: self-signed for a private IP without userinfo rejected: %v", err)
	}
	// Credential-bearing target -> refused.
	if err := verifyHTTPCert([]*x509.Certificate{leaf}, "192.168.1.50", true); err == nil {
		t.Fatal("self-signed cert ACCEPTED for a credential-bearing target — a minted matching cert would harvest the Basic auth header")
	}
}

// TestVerifyHTTPCertRefusesSelfSignedPublicIP pins the public-IP gate: a
// self-signed cert presented on a globally routable IP is not an
// operator's device — refused even without userinfo. Private IPs keep the
// homelab acceptance.
func TestVerifyHTTPCertRefusesSelfSignedPublicIP(t *testing.T) {
	pub := selfSignedIPCert(t, net.ParseIP("93.184.216.34"))
	pubLeaf, err := x509.ParseCertificate(pub.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyHTTPCert([]*x509.Certificate{pubLeaf}, "93.184.216.34", false); err == nil {
		t.Fatal("self-signed cert for a PUBLIC ip accepted — want refuse (pin via PULSEMON_CA_FILE)")
	}
	priv := selfSignedIPCert(t, net.ParseIP("10.0.0.5"))
	privLeaf, err := x509.ParseCertificate(priv.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyHTTPCert([]*x509.Certificate{privLeaf}, "10.0.0.5", false); err != nil {
		t.Fatalf("control: self-signed cert for a private ip rejected: %v", err)
	}
}

// TestIsPublicProbeIP pins the public/private classification that the
// self-signed gate keys on.
func TestIsPublicProbeIP(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"10.0.0.1", false},            // RFC1918
		{"172.16.5.5", false},          // RFC1918
		{"172.15.0.1", true},           // just below 172.16/12
		{"172.32.0.1", true},           // just above 172.16/12
		{"192.168.1.1", false},         // RFC1918
		{"127.0.0.1", false},           // loopback
		{"169.254.1.1", false},         // link-local
		{"0.0.0.0", false},             // 0.0.0.0/8
		{"8.8.8.8", true},              // public
		{"93.184.216.34", true},        // public
		{"::1", false},                 // IPv6 loopback
		{"fe80::1", false},             // IPv6 link-local
		{"fd00::1", false},             // ULA
		{"fc00::1", false},             // ULA
		{"2606:4700:4700::1111", true}, // public
		{"::ffff:10.0.0.1", false},     // IPv4-mapped, private
		{"::ffff:8.8.8.8", true},       // IPv4-mapped, public
		{"example.com", false},         // hostname: not an IP literal
		{"router.local", false},        // hostname: homelab pattern
	}
	for _, c := range cases {
		if got := isPublicProbeIP(c.in); got != c.want {
			t.Errorf("isPublicProbeIP(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestProbeHTTPSUserinfoRefusesSelfSigned is the END-TO-END pin of the MITM
// hole: an https://user:pass@ target presenting a matching self-signed cert
// must be a LOSS with ZERO request bytes written — the cert is refused in
// probeDialTLS before the transport writes the Authorization header. The
// same target without userinfo must stay UP (the homelab pattern the gate
// preserves).
func TestProbeHTTPSUserinfoRefusesSelfSigned(t *testing.T) {
	// testSelfSigned's SANs are 127.0.0.1 + localhost — the exact cert an
	// attacker would mint for this target.
	cert := testSelfSigned(t, time.Now().Add(48*time.Hour))
	var authSeen int
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			authSeen++
		}
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	// Control: no userinfo -> the self-signed homelab pattern is accepted.
	if r := probeHTTP(context.Background(), srv.URL, 5*time.Second); r.Lost {
		t.Fatalf("control: no-userinfo probe of a self-signed target lost: %v", r.Err)
	}

	// Credential-bearing: refused BEFORE any request byte goes out.
	target := strings.Replace(srv.URL, "://", "://user:pass@", 1)
	if r := probeHTTP(context.Background(), target, 5*time.Second); !r.Lost {
		t.Fatal("credential-bearing probe of a self-signed target SUCCEEDED — the Basic auth header was exposed to a minted cert")
	} else if r.Err == nil || !strings.Contains(r.Err.Error(), "credentials") {
		t.Errorf("refusal should name the credentials rule, got: %v", r.Err)
	}
	if authSeen != 0 {
		t.Errorf("server saw an Authorization header %d time(s) — the cert gate must reject before the request is written", authSeen)
	}
}
