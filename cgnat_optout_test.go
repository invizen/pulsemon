package main

import (
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
	"strings"
	"testing"
	"time"
)

// setAllowCGNAT flips the CGNAT opt-out for the duration of a test and
// restores the startup value (the env var is install-time, so tests are
// the only other writer of allowCGNAT).
func setAllowCGNAT(t *testing.T, on bool) {
	t.Helper()
	old := allowCGNAT
	allowCGNAT = on
	t.Cleanup(func() { allowCGNAT = old })
}

// TestCGNATOptOutParsing pins the accepted env spellings: 1/true/yes
// (any case, surrounding whitespace) enable the opt-out; anything else —
// including unset — keeps the block.
func TestCGNATOptOutParsing(t *testing.T) {
	cases := map[string]bool{
		"":       false,
		"0":      false,
		"false":  false,
		"no":     false,
		"banana": false,
		"1":      true,
		"true":   true,
		"yes":    true,
		" TRUE ": true,
	}
	for v, want := range cases {
		t.Setenv("PULSEMON_ALLOW_CGNAT", v)
		if got := parseCGNATOptOut(); got != want {
			t.Errorf("parseCGNATOptOut() with PULSEMON_ALLOW_CGNAT=%q = %v, want %v", v, got, want)
		}
	}
}

// TestCGNATBlockedByDefault pins the default posture: CGNAT is refused on
// both boundaries of 100.64.0.0/10. (F6: this is exactly what broke
// Tailscale — the opt-out tests below are the fix, and it must not leak
// into the default.) webhook_reserved_test.go pins the same for the
// webhook path; the opt-out changed this code, so pin it here too.
func TestCGNATBlockedByDefault(t *testing.T) {
	setAllowCGNAT(t, false)
	for _, s := range []string{"100.64.0.1", "100.127.255.254"} {
		if err := checkWebhookIP(net.ParseIP(s), "tail.example"); err == nil {
			t.Errorf("checkWebhookIP(%s) by default = nil, want refusal", s)
		}
	}
}

// TestCGNATOptOutAllowsTailnet: with the opt-out the CGNAT range passes —
// a Tailscale/Headscale node is the operator's own extended LAN.
func TestCGNATOptOutAllowsTailnet(t *testing.T) {
	setAllowCGNAT(t, true)
	for _, s := range []string{"100.64.0.1", "100.100.1.5", "100.127.255.254"} {
		if err := checkWebhookIP(net.ParseIP(s), "tail.example"); err != nil {
			t.Errorf("checkWebhookIP(%s) with opt-out = %v, want allow", s, err)
		}
	}
}

// TestCGNATOptOutIsCGNATOnly: the opt-out widens NOTHING else. The
// 169.254/16 metadata block (the protection that actually matters here),
// loopback, 0/8, reserved-for-testing, and Class E stay refused; public
// space and the always-allowed LAN categories are untouched.
func TestCGNATOptOutIsCGNATOnly(t *testing.T) {
	setAllowCGNAT(t, true)
	for _, s := range []string{"169.254.169.254", "127.0.0.1", "0.0.0.1", "198.18.0.1", "240.0.0.1", "255.255.255.255"} {
		if err := checkWebhookIP(net.ParseIP(s), "meta.example"); err == nil {
			t.Errorf("checkWebhookIP(%s) with opt-out = nil, want refusal (opt-out is CGNAT-only)", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "192.168.1.1", "10.0.0.1", "172.16.0.1", "100.63.255.254", "100.128.0.1"} {
		if err := checkWebhookIP(net.ParseIP(s), "ok.example"); err != nil {
			t.Errorf("checkWebhookIP(%s) with opt-out = %v, want allow", s, err)
		}
	}
}

// TestCGNATOptOutEmbeddedIPv6: the dotted-quad / mapped forms go through
// the embedded-IPv4 recursion — the opt-out must apply to the CGNAT form
// (::6440:1 == 100.64.0.1) and NOT to the metadata form
// (::a9fe:a9fe == 169.254.169.254).
func TestCGNATOptOutEmbeddedIPv6(t *testing.T) {
	setAllowCGNAT(t, false)
	for _, s := range []string{"::6440:1", "::a9fe:a9fe"} {
		if err := checkWebhookIP(net.ParseIP(s), "v6.example"); err == nil {
			t.Errorf("checkWebhookIP(%s) by default = nil, want refusal", s)
		}
	}
	setAllowCGNAT(t, true)
	if err := checkWebhookIP(net.ParseIP("::6440:1"), "v6.example"); err != nil {
		t.Errorf("checkWebhookIP(::6440:1) with opt-out = %v, want allow", err)
	}
	if err := checkWebhookIP(net.ParseIP("::a9fe:a9fe"), "v6.example"); err == nil {
		t.Error("checkWebhookIP(::a9fe:a9fe) with opt-out = nil, want refusal (metadata block stays)")
	}
}

// TestRedirectTargetAllowedCGNAT: the HTTP-sensor redirect guard shares
// the canonical judge, so the opt-out covers it — a redirect to a tailnet
// host is refused by default and allowed under PULSEMON_ALLOW_CGNAT (F6's
// second breakage: http://nas → https://nas.tail1234.ts.net).
func TestRedirectTargetAllowedCGNAT(t *testing.T) {
	setAllowCGNAT(t, false)
	if _, err := redirectTargetAllowed(context.Background(), "100.64.7.7", "nas.example"); err == nil {
		t.Error("redirect to 100.64.7.7 by default = nil, want refusal")
	}
	setAllowCGNAT(t, true)
	if _, err := redirectTargetAllowed(context.Background(), "100.64.7.7", "nas.example"); err != nil {
		t.Errorf("redirect to 100.64.7.7 with opt-out = %v, want allow", err)
	}
}

// TestCGNATOptOutSMTPSavePath: the SMTP save path shares the canonical
// judge too — an SMTP relay on the tailnet is refused by default and
// allowed under the opt-out.
func TestCGNATOptOutSMTPSavePath(t *testing.T) {
	setAllowCGNAT(t, false)
	if err := validateSMTPHostNoDNS("100.64.9.9"); err == nil {
		t.Error("validateSMTPHostNoDNS(100.64.9.9) by default = nil, want refusal")
	}
	setAllowCGNAT(t, true)
	if err := validateSMTPHostNoDNS("100.64.9.9"); err != nil {
		t.Errorf("validateSMTPHostNoDNS(100.64.9.9) with opt-out = %v, want allow", err)
	}
}

// TestCGNATOptOutCleartextWebhookGates: the PRIVATE gates — not just the
// blocklist — must honor the opt-out. By default a CGNAT literal or host
// is refused for http:// at save time AND dial time; under
// PULSEMON_ALLOW_CGNAT it saves and dials. (MINOR-16: the opt-out used to
// relax only checkWebhookIP, so http://100.64.x.y relays — ntfy/Gotify on
// a WireGuard tailnet — saved nothing and dialed nothing.)
func TestCGNATOptOutCleartextWebhookGates(t *testing.T) {
	// Save-time, IP-literal form (validateWebhookURLNoDNS).
	setAllowCGNAT(t, false)
	if _, _, err := validateWebhookURLNoDNS("http://100.64.7.7:8080/notify"); err == nil {
		t.Error("validateWebhookURLNoDNS(http://100.64.7.7:8080) by default = nil, want refusal")
	}
	setAllowCGNAT(t, true)
	if _, _, err := validateWebhookURLNoDNS("http://100.64.7.7:8080/notify"); err != nil {
		t.Errorf("validateWebhookURLNoDNS(http://100.64.7.7:8080) with opt-out = %v, want allow", err)
	}
	// https stays allowed for CGNAT in both postures (the opt-out only
	// matters for the cleartext gate).
	if _, _, err := validateWebhookURLNoDNS("https://100.64.7.7:8443/notify"); err != nil {
		t.Errorf("https CGNAT literal with opt-out = %v, want allow", err)
	}

	// Save-time, hostname form (validateWebhookURL) — all answers must
	// pass, same rule as the dial-time gate.
	withFakeResolver(t, map[string][]net.IP{
		"tail.lan":  {net.ParseIP("100.64.7.7")},
		"mixed.lan": {net.ParseIP("100.64.7.7"), net.ParseIP("93.184.216.34")},
		"pub.lan":   {net.ParseIP("93.184.216.34")},
	})
	setAllowCGNAT(t, false)
	if err := validateWebhookURL("http://tail.lan/notify"); err == nil {
		t.Error("validateWebhookURL(http://tail.lan) by default = nil, want refusal")
	}
	setAllowCGNAT(t, true)
	if err := validateWebhookURL("http://tail.lan/notify"); err != nil {
		t.Errorf("validateWebhookURL(http://tail.lan) with opt-out = %v, want allow", err)
	}
	// Mixed records stay refused even under the opt-out: a name that
	// answers with a public address too cannot be trusted for cleartext.
	if err := validateWebhookURL("http://mixed.lan/notify"); err == nil {
		t.Error("mixed CGNAT+public records with opt-out accepted, want refusal")
	}
	// Pure public stays refused.
	if err := validateWebhookURL("http://pub.lan/notify"); err == nil {
		t.Error("public host with opt-out accepted, want refusal (opt-out is CGNAT-only)")
	}

	// Dial-time (dialCheckedCleartext): refused by default, dials under
	// the opt-out — the seam proves the policy let the dial through.
	withFakeResolver(t, map[string][]net.IP{
		"tail.lan": {net.ParseIP("100.64.7.7")},
	})
	c1, c2 := net.Pipe()
	defer c2.Close()
	d := recordingDialer(c1)
	orig := webhookDialer
	webhookDialer = d
	t.Cleanup(func() { webhookDialer = orig })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	setAllowCGNAT(t, false)
	d.called = false
	// By default the BLOCKLIST refuses CGNAT first (the private gate
	// below it is the layer the opt-out exercises — see the success arm).
	if _, err := dialCheckedCleartext(ctx, "tcp", "tail.lan:8080"); err == nil || !strings.Contains(err.Error(), "carrier-NAT") {
		t.Fatalf("dialCheckedCleartext by default = %v, want the carrier-NAT blocklist refusal", err)
	}
	if d.called {
		t.Fatal("dialer was called for a refused CGNAT target")
	}
	setAllowCGNAT(t, true)
	d.called = false
	if conn, err := dialCheckedCleartext(ctx, "tcp", "tail.lan:8080"); err != nil {
		t.Fatalf("dialCheckedCleartext with opt-out = %v, want the dial to proceed", err)
	} else if conn != c1 {
		t.Fatal("dialer result not plumbed through")
	}
}

// TestIsPublicProbeIPCGNATOptOut: the probe-side judge — CGNAT IP
// literals are "public" (self-signed certs refused) by default and NOT
// public under the opt-out; the range boundaries stay public either way.
func TestIsPublicProbeIPCGNATOptOut(t *testing.T) {
	setAllowCGNAT(t, false)
	for _, s := range []string{"100.64.0.1", "100.100.1.5", "100.127.255.254", "::ffff:100.64.7.7"} {
		if !isPublicProbeIP(s) {
			t.Errorf("isPublicProbeIP(%q) by default = false, want true (CGNAT is public without the opt-out)", s)
		}
	}
	setAllowCGNAT(t, true)
	for _, s := range []string{"100.64.0.1", "100.100.1.5", "100.127.255.254", "::ffff:100.64.7.7"} {
		if isPublicProbeIP(s) {
			t.Errorf("isPublicProbeIP(%q) with opt-out = true, want false (tailnet)", s)
		}
	}
	for _, s := range []string{"100.63.255.254", "100.128.0.1"} {
		if !isPublicProbeIP(s) {
			t.Errorf("isPublicProbeIP(%q) with opt-out = false, want true (outside 100.64.0.0/10)", s)
		}
	}
}

// selfSignedTLSForIP builds a self-signed cert whose ONLY SAN is the IP
// address — the cert a homelab operator generates for an IP-literal
// target (selfSignedTLSForHost is DNS-SAN-only, by design for its
// redirect tests).
func selfSignedTLSForIP(t *testing.T, ip string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pulsemon test self-signed"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IPAddresses:           []net.IP{net.ParseIP(ip)},
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

// TestCGNATProbeSelfSignedOptOut: end to end — an https://100.64.x.y
// sensor presenting a matching self-signed IP-SAN cert is a LOSS by
// default ("self-signed for a public IP") and UP under
// PULSEMON_ALLOW_CGNAT. (The IP literal is unroutable in the test
// environment; the probeDialer seam routes the dial to the in-process
// server, exactly like the redirect-rebinding pins.)
func TestCGNATProbeSelfSignedOptOut(t *testing.T) {
	const targetIP = "100.64.7.7"
	cert := selfSignedTLSForIP(t, targetIP)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	oldDialer := probeDialer
	probeDialer = loopbackDialer{} // any dial -> where the test server lives
	t.Cleanup(func() { probeDialer = oldDialer })

	// A fresh cert-read map so each probe forces one real handshake.
	certReadMu.Lock()
	oldMap := certReadTimes
	certReadTimes = make(map[string]time.Time)
	certReadMu.Unlock()
	t.Cleanup(func() {
		certReadMu.Lock()
		certReadTimes = oldMap
		certReadMu.Unlock()
	})

	url := fmt.Sprintf("https://%s:%d/", targetIP, port)
	setAllowCGNAT(t, false)
	res := probeHTTP(context.Background(), url, 5*time.Second)
	if !res.Lost {
		t.Fatalf("CGNAT probe by default marked up, want loss: %+v", res)
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "self-signed for a public IP") {
		t.Fatalf("default refusal = %v, want the public-IP self-signed refusal", res.Err)
	}

	setAllowCGNAT(t, true)
	res = probeHTTP(context.Background(), url, 5*time.Second)
	if res.Lost {
		t.Fatalf("CGNAT probe with opt-out marked lost: %+v", res)
	}
}
