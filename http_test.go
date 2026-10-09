package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// testTLSChain builds a throwaway CA + leaf cert pair. The leaf is valid
// for localhost/127.0.0.1 and expires at notAfter; the pool trusts the CA.
// The leaf is CA-signed (NOT self-signed): with the CA pool it is trusted,
// without it it is an "unknown authority" — the case verifyHTTPCert must
// reject. Used to exercise the cert-expiry + untrusted-CA paths without
// touching system roots.
func testTLSChain(t *testing.T, notAfter time.Time) (cert tls.Certificate, pool *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkixName("pulsemon test CA"),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkixName("pulsemon test leaf"),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(caCert)
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}, pool
}

func pkixName(cn string) pkix.Name {
	return pkix.Name{CommonName: cn}
}

// TestProbeHTTPSuccess: 2xx → not lost, status recorded, IP resolved.
func TestProbeHTTPSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	r := probeHTTP(srv.URL, 5*time.Second)
	if r.Lost {
		t.Fatalf("200 response marked lost: %+v", r)
	}
	if r.Status == nil || *r.Status != 200 {
		t.Fatalf("status = %v, want 200", r.Status)
	}
	if r.IP == "" {
		t.Error("resolved IP empty, want 127.0.0.1")
	}
	if r.Err != nil {
		t.Errorf("unexpected transport error: %v", r.Err)
	}
}

// TestProbeHTTPFollowsRedirect: a 3xx chain is followed and the FINAL status
// decides. / → 302 → /other (200) is UP with status 200, which is the
// common shape of a web UI that redirects to its login page.
func TestProbeHTTPFollowsRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/other", http.StatusFound) // 302
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := probeHTTP(srv.URL, 5*time.Second)
	if r.Lost {
		t.Fatalf("redirect chain ending in 200 marked loss, want up")
	}
	if r.Status == nil || *r.Status != 200 {
		t.Fatalf("status = %v, want 200 (final hop)", r.Status)
	}
}

// TestProbeHTTPRedirectLoopIsLoss: a host that redirects forever must not
// hang the probe — the cap leaves the last 3xx as the terminal status (loss).
func TestProbeHTTPRedirectLoopIsLoss(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"/", http.StatusFound) // 302 to self-ish, forever
	}))
	defer srv.Close()

	r := probeHTTP(srv.URL, 5*time.Second)
	if !r.Lost {
		t.Fatalf("redirect loop marked up, want loss")
	}
	if r.Status == nil || *r.Status != http.StatusFound {
		t.Fatalf("status = %v, want 302 (last hop)", r.Status)
	}
}

// TestProbeHTTPErrorsAreLoss: 4xx/5xx responses are losses, code recorded.
func TestProbeHTTPErrorsAreLoss(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusServiceUnavailable} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "x", code)
		}))
		r := probeHTTP(srv.URL, 5*time.Second)
		srv.Close()
		if !r.Lost {
			t.Errorf("status %d marked up, want loss", code)
		}
		if r.Status == nil || *r.Status != code {
			t.Errorf("status = %v, want %d", r.Status, code)
		}
	}
}

// TestProbeHTTPTimeout: a slow handler must produce a clean loss with no
// status code when the per-probe deadline fires first.
func TestProbeHTTPTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(3 * time.Second):
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	start := time.Now()
	r := probeHTTP(srv.URL, 400*time.Millisecond)
	if !r.Lost {
		t.Fatalf("slow handler marked up, want loss")
	}
	if r.Status != nil {
		t.Errorf("status = %v, want nil (no response before deadline)", *r.Status)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("probe took %v, want ~400ms deadline", time.Since(start))
	}
}

// TestProbeHTTPUntrustedCACert: a cert from a CA that is NOT in the system
// roots is rejected (it is not self-signed, so verifyHTTPCert's allowance
// does not apply). The probe is a LOSS, but the presented cert is still
// captured so the card can show its expiry.
func TestProbeHTTPUntrustedCACert(t *testing.T) {
	// 2-day expiry: well inside the warning window.
	notAfter := time.Now().Add(48 * time.Hour)
	cert, pool := testTLSChain(t, notAfter)
	_ = pool // not trusted by the default client — that's the point

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	r := probeHTTP(srv.URL, 5*time.Second)
	if !r.Lost {
		t.Fatalf("untrusted-CA cert marked up, want loss (verification failed)")
	}
	if r.CertExpiry == nil {
		t.Fatal("CertExpiry = nil, want the cert's NotAfter from the presented certs")
	}
	if diff := r.CertExpiry.Sub(notAfter); diff > time.Minute || diff < -time.Minute {
		t.Errorf("CertExpiry = %v, want ~%v", r.CertExpiry, notAfter)
	}
}

// testSelfSigned builds a genuinely self-signed cert (issuer == subject)
// valid for 127.0.0.1, expiring at notAfter. A self-signed cert is the
// homelab case verifyHTTPCert is meant to ACCEPT (when host + expiry hold).
func testSelfSigned(t *testing.T, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkixName("pulsemon test self-signed"),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
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

// TestProbeHTTPSelfSignedAccepted: a valid self-signed cert whose host
// matches the target is ACCEPTED — the probe is UP and the expiry is
// captured. This is the homelab self-signed web-UI case the feature targets.
func TestProbeHTTPSelfSignedAccepted(t *testing.T) {
	notAfter := time.Now().Add(48 * time.Hour)
	cert := testSelfSigned(t, notAfter)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	r := probeHTTP(srv.URL, 5*time.Second)
	if r.Lost {
		t.Fatalf("valid self-signed cert marked loss, want up: err=%v", r.Err)
	}
	if r.Status == nil || *r.Status != 200 {
		t.Fatalf("status = %v, want 200", r.Status)
	}
	if r.CertExpiry == nil {
		t.Fatal("CertExpiry = nil, want the self-signed cert's NotAfter")
	}
	if diff := r.CertExpiry.Sub(notAfter); diff > time.Minute || diff < -time.Minute {
		t.Errorf("CertExpiry = %v, want ~%v", r.CertExpiry, notAfter)
	}
}

// TestProbeHTTPSelfSignedExpiredRejected: a self-signed cert that is
// EXPIRED is still rejected — self-signed acceptance enforces expiry. The
// probe is a loss and the cert expiry is captured.
func TestProbeHTTPSelfSignedExpiredRejected(t *testing.T) {
	notAfter := time.Now().Add(-24 * time.Hour) // already expired
	cert := testSelfSigned(t, notAfter)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	r := probeHTTP(srv.URL, 5*time.Second)
	if !r.Lost {
		t.Fatalf("expired self-signed cert marked up, want loss (expiry enforced)")
	}
	if r.CertExpiry == nil {
		t.Fatal("CertExpiry = nil, want the expired cert's NotAfter")
	}
}

// TestProbeHTTPTLSKeepAlive: three HTTPS probes to the same host must reuse
// one TCP+TLS connection. The server counts the DISTINCT client addresses
// it sees: a reused connection keeps the same source port (1 distinct),
// while a fresh connection per probe uses a new ephemeral port (3 distinct).
// This pins the bounded body-drain — without it, net/http discards the
// connection after an unread body and every probe re-handshakes.
func TestProbeHTTPTLSKeepAlive(t *testing.T) {
	cert := testSelfSigned(t, time.Now().Add(48*time.Hour))

	var mu sync.Mutex
	seen := map[string]bool{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.RemoteAddr] = true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	for i := 0; i < 3; i++ {
		r := probeHTTP(srv.URL, 5*time.Second)
		if r.Lost {
			t.Fatalf("probe %d lost: %v", i, r.Err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	n := len(seen)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("server saw %d distinct client connections over 3 same-host probes, want 1 (keep-alive reuse)", n)
	}
}

// TestVerifyHTTPCert: direct unit coverage of the self-signed allowance —
// valid self-signed accepted, expired self-signed rejected, and an empty
// presented slice (plain HTTP) accepted with nothing to verify.
func TestVerifyHTTPCert(t *testing.T) {
	valid := testSelfSigned(t, time.Now().Add(48*time.Hour))
	expired := testSelfSigned(t, time.Now().Add(-24*time.Hour))

	// Parse the leaf certs out of the tls.Certificates for verifyHTTPCert.
	leaf, _ := x509.ParseCertificate(valid.Certificate[0])
	expLeaf, _ := x509.ParseCertificate(expired.Certificate[0])

	// Valid self-signed matching 127.0.0.1 -> accepted.
	if err := verifyHTTPCert([]*x509.Certificate{leaf}, "127.0.0.1"); err != nil {
		t.Errorf("valid self-signed rejected: %v", err)
	}
	// Expired self-signed -> rejected (self-signed acceptance enforces expiry).
	if err := verifyHTTPCert([]*x509.Certificate{expLeaf}, "127.0.0.1"); err == nil {
		t.Error("expired self-signed accepted, want reject")
	}
	// No presented certs (plain HTTP) -> nothing to verify, accepted.
	if err := verifyHTTPCert(nil, "127.0.0.1"); err != nil {
		t.Errorf("empty presented certs rejected: %v", err)
	}
	// Wrong host -> rejected.
	if err := verifyHTTPCert([]*x509.Certificate{leaf}, "10.9.9.9"); err == nil {
		t.Error("wrong-host self-signed accepted, want reject")
	}
}

// TestVerifyHTTPCertVariantFallback: regression guard for the www/bare
// hostname fallback in verifyHTTPCert. Real CDNs and registrars commonly
// serve a cert for the www variant of a bare domain (google.com -> the
// presented cert is www.google.com) or the other way around; a target host
// that differs from the SAN only by the www. prefix must still verify.
// Self-signed certs are used so the test is fully deterministic (no network,
// no system trust store).
func TestVerifyHTTPCertVariantFallback(t *testing.T) {
	certFor := func(dns ...string) *x509.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("key: %v", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkixName("pulsemon test variant"),
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(48 * time.Hour),
			DNSNames:              dns,
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatalf("cert: %v", err)
		}
		return x509MustParse(t, der)
	}
	wwwCert := certFor("www.example.com")
	bareCert := certFor("example.com")

	// Bare target, www SAN -> accepted via the www. prefix fallback.
	if err := verifyHTTPCert([]*x509.Certificate{wwwCert}, "example.com"); err != nil {
		t.Errorf("bare target vs www SAN rejected (want variant fallback): %v", err)
	}
	// www target, bare SAN -> accepted via the www. trim fallback.
	if err := verifyHTTPCert([]*x509.Certificate{bareCert}, "www.example.com"); err != nil {
		t.Errorf("www target vs bare SAN rejected (want variant trim): %v", err)
	}
	// A different domain must NOT ride the fallback.
	if err := verifyHTTPCert([]*x509.Certificate{wwwCert}, "other.com"); err == nil {
		t.Error("unrelated host accepted, want reject")
	}
	// Exact match still works (no fallback needed).
	if err := verifyHTTPCert([]*x509.Certificate{wwwCert}, "www.example.com"); err != nil {
		t.Errorf("exact match rejected: %v", err)
	}
}

func x509MustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c
}

// selfSignedWithSANs builds a genuine self-signed cert with the given SANs
// (parsed), for direct verifyHTTPCert unit tests. 48h validity.
func selfSignedWithSANs(t *testing.T, ips []net.IP, dns []string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkixName("pulsemon test self-signed"),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IPAddresses:           ips,
		DNSNames:              dns,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-signed cert: %v", err)
	}
	return x509MustParse(t, der)
}

// TestVerifyHTTPCertIPLiteral: regression guard settling the "DNSName can't
// match IP SANs" misdiagnosis. x509.Verify routes a DNSName that parses as
// an IP to IP-SAN-only matching (RFC 6125 B.2) — it does NOT fall back to
// DNS SANs. Pins:
//   - self-signed cert with a matching IP SAN → accepted,
//   - self-signed cert with a non-matching IP SAN → rejected,
//   - DNS-only SAN vs an IP target → rejected (no DNS fallback),
//   - UNTRUSTED-CA cert with a matching IP SAN → rejected.
//
// The last case is what a naive "leaf.VerifyHostname(host)" check would
// accept (VerifyHostname does NO trust validation), which is why that
// approach must not replace the InsecureSkipVerify + manual-verify design:
// "untrusted CA = loss" is a load-bearing property.
func TestVerifyHTTPCertIPLiteral(t *testing.T) {
	ipCert := selfSignedWithSANs(t, []net.IP{net.ParseIP("10.1.2.3")}, nil)
	dnsCert := selfSignedWithSANs(t, nil, []string{"internal.example.com"})

	// Matching IP SAN → accepted (branch (b), self-signed + IP SAN).
	if err := verifyHTTPCert([]*x509.Certificate{ipCert}, "10.1.2.3"); err != nil {
		t.Errorf("self-signed cert with matching IP SAN rejected: %v", err)
	}
	// Non-matching IP → rejected.
	if err := verifyHTTPCert([]*x509.Certificate{ipCert}, "10.9.9.9"); err == nil {
		t.Error("self-signed cert with non-matching IP SAN accepted")
	}
	// DNS-only SAN vs an IP target: the IP literal must be matched against
	// IP SANs only; a DNS SAN for internal.example.com must NOT cover it.
	if err := verifyHTTPCert([]*x509.Certificate{dnsCert}, "10.1.2.3"); err == nil {
		t.Error("DNS-only cert accepted for an IP target (DNS fallback must not exist)")
	}
	// Untrusted CA (throwaway, not in system roots) whose leaf carries a
	// matching IP SAN → rejected. testTLSChain's leaf is exactly this:
	// CA-signed, IPAddresses [127.0.0.1]. VerifyHostname alone would accept
	// it — this assertion is the guard against that regression.
	leafCert, _ := testTLSChain(t, time.Now().Add(48*time.Hour))
	leaf, err := x509.ParseCertificate(leafCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse test leaf: %v", err)
	}
	if err := verifyHTTPCert([]*x509.Certificate{leaf}, "127.0.0.1"); err == nil {
		t.Error("untrusted-CA cert with matching IP SAN accepted (trust validation lost)")
	}
}

// TestProbeHTTPPublicCertWithIntermediate: regression guard for the
// system-trust branch. Real web servers (CDN front ends) present a LEAF +
// INTERMEDIATE chain to a trusted root; chain building requires that
// intermediate, and verifyHTTPCert must feed it to Verify via
// Intermediates. The v0.1.29 bug checked the leaf against system roots
// with an EMPTY Intermediates pool, so every such cert read "not trusted"
// and the probe was a loss — even though a standard TLS client accepts it.
// The regression's signature is the exact "not trusted" error; a network
// failure is a different error and just skips the test.
func TestProbeHTTPPublicCertWithIntermediate(t *testing.T) {
	const target = "https://pulsemon.net"
	r := probeHTTP(target, 10*time.Second)
	if r.Err != nil && strings.Contains(r.Err.Error(), "not trusted") {
		t.Fatalf("%s rejected as untrusted (chain-building regression): %v", target, r.Err)
	}
	if r.Lost {
		// No network / target down in this environment — not a regression.
		t.Skipf("skipping: no usable response from %s: %v", target, r.Err)
	}
	if r.Status == nil || *r.Status != 200 {
		t.Fatalf("%s status = %v, want 200", target, r.Status)
	}
}

// TestValidURL: the save-time gate for HTTP targets.
func TestValidURL(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"https://example.com/health", true},
		{"http://10.0.0.5:8080/x", true},
		{"https://[::1]:9443/", true},
		{"https://example.com", true},
		{"http://nas:8080", true},         // single-label internal host + explicit port
		{"https://myhost:8443/health", true}, // single-label + port
		{"ftp://example.com", false},
		{"example.com", false},    // no scheme
		{"http://", false},        // no host
		{"https://router", false}, // single-label, no dot/brackets/port
		{"", false},
	}
	for _, c := range cases {
		if got := validURL(c.in); got != c.want {
			t.Errorf("validURL(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestAPIHTTPTargetValidation: the POST gate — an HTTP sensor must carry a
// URL, an ICMP sensor must not carry a bare host, and a mixed pair is
// rejected with a clear 400.
func TestAPIHTTPTargetValidation(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "httpapi.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	srv := NewServer(db, NewProbeWorker(db))

	post := func(body string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/sensors", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.Mux().ServeHTTP(w, req)
		return w.Code
	}

	if code := post(`{"name":"ok-http","target":"https://example.com/health","type":"http"}`); code != http.StatusCreated {
		t.Errorf("http sensor with URL: %d, want 201", code)
	}
	if code := post(`{"name":"bad-http","target":"example.com","type":"http"}`); code != http.StatusBadRequest {
		t.Errorf("http sensor with bare host: %d, want 400", code)
	}
	if code := post(`{"name":"bad-icmp","target":"https://example.com/health","type":"icmp"}`); code != http.StatusBadRequest {
		t.Errorf("icmp sensor with URL: %d, want 400 (URL is not an IP/hostname)", code)
	}
	// Omitted type must default to icmp (legacy clients).
	if code := post(`{"name":"legacy","target":"10.0.0.5"}`); code != http.StatusCreated {
		t.Errorf("omitted type: %d, want 201", code)
	}

	// Read back: the created HTTP sensor must report type http + its URL.
	var got Sensor
	if err := db.QueryRow("SELECT name, target, type FROM sensors WHERE name = ?", "ok-http").
		Scan(&got.Name, &got.Target, &got.Type); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.Type != "http" || got.Target != "https://example.com/health" {
		t.Errorf("read back = %+v, want type=http target=https://example.com/health", got)
	}
}

// TestAPIHTTPViewFields: GET /api/sensors carries http_status + cert_expiry
// for an HTTP sensor only when the probe worker has a result; ICMP sensors
// omit both.
func TestAPIHTTPViewFields(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "httpview.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	pw := NewProbeWorker(db)
	srv := NewServer(db, pw)

	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('hsens','h','https://example.com', 'http', 60, 1000, 25, 2, 3, 'active', 'up', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('csens','c','10.0.0.5', 'icmp', 60, 1000, 25, 2, 3, 'active', 'up', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Seed the worker's last-probe state the way doProbe does.
	pw.mu.Lock()
	code := 503
	exp := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	pw.sensors["hsens"] = &ProbeState{lastHTTPStatus: &code, lastCertExpiry: &exp}
	pw.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/sensors", nil)
	w := httptest.NewRecorder()
	srv.Mux().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/sensors: %d", w.Code)
	}
	var views []SensorView
	if err := json.Unmarshal(w.Body.Bytes(), &views); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var httpView, icmpView *SensorView
	for i := range views {
		switch views[i].ID {
		case "hsens":
			httpView = &views[i]
		case "csens":
			icmpView = &views[i]
		}
	}
	if httpView == nil || icmpView == nil {
		t.Fatalf("views missing sensors: %d", len(views))
	}
	if httpView.HTTPStatus == nil || *httpView.HTTPStatus != 503 {
		t.Errorf("http http_status = %v, want 503", httpView.HTTPStatus)
	}
	if httpView.CertExpiry == nil || !httpView.CertExpiry.Equal(exp) {
		t.Errorf("http cert_expiry = %v, want %v", httpView.CertExpiry, exp)
	}
	if icmpView.HTTPStatus != nil || icmpView.CertExpiry != nil {
		t.Errorf("icmp sensor must omit http fields: status=%v cert=%v", icmpView.HTTPStatus, icmpView.CertExpiry)
	}
}

// TestProbeTargetDispatch: probeTarget routes by type — http sensors call
// probeHTTP (status + cert captured), icmp sensors go through pingHost.
func TestProbeTargetDispatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	o := probeTarget("http", srv.URL, 5*time.Second)
	if o.lost || o.httpCode == nil || *o.httpCode != 200 || o.certExpiry != nil {
		t.Errorf("http dispatch = %+v, want up 200 no-cert (plain http)", o)
	}
	if o.rttMs < 0 {
		t.Errorf("http rttMs = %v, want >= 0", o.rttMs)
	}

	// ICMP: 127.0.0.1 loopback should answer on any sane host. (If the test
	// box has ICMP blocked, the lost flag may be true — both are valid
	// outcomes; what matters is NO http fields leak into an icmp probe.)
	oi := probeTarget("icmp", "127.0.0.1", 2*time.Second)
	if oi.httpCode != nil || oi.certExpiry != nil {
		t.Errorf("icmp dispatch leaked http fields: %+v", oi)
	}

	// Unknown type falls through to icmp (the default).
	ou := probeTarget("nonsense", "127.0.0.1", 2*time.Second)
	if ou.httpCode != nil {
		t.Errorf("unknown type leaked http fields: %+v", ou)
	}
}

// TestPingNowHTTPSensor: Pulse Now on an HTTP sensor makes an HTTP request
// (via probeTarget), records the row with http_status, and does NOT derive
// status.
func TestPingNowHTTPSensor(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "pnowhttp.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('pnow','pnow','https://127.0.0.1:1/never', 'http', 60, 1000, 25, 1, 3, 'active', 'up', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	pw := NewProbeWorker(db)

	// down_after=1: a single lost probe WOULD error the sensor if PingNow
	// derived status. It must not.
	o, err := pw.PingNow("pnow")
	if err != nil {
		t.Fatalf("PingNow: %v", err)
	}
	if !o.lost {
		t.Errorf("unroutable target marked up, want loss")
	}

	var rtt sql.NullFloat64
	if err := db.QueryRow("SELECT rtt_ms FROM probes WHERE sensor_id = ?", "pnow").Scan(&rtt); err != nil {
		t.Fatalf("read rtt_ms: %v", err)
	}
	if rtt.Valid {
		t.Errorf("recorded rtt_ms = %v, want NULL (lost probe)", rtt.Float64)
	}
	var status string
	if err := db.QueryRow("SELECT status FROM sensors WHERE id = ?", "pnow").Scan(&status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status != "up" {
		t.Errorf("status after pulse = %q, want up (manual probe must not flip status)", status)
	}
}
