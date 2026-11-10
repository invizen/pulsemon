package main

// Probe redirect guard + DNS-rebinding TOCTOU: same-host hops pass, cross-host
// pivots into loopback/link-local/metadata are refused, and the dial is pinned to
// the checked IP while the hostname is kept for SNI/cert verification.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestRedirectTargetAllowed locks the probe redirect guard: same-host hops
// pass (router.local/ -> /login shape), cross-host pivots into loopback /
// link-local metadata are refused, and LAN cross-host hops stay allowed.
func TestRedirectTargetAllowed(t *testing.T) {
	cases := []struct {
		host, orig string
		wantErr    bool
		why        string
	}{
		{"router.local", "router.local", false, "same-host hop"},
		{"ROUTER.local", "router.local", false, "same-host case-insensitive"},
		{"127.0.0.1", "example.com", true, "cross-host loopback"},
		{"169.254.169.254", "example.com", true, "cloud metadata"},
		{"0.1.2.3", "example.com", true, "0.0.0.0/8 local route"},
		{"100.64.0.1", "example.com", true, "carrier NAT"},
		{"10.99.99.50", "example.com", false, "LAN redirect stays allowed"},
		{"10.0.0.7", "example.com", false, "RFC1918 redirect allowed"},
		{"::ffff:169.254.169.254", "example.com", true, "IPv4-mapped metadata literal"},
		{"::ffff:127.0.0.1", "example.com", true, "IPv4-mapped loopback literal"},
		{"::7f00:1", "example.com", true, "IPv4-EMBEDDED loopback literal (2026-10-20 review: the hand-copied judge missed embeddedIPv4)"},
		{"::a9fe:a9fe", "example.com", true, "IPv4-EMBEDDED metadata literal (2026-10-20 review)"},
		{"::127.0.0.1", "example.com", true, "dotted-quad embedded loopback literal"},
		{"fe80::1%eth0", "example.com", true, "zoned link-local literal"},
		{"fe80::1%25eth0", "example.com", true, "zoned literal, percent-encoded zone (URL.Hostname form)"},
		{"203.0.113.5", "example.com", false, "public literal stays allowed"},
		{"2001:db8::1", "example.com", false, "public IPv6 literal stays allowed"},
		{"", "example.com", true, "empty host"},
	}
	for _, c := range cases {
		_, err := redirectTargetAllowed(context.Background(), c.host, c.orig)
		if c.wantErr && err == nil {
			t.Errorf("redirectTargetAllowed(%q, %q) = nil, want refusal (%s)", c.host, c.orig, c.why)
		}
		if !c.wantErr && err != nil {
			t.Errorf("redirectTargetAllowed(%q, %q) = %v, want allow (%s)", c.host, c.orig, err, c.why)
		}
	}
}

// TestProbeHTTPCrossHostMetadataRedirectIsLoss drives the real probe client
// end to end: a public-ish (here: httptest, loopback) server that 302s to a
// literal link-local address must NOT have that hop fetched — the probe
// records a loss, and no request reaches the metadata stand-in.
//
// Note the first hop here is loopback itself: the INITIAL request is the
// operator's configured target and is deliberately unguarded, so the guard
// must reject the CROSS-HOP to 169.254.169.254 while never dialing it.

// TestProbeHTTPCrossHostMetadataRedirectIsLoss drives the real probe client
// end to end: a public-ish (here: httptest, loopback) server that 302s to a
// literal link-local address must NOT have that hop fetched — the probe
// records a loss, and no request reaches the metadata stand-in.
//
// Note the first hop here is loopback itself: the INITIAL request is the
// operator's configured target and is deliberately unguarded, so the guard
// must reject the CROSS-HOP to 169.254.169.254 while never dialing it.
func TestProbeHTTPCrossHostMetadataRedirectIsLoss(t *testing.T) {
	metadataHit := false
	meta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadataHit = true
	}))
	defer meta.Close()
	meta.Close() // free the port; 127.0.0.1:<port> now refuses instead of answering

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Cross-host pivot to the link-local metadata range.
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	res := probeHTTP(context.Background(), srv.URL, 5*time.Second)
	if !res.Lost {
		t.Fatalf("metadata redirect marked up, want loss (guard failed): %+v", res)
	}
	if metadataHit {
		t.Fatal("probe actually fetched the metadata-stand-in URL")
	}
}

// TestProbeHTTPRedirectRebindingClosed proves the check-then-dial TOCTOU is
// closed: a hostname that resolves to a public IP at check time
// (redirectTargetAllowed passes) but to a loopback IP at dial time (DNS
// rebinding) must NOT have the probe dial the loopback address. The fix
// rewrites the redirect URL to the checked IP, so the transport dials the
// public IP directly (no re-resolution) and the loopback stand-in is never
// reached.

// TestProbeHTTPRedirectRebindingClosed proves the check-then-dial TOCTOU is
// closed: a hostname that resolves to a public IP at check time
// (redirectTargetAllowed passes) but to a loopback IP at dial time (DNS
// rebinding) must NOT have the probe dial the loopback address. The fix
// rewrites the redirect URL to the checked IP, so the transport dials the
// public IP directly (no re-resolution) and the loopback stand-in is never
// reached.
func TestProbeHTTPRedirectRebindingClosed(t *testing.T) {
	// Rebinding stand-in: a server on loopback. If the dial goes to
	// 127.0.0.1:<port> (the rebinding IP), this server receives the
	// request. If the dial goes to 203.0.113.1:<port> (the checked IP),
	// it does not.
	rebindingHit := int32(0)
	rebindingSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.StoreInt32(&rebindingHit, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer rebindingSrv.Close()
	rebindingPort := rebindingSrv.Listener.Addr().(*net.TCPAddr).Port

	// Minimal DNS-over-UDP responder: returns 203.0.113.1 on the first
	// lookup (the check) and 127.0.0.1 on the second (the dial, if it
	// happens). With the fix, only the first lookup occurs.
	udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind UDP for DNS responder: %v", err)
	}
	defer udpConn.Close()
	dnsAddr := udpConn.LocalAddr().(*net.UDPAddr)

	var callCount int32
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := udpConn.ReadFrom(buf)
			if err != nil {
				return
			}
			// Walk the question name to find the end of the question
			// section (name + 2-byte qtype + 2-byte qclass).
			i := 12
			questionEnd := -1
			for i+3 < n && buf[i] != 0 {
				l := int(buf[i])
				if i+l+1 > n {
					break
				}
				i += l + 1
			}
			if i < n && buf[i] == 0 && i+5 <= n {
				questionEnd = i + 1 + 4
			}
			if questionEnd < 0 {
				continue
			}
			call := atomic.AddInt32(&callCount, 1)
			var ipBytes []byte
			if call == 1 {
				ipBytes = []byte{203, 0, 113, 1} // public (check passes)
			} else {
				ipBytes = []byte{127, 0, 0, 1} // loopback (rebinding)
			}
			resp := append([]byte(nil), buf[0:2]...)
			resp = append(resp, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
			resp = append(resp, buf[12:questionEnd]...)
			resp = append(resp,
				0x00,
				0x00, 0x01, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x04,
			)
			resp = append(resp, ipBytes...)
			udpConn.WriteTo(resp, from)
		}
	}()

	oldResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if network == "tcp" {
				return nil, fmt.Errorf("resolver: no TCP DNS in this test")
			}
			d := &net.Dialer{}
			c, err := d.DialContext(ctx, "udp4", dnsAddr.String())
			if err != nil {
				return nil, err
			}
			return c, nil
		},
	}
	defer func() {
		httpClient.Transport.(uaRoundTripper).base.(*http.Transport).CloseIdleConnections()
		time.Sleep(50 * time.Millisecond) // let any in-flight dialer goroutine finish
		net.DefaultResolver = oldResolver
	}()

	// Source server 302s to the rebinding hostname on the stand-in's port.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, fmt.Sprintf("http://rebind.example.com:%d/", rebindingPort), http.StatusFound)
	}))
	defer srv.Close()

	res := probeHTTP(context.Background(), srv.URL, 5*time.Second)
	if !res.Lost {
		t.Fatalf("probe marked up, want loss (203.0.113.1 is not a real server): %+v", res)
	}
	if atomic.LoadInt32(&rebindingHit) != 0 {
		t.Fatal("probe dialed the rebinding loopback address — TOCTOU not closed")
	}
}

// loopbackDialer dials every address to 127.0.0.1 (the httptest servers'
// host), preserving the port and network. It lets a cross-host redirect hop
// — whose pinned IP is a non-loopback RFC1918 address the redirect guard
// requires — actually reach a loopback test server.

// loopbackDialer dials every address to 127.0.0.1 (the httptest servers'
// host), preserving the port and network. It lets a cross-host redirect hop
// — whose pinned IP is a non-loopback RFC1918 address the redirect guard
// requires — actually reach a loopback test server.
type loopbackDialer struct{}

func (loopbackDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
}

// TestProbeHTTPCrossHostRedirectKeepsHostname proves the cross-host redirect
// fix end to end: a redirect hop to a DIFFERENT hostname must (a) dial the
// checked IP (closing the DNS-rebinding TOCTOU) and (b) keep the hostname
// for SNI and cert verification — a cert issued for the DNS name (no IP SAN)
// verifies correctly. Pre-fix, CheckRedirect rewrote the URL to the IP, so
// probeDialTLS saw an IP literal: Go blanked the SNI and verifyHTTPCert
// judged the cert against the IP, failing this DNS-name cert (a permanent
// loss for https://host → https://other.host redirects). The httptest servers
// bind loopback — which the guard refuses for cross-host hops — so the test
// stubs the resolver (target → RFC1918 IP) and the dialer (pinned IP →
// loopback) to exercise the hop.

// TestProbeHTTPCrossHostRedirectKeepsHostname proves the cross-host redirect
// fix end to end: a redirect hop to a DIFFERENT hostname must (a) dial the
// checked IP (closing the DNS-rebinding TOCTOU) and (b) keep the hostname
// for SNI and cert verification — a cert issued for the DNS name (no IP SAN)
// verifies correctly. Pre-fix, CheckRedirect rewrote the URL to the IP, so
// probeDialTLS saw an IP literal: Go blanked the SNI and verifyHTTPCert
// judged the cert against the IP, failing this DNS-name cert (a permanent
// loss for https://host → https://other.host redirects). The httptest servers
// bind loopback — which the guard refuses for cross-host hops — so the test
// stubs the resolver (target → RFC1918 IP) and the dialer (pinned IP →
// loopback) to exercise the hop.
func TestProbeHTTPCrossHostRedirectKeepsHostname(t *testing.T) {
	const targetHost = "redirect-target.example.test"
	cert := selfSignedTLSForHost(t, targetHost)

	// TLS server on loopback serving the target-host cert; it REQUIRES the
	// SNI to be the target hostname (proves the client sent it — pre-fix the
	// SNI was blanked for the IP literal and the handshake would fail here).
	var gotSNI atomic.Value
	tlsSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	tlsSrv.TLS = &tls.Config{
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			gotSNI.Store(hi.ServerName)
			if hi.ServerName != targetHost {
				return nil, fmt.Errorf("server requires SNI=%s, got %q", targetHost, hi.ServerName)
			}
			return &cert, nil
		},
	}
	tlsSrv.StartTLS()
	defer tlsSrv.Close()
	targetPort := tlsSrv.Listener.Addr().(*net.TCPAddr).Port

	// Origin server 302s to the target hostname (cross-host). The target
	// resolves (fake DNS) to a non-loopback RFC1918 IP, so the redirect guard
	// allows the hop and records a pin.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, fmt.Sprintf("https://%s:%d/", targetHost, targetPort), http.StatusFound)
	}))
	defer origin.Close()

	// Fake DNS: every hostname → 10.99.99.50 (RFC1918, passes the guard).
	startFakeDNS(t, "10.99.99.50")

	// Fake dialer: pinned IP (or loopback) → 127.0.0.1, where the servers live.
	oldDialer := probeDialer
	probeDialer = loopbackDialer{}
	t.Cleanup(func() { probeDialer = oldDialer })

	res := probeHTTP(context.Background(), origin.URL, 5*time.Second)
	if res.Lost {
		t.Fatalf("cross-host redirect marked loss, want 200 (SNI/cert broken): %+v", res)
	}
	if res.Status == nil || *res.Status != 200 {
		t.Fatalf("status = %v, want 200", res.Status)
	}
	if got, _ := gotSNI.Load().(string); got != targetHost {
		t.Fatalf("SNI = %q, want %q (the dial must keep the hostname for SNI)", got, targetHost)
	}
}

// TestValidVersionToken locks the fetchRelease URL-path guard: normal tags
// (incl. pre-release) pass, traversal and whitespace/control junk fail.
