package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestRedirectPolicyClosesEveryHTTPSHop pins the 2026-10-20 external-review
// fix: the probe client's redirect policy must set req.Close on EVERY HTTPS
// hop, not only hops that change host or scheme (the 2026-10-19 N4 form).
// A SAME-host HTTPS redirect (https://h/a -> https://h/b) reuses the pooled
// conn a previous probe's redirect hop left behind (the shared transport
// keeps idle conns for IdleConnTimeout = 10 min), so the hop reports the
// cert from that conn's ORIGINAL handshake — a renewed cert stays invisible
// in the displayed expiry, and verifyHTTPCert judges the stale cert.
// Plain-HTTP hops carry no cert data, so they may keep reusing pooled conns.
func TestRedirectPolicyClosesEveryHTTPSHop(t *testing.T) {
	mk := func(scheme, host string) *http.Request {
		r, err := http.NewRequest(http.MethodGet, scheme+"://"+host+"/x", nil)
		if err != nil {
			t.Fatalf("NewRequest(%s://%s): %v", scheme, host, err)
		}
		return r
	}
	cases := []struct {
		name       string
		scheme     string // the redirect TARGET hop
		host       string
		prevScheme string // the previous hop (via[len-1])
		prevHost   string
		wantClose  bool
	}{
		{"same-host https hop (the 2026-10-20 gap)", "https", "h.example:443", "https", "h.example:443", true},
		{"cross-host https hop (N4 regression)", "https", "192.0.2.2:443", "https", "192.0.2.1:443", true},
		{"http->https scheme flip (N4 regression)", "https", "h.example:443", "http", "h.example:80", true},
		{"same-host http hop keeps pooling", "http", "h.example:80", "http", "h.example:80", false},
		{"https->http flip keeps pooling (no cert data)", "http", "h.example:80", "https", "h.example:443", false},
	}
	for _, tc := range cases {
		req := mk(tc.scheme, tc.host)
		req.Close = false
		via := []*http.Request{mk(tc.prevScheme, tc.prevHost)}
		if err := httpClient.CheckRedirect(req, via); err != nil {
			t.Fatalf("%s: CheckRedirect = %v, want nil (same-host cases short-circuit the target guard; IP literals need no DNS)", tc.name, err)
		}
		if req.Close != tc.wantClose {
			t.Fatalf("%s: req.Close = %v, want %v", tc.name, req.Close, tc.wantClose)
		}
	}

	// The redirect cap and the target guard must be intact: an over-limit
	// chain is refused with ErrUseLastResponse, and a cross-host hop to a
	// BLOCKED address (loopback) is refused before any Close decision.
	over := mk("https", "h.example:443")
	via := make([]*http.Request, 0, maxHTTPRedirects+1)
	for i := 0; i <= maxHTTPRedirects; i++ {
		via = append(via, mk("https", "h.example:443"))
	}
	if err := httpClient.CheckRedirect(over, via); err != http.ErrUseLastResponse {
		t.Fatalf("over-limit chain: CheckRedirect = %v, want ErrUseLastResponse", err)
	}
	loop := mk("https", "127.0.0.1:443")
	if err := httpClient.CheckRedirect(loop, []*http.Request{mk("https", "192.0.2.1:443")}); err == nil {
		t.Fatal("cross-host hop to loopback: CheckRedirect = nil, want a refusal (redirectTargetAllowed)")
	}
}

// roundTripFunc adapts a func to http.RoundTripper (routing pins).
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestReqCloseRoutesFlaggedRequests pins the uaRoundTripper routing: every
// req.Close-flagged request goes to the no-reuse (fresh) transport, every
// unflagged request to the pooled (base) transport. The 2026-11-11 review
// found that req.Close alone does NOT force a dial on a pooled transport —
// Transport.getConn serves an idle conn regardless of the flag (verified on
// Go 1.26) — so the flag is only a signal that this router must act on.
func TestReqCloseRoutesFlaggedRequests(t *testing.T) {
	var baseN, freshN int
	rt := uaRoundTripper{
		base:  roundTripFunc(func(*http.Request) (*http.Response, error) { baseN++; return nil, nil }),
		fresh: roundTripFunc(func(*http.Request) (*http.Response, error) { freshN++; return nil, nil }),
	}
	mk := func(closeFlag bool) *http.Request {
		r, err := http.NewRequest(http.MethodGet, "https://h.example/", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Close = closeFlag
		return r
	}
	for _, closeFlag := range []bool{false, true, true, false} {
		_, _ = rt.RoundTrip(mk(closeFlag))
	}
	if baseN != 2 || freshN != 2 {
		t.Fatalf("routing: base=%d fresh=%d, want 2/2 (req.Close routes to the no-reuse transport)", baseN, freshN)
	}
}

// TestPinnedRedirectHopDialsFreshConn is the end-to-end proof of the same
// invariant on the live probe client: a PINNED cross-host HTTPS redirect hop
// must DIAL, not ride the pooled conn its target left behind. The pool is
// pre-warmed with an idle conn for the redirect target (two direct probes:
// fresh-dial+closed, then keep-alive+pooled), the origin 302s to that same
// host:port, and the target must see a THIRD client connection. Riding the
// pooled conn would dial WITHOUT the checked pin (that conn's IP was
// resolved under the sensor's own lookup, not this probe's) — the exact
// shape the pin map exists to close.
func TestPinnedRedirectHopDialsFreshConn(t *testing.T) {
	const targetHost = "pinned-hop-target.example.test"
	cert := selfSignedTLSForHost(t, targetHost)

	var mu sync.Mutex
	seen := map[string]bool{}
	tlsSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.RemoteAddr] = true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	tlsSrv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	tlsSrv.StartTLS()
	defer tlsSrv.Close()
	targetPort := tlsSrv.Listener.Addr().(*net.TCPAddr).Port

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, fmt.Sprintf("https://%s:%d/", targetHost, targetPort), http.StatusFound)
	}))
	defer origin.Close()

	startFakeDNS(t, "10.99.99.50") // target resolves RFC1918: guard allows, pin records
	oldDialer := probeDialer
	probeDialer = loopbackDialer{} // pinned IP -> where the test servers live
	t.Cleanup(func() {
		probeDialer = oldDialer
		httpClient.Transport.(uaRoundTripper).base.(*http.Transport).CloseIdleConnections()
	})

	certReadMu.Lock()
	oldMap := certReadTimes
	certReadTimes = make(map[string]time.Time)
	certReadMu.Unlock()
	t.Cleanup(func() {
		certReadMu.Lock()
		certReadTimes = oldMap
		certReadMu.Unlock()
	})

	ctx := context.Background()
	targetURL := fmt.Sprintf("https://%s:%d/", targetHost, targetPort)
	// Warm the pool for the redirect target: probe 1 forces a fresh
	// handshake (no cert entry) and its conn is closed (req.Close), probe 2
	// has a fresh cert -> keep-alive conn lands in the idle pool.
	if res := probeHTTP(ctx, targetURL, 5*time.Second); res.Lost {
		t.Fatalf("warm probe 1 lost: %+v", res)
	}
	if res := probeHTTP(ctx, targetURL, 5*time.Second); res.Lost {
		t.Fatalf("warm probe 2 lost: %+v", res)
	}
	mu.Lock()
	warm := len(seen)
	mu.Unlock()
	if warm != 2 {
		t.Fatalf("warm-up opened %d connections, want 2 (dial+close, then dial+pooled)", warm)
	}

	// The redirect hop is flagged req.Close by CheckRedirect (pinned +
	// HTTPS): it must open a NEW conn, so the target sees 3 in total.
	if res := probeHTTP(ctx, origin.URL, 5*time.Second); res.Lost {
		t.Fatalf("origin probe (redirect chain) lost: %+v", res)
	}
	mu.Lock()
	total := len(seen)
	mu.Unlock()
	if total != 3 {
		t.Fatalf("target saw %d connections over warm-up + redirect, want 3 — the flagged hop rode the pooled conn (req.Close did not force a dial)", total)
	}
}
