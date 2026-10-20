package main

import (
	"net/http"
	"testing"
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
