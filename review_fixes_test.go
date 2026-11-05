package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestCheckWebhookIPBlocksZeroEight locks the 0.0.0.0/8 addition: on Linux
// the whole block routes locally (not just 0.0.0.0), so IsUnspecified()
// alone left http://0.1.2.3 reaching local services.
func TestCheckWebhookIPBlocksZeroEight(t *testing.T) {
	for _, s := range []string{"0.0.0.0", "0.1.2.3", "0.255.255.255"} {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad test IP %q", s)
		}
		if err := checkWebhookIP(ip, s); err == nil {
			t.Errorf("checkWebhookIP(%q) = nil, want blocked (0.0.0.0/8 routes local on Linux)", s)
		}
	}
	// IPv4-mapped IPv6 form must be judged as IPv4 too.
	if err := checkWebhookIP(net.ParseIP("::ffff:0.1.2.3"), "::ffff:0.1.2.3"); err == nil {
		t.Error("IPv4-mapped ::ffff:0.1.2.3 not blocked")
	}
}

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
		httpClient.Transport.(*http.Transport).CloseIdleConnections()
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

// TestValidVersionToken locks the fetchRelease URL-path guard: normal tags
// (incl. pre-release) pass, traversal and whitespace/control junk fail.
func TestValidVersionToken(t *testing.T) {
	ok := []string{"v0.2.2", "v1.0", "v10.20.30", "v1.2.3-rc1", "v1.2.3+build5"}
	bad := []string{"", "v", "0.2.2", "v../evil", "v0.2 2", "v0.2.2\n", "v" + strings.Repeat("9", 50), "v0.2.2; rm"}
	for _, s := range ok {
		if !validVersionToken(s) {
			t.Errorf("validVersionToken(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if validVersionToken(s) {
			t.Errorf("validVersionToken(%q) = true, want false", s)
		}
	}
}

// TestFetchReleaseRejectsBadVersion proves fetchRelease surfaces a clean
// error (not a nil-req panic) for a malformed pinned version.
func TestFetchReleaseRejectsBadVersion(t *testing.T) {
	cases := []string{"v../evil", "v0.2 2", "v\n"}
	for _, v := range cases {
		rel, err := fetchRelease(http.DefaultClient, v)
		if err == nil {
			t.Errorf("fetchRelease(%q) = %+v, want error", v, rel)
		}
	}
}

// TestUpdateCheckStaleOnFailure pins the negative-caching behavior: once a
// good result is cached, a failing GitHub lookup serves the stale result
// with cached:true instead of 503, and the failure is suppressed for
// updateCheckFailTTL (no repeated upstream hits).
func TestUpdateCheckStaleOnFailure(t *testing.T) {
	// Point releaseBase at a server that succeeds once, then fails.
	var hits int
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits > 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"tag_name":"v9.9.9","html_url":"https://github.com/invizen/pulsemon/releases/tag/v9.9.9"}`))
	}))
	defer gh.Close()

	oldBase := releaseBase
	releaseBase = gh.URL + "/releases"
	t.Cleanup(func() { releaseBase = oldBase })

	oldCache, oldAt, oldFailed := updateCheckCached, updateCheckAt, updateCheckFailed
	oldTTL, oldFailTTL := updateCheckTTL, updateCheckFailTTL
	t.Cleanup(func() {
		updateCheckCached, updateCheckAt, updateCheckFailed = oldCache, oldAt, oldFailed
		updateCheckTTL, updateCheckFailTTL = oldTTL, oldFailTTL
	})
	updateCheckCached, updateCheckFailed = nil, false
	updateCheckTTL = time.Millisecond // force upstream on first call
	updateCheckFailTTL = time.Hour    // failure suppression window for the test

	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	get := func() (int, updateCheckResult) {
		req := httptest.NewRequest("GET", "/api/update-check", nil)
		rec := httptest.NewRecorder()
		srv.handleUpdateCheck(rec, req)
		var res updateCheckResult
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		return rec.Code, res
	}

	code, res := get() // hit 1: success, cached fresh
	if code != 200 || res.Latest != "v9.9.9" || res.Cached {
		t.Fatalf("first check: code=%d res=%+v", code, res)
	}

	time.Sleep(2 * time.Millisecond) // let updateCheckTTL expire
	code, res = get()                // upstream attempted, fails -> stale served
	if code != 200 || res.Latest != "v9.9.9" || !res.Cached {
		t.Fatalf("failure path: code=%d res=%+v, want 200 stale cached:true", code, res)
	}
	if hits != 2 {
		t.Fatalf("upstream hit %d times, want 2 (success + one failed probe)", hits)
	}

	code, res = get() // failure suppressed within updateCheckFailTTL: no upstream hit
	if code != 200 || res.Latest != "v9.9.9" || !res.Cached {
		t.Fatalf("suppressed path: code=%d res=%+v, want 200 stale cached:true", code, res)
	}
	if hits != 2 {
		t.Fatalf("upstream hit %d times during failure suppression, want still 2", hits)
	}
}

// TestUpdateCheckRefreshThrottled pins the ?refresh=1 throttle: a refresh
// younger than updateCheckRefreshMinInterval since the last fetch attempt is
// ignored and served from the cache (no new upstream hit), so the endpoint
// can't be used to hammer the GitHub API by repeated refreshes. A refresh
// once the interval has elapsed DOES force a fresh fetch. Pre-fix, every
// ?refresh=1 bypassed the cache and forced a fetchRelease.
func TestUpdateCheckRefreshThrottled(t *testing.T) {
	var hits int
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"tag_name":"v9.9.9","html_url":"https://github.com/invizen/pulsemon/releases/tag/v9.9.9"}`))
	}))
	defer gh.Close()

	oldBase := releaseBase
	releaseBase = gh.URL + "/releases"
	t.Cleanup(func() { releaseBase = oldBase })

	oldCache, oldAt, oldAttempt, oldFailed := updateCheckCached, updateCheckAt, updateCheckAttemptAt, updateCheckFailed
	oldTTL, oldMinRefresh := updateCheckTTL, updateCheckRefreshMinInterval
	t.Cleanup(func() {
		updateCheckCached, updateCheckAt, updateCheckAttemptAt, updateCheckFailed = oldCache, oldAt, oldAttempt, oldFailed
		updateCheckTTL, updateCheckRefreshMinInterval = oldTTL, oldMinRefresh
	})
	updateCheckCached, updateCheckFailed = nil, false
	updateCheckAt, updateCheckAttemptAt = time.Time{}, time.Time{}
	updateCheckTTL = time.Hour // normal polls served from cache, not re-fetched
	updateCheckRefreshMinInterval = 50 * time.Millisecond

	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	get := func(refresh bool) (int, updateCheckResult) {
		u := "/api/update-check"
		if refresh {
			u += "?refresh=1"
		}
		req := httptest.NewRequest("GET", u, nil)
		rec := httptest.NewRecorder()
		srv.handleUpdateCheck(rec, req)
		var res updateCheckResult
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		return rec.Code, res
	}

	// 1. First check (no refresh): fetches and caches. hits=1.
	code, res := get(false)
	if code != 200 || res.Latest != "v9.9.9" || res.Cached {
		t.Fatalf("first check: code=%d res=%+v", code, res)
	}
	if hits != 1 {
		t.Fatalf("first check hit upstream %d times, want 1", hits)
	}

	// 2. Immediate ?refresh=1 (within the min interval): IGNORED — served from
	//    the fresh cache, NO new upstream hit. Pre-fix this forced a fetch
	//    (hits would become 2).
	code, res = get(true)
	if code != 200 || res.Cached {
		t.Fatalf("throttled refresh: code=%d res=%+v, want 200 served from fresh cache", code, res)
	}
	if hits != 1 {
		t.Fatalf("throttled refresh hit upstream %d times, want still 1 (a refresh within the min interval must be ignored)", hits)
	}

	// 3. After the min interval elapses: ?refresh=1 forces a fresh fetch.
	time.Sleep(60 * time.Millisecond)
	code, res = get(true)
	if code != 200 || res.Cached {
		t.Fatalf("post-interval refresh: code=%d res=%+v", code, res)
	}
	if hits != 2 {
		t.Fatalf("post-interval refresh hit upstream %d times, want 2", hits)
	}
}
