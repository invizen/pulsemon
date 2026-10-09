package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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
		{"", "example.com", true, "empty host"},
	}
	for _, c := range cases {
		err := redirectTargetAllowed(c.host, c.orig)
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

	res := probeHTTP(srv.URL, 5*time.Second)
	if !res.Lost {
		t.Fatalf("metadata redirect marked up, want loss (guard failed): %+v", res)
	}
	if metadataHit {
		t.Fatal("probe actually fetched the metadata-stand-in URL")
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
