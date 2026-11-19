package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// certReadTimes regression pins (2026-11-19 finding #10):
//
//  1. A keep-alive reuse must NOT advance the freshness timestamp — the
//     cert it reports is the pooled conn's ORIGINAL handshake, so
//     refreshing on reuse defeated certFreshness for any sensor polling
//     faster than the window (renewed/expired certs stale forever).
//  2. A continuously polling sensor must still get a fresh handshake at
//     least every certFreshness window.
//  3. The stale-entry scan runs at most once per certFreshness window,
//     not on every HTTPS probe (O(N) under a global lock per probe).

// TestCertReadTimesNotRefreshedOnKeepAliveReuse: probe 1 dials on the
// no-reuse transport (no entry), probe 2 dials fresh on the pooled
// transport and pools its conn, probe 3 REUSES that pooled conn. The
// certReadTimes entry must be exactly probe 2's timestamp after probe 3
// — pre-fix it was overwritten with time.Now() on every successful probe
// (including reuses), which is what kept the stale gate from ever firing
// for fast pollers.
func TestCertReadTimesNotRefreshedOnKeepAliveReuse(t *testing.T) {
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
	t.Cleanup(func() {
		httpClient.Transport.(uaRoundTripper).base.(*http.Transport).CloseIdleConnections()
	})

	hostKey := "https://" + srv.Listener.Addr().String()
	certReadMu.Lock()
	oldMap := certReadTimes
	oldPrune := certReadLastPrune
	certReadTimes = make(map[string]time.Time)
	certReadLastPrune = time.Time{}
	certReadMu.Unlock()
	t.Cleanup(func() {
		certReadMu.Lock()
		certReadTimes = oldMap
		certReadLastPrune = oldPrune
		certReadMu.Unlock()
	})

	ctx := context.Background()
	if res := probeHTTP(ctx, srv.URL, 5*time.Second); res.Lost {
		t.Fatalf("probe 1 lost: %+v", res)
	}
	if res := probeHTTP(ctx, srv.URL, 5*time.Second); res.Lost {
		t.Fatalf("probe 2 lost: %+v", res)
	}
	certReadMu.Lock()
	t2 := certReadTimes[hostKey]
	certReadMu.Unlock()
	if t2.IsZero() {
		t.Fatalf("certReadTimes has no entry for %q after probe 2 (a real handshake should have recorded it)", hostKey)
	}
	// Probe 3: fresh entry + pooled idle conn → keep-alive REUSE.
	if res := probeHTTP(ctx, srv.URL, 5*time.Second); res.Lost {
		t.Fatalf("probe 3 lost: %+v", res)
	}
	certReadMu.Lock()
	t3 := certReadTimes[hostKey]
	certReadMu.Unlock()
	if !t3.Equal(t2) {
		t.Fatalf("keep-alive reuse refreshed certReadTimes: t2=%v t3=%v — only a real handshake may advance the timestamp", t2, t3)
	}
	mu.Lock()
	n := len(seen)
	mu.Unlock()
	if n != 2 {
		t.Fatalf("server saw %d distinct connections over 3 probes, want 2 (probe 3 must have reused the pooled conn for the timestamp to matter)", n)
	}
}

// TestCertFreshnessForcesHandshakeUnderContinuousPolling: a sensor that
// polls faster than certFreshness must still force a fresh handshake at
// least once per window — otherwise a renewed cert stays invisible for
// the pooled conn's whole lifetime (which never goes idle while the
// poller keeps it warm). The window is shrunk to 150ms via the certFreshness
// seam so the cadence is seconds, not 10 minutes: 4 distinct connections
// must appear within a 5s budget of ~40ms polling. Pre-fix, the reuse
// refreshed the timestamp on every probe, so only 2 connections ever
// appeared and the gate never fired.
func TestCertFreshnessForcesHandshakeUnderContinuousPolling(t *testing.T) {
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
	t.Cleanup(func() {
		httpClient.Transport.(uaRoundTripper).base.(*http.Transport).CloseIdleConnections()
	})

	certReadMu.Lock()
	oldMap := certReadTimes
	oldPrune := certReadLastPrune
	certReadTimes = make(map[string]time.Time)
	certReadLastPrune = time.Time{}
	certReadMu.Unlock()
	oldFreshness := certFreshness
	certFreshness = 150 * time.Millisecond
	t.Cleanup(func() {
		certFreshness = oldFreshness
		certReadMu.Lock()
		certReadTimes = oldMap
		certReadLastPrune = oldPrune
		certReadMu.Unlock()
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		if res := probeHTTP(context.Background(), srv.URL, 2*time.Second); res.Lost {
			t.Fatalf("probe lost: %+v", res)
		}
		mu.Lock()
		n := len(seen)
		mu.Unlock()
		if n >= 4 {
			return // the stale gate fired repeatedly: cadence is intact
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d distinct connections after 5s of continuous polling — keep-alive reuses kept refreshing certReadTimes, so the stale-cert gate never fired (a renewed cert would stay stale forever)", n)
		}
		time.Sleep(40 * time.Millisecond)
	}
}

// TestCertReadTimesPruneThrottledToWindow: the stale-entry scan runs at
// most once per certFreshness window. With the window elapsed, a write
// scans (stale ghosts are pruned, certReadLastPrune advances). With the
// window fresh, a write SKIPS the scan (stale ghosts survive until the
// next window) — pre-fix the full map ran on every probe.
func TestCertReadTimesPruneThrottledToWindow(t *testing.T) {
	const ghost = "https://ghost-stale.invalid:443"
	cert := testSelfSigned(t, time.Now().Add(48*time.Hour))
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	certReadMu.Lock()
	oldMap := certReadTimes
	oldPrune := certReadLastPrune
	certReadMu.Unlock()
	t.Cleanup(func() {
		certReadMu.Lock()
		certReadTimes = oldMap
		certReadLastPrune = oldPrune
		certReadMu.Unlock()
	})

	seedGhost := func(pruneAt time.Time) {
		certReadMu.Lock()
		certReadTimes = map[string]time.Time{
			ghost: time.Now().Add(-certFreshness - time.Hour),
		}
		certReadLastPrune = pruneAt
		certReadMu.Unlock()
	}
	ghostPresent := func() bool {
		certReadMu.Lock()
		defer certReadMu.Unlock()
		_, ok := certReadTimes[ghost]
		return ok
	}

	t.Run("windowElapsedScanRuns", func(t *testing.T) {
		seedGhost(time.Now().Add(-certFreshness - time.Second))
		if res := probeHTTP(context.Background(), srv.URL, 5*time.Second); res.Lost {
			t.Fatalf("probe lost: %+v", res)
		}
		if ghostPresent() {
			t.Fatal("stale entry survived: the elapsed prune window must scan on write")
		}
		certReadMu.Lock()
		pruned := certReadLastPrune
		certReadMu.Unlock()
		if time.Since(pruned) > time.Minute {
			t.Fatalf("certReadLastPrune not advanced by the scan: %v", pruned)
		}
	})

	t.Run("windowFreshScanSkipped", func(t *testing.T) {
		seedGhost(time.Now())
		if res := probeHTTP(context.Background(), srv.URL, 5*time.Second); res.Lost {
			t.Fatalf("probe lost: %+v", res)
		}
		if !ghostPresent() {
			t.Fatal("stale entry pruned within the window: the scan must run at most once per certFreshness window")
		}
	})
}
