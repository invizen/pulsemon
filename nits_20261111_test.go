package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// 2026-11-11 nit batch: probe identity moved from the transport wrapper to
// the request's creator (RoundTripper contract: do not mutate the caller's
// request), certReadTimes gained write-time pruning, and the graph cache
// lock moved inside ProbeWorker. These tests pin all three.

// TestProbeHTTPStampsUserAgent: probeHTTP stamps probeUserAgent on the
// request it builds (the stamp lives here now, not in uaRoundTripper).
func TestProbeHTTPStampsUserAgent(t *testing.T) {
	var mu sync.Mutex
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Get("User-Agent")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if res := probeHTTP(context.Background(), srv.URL, 5*time.Second); res.Lost {
		t.Fatalf("probe lost: %+v", res)
	}
	mu.Lock()
	defer mu.Unlock()
	if got != probeUserAgent {
		t.Fatalf("probe sent User-Agent %q, want %q", got, probeUserAgent)
	}
}

// TestProbeHTTPRedirectHopsCarryUA: the stamp rides every redirect hop
// because Client copies the initial request's headers onto each hop — the
// property that made the in-wrapper stamp redundant.
func TestProbeHTTPRedirectHopsCarryUA(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{} // role -> UA
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen["dest"] = r.Header.Get("User-Agent")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer dest.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen["origin"] = r.Header.Get("User-Agent")
		mu.Unlock()
		http.Redirect(w, r, dest.URL+"/", http.StatusFound)
	}))
	defer origin.Close()
	if res := probeHTTP(context.Background(), origin.URL, 5*time.Second); res.Lost {
		t.Fatalf("probe lost: %+v", res)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, role := range []string{"origin", "dest"} {
		if seen[role] != probeUserAgent {
			t.Errorf("%s saw User-Agent %q, want %q (hop must inherit the stamp)", role, seen[role], probeUserAgent)
		}
	}
}

// TestUARoundTripperDoesNotMutateRequest: the wrapper is routing-only. A
// RoundTripper must not modify the caller's request (net/http contract), so
// RoundTrip leaves the header exactly as the caller built it.
func TestUARoundTripperDoesNotMutateRequest(t *testing.T) {
	rt := uaRoundTripper{
		base:  roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil }),
		fresh: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil }),
	}
	r, err := http.NewRequest(http.MethodGet, "https://h.example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = rt.RoundTrip(r)
	if ua := r.Header.Get("User-Agent"); ua != "" {
		t.Fatalf("RoundTrip mutated the caller's request: stamped User-Agent %q", ua)
	}
}

// TestCertReadTimesPrunedOnWrite: the cert-read write path deletes entries
// older than certFreshness. Pruning is loss-free (the only reader treats a
// stale entry exactly like a missing one — both force a fresh handshake),
// and it is what bounds the map by LIVE HTTPS hosts: without it, every
// edited or deleted sensor target leaves a permanent entry.
func TestCertReadTimesPrunedOnWrite(t *testing.T) {
	cert := testSelfSigned(t, time.Now().Add(48*time.Hour))
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	hostKey := "https://" + srv.Listener.Addr().String()
	certReadMu.Lock()
	oldMap := certReadTimes
	certReadTimes = map[string]time.Time{
		"https://ghost-a.invalid:443": time.Now().Add(-certFreshness - time.Minute),
		"https://ghost-b.invalid:443": time.Now().Add(-certFreshness - time.Hour),
		"https://ghost-c.invalid:443": time.Now().Add(-time.Second), // fresh: must survive
	}
	certReadMu.Unlock()
	t.Cleanup(func() {
		certReadMu.Lock()
		certReadTimes = oldMap
		certReadMu.Unlock()
	})

	if res := probeHTTP(context.Background(), srv.URL, 5*time.Second); res.Lost {
		t.Fatalf("probe lost: %+v", res)
	}
	certReadMu.Lock()
	defer certReadMu.Unlock()
	if _, ok := certReadTimes[hostKey]; !ok {
		t.Fatalf("live host %q not recorded: %v", hostKey, certReadTimes)
	}
	for k := range certReadTimes {
		if strings.HasPrefix(k, "https://ghost-a") || strings.HasPrefix(k, "https://ghost-b") {
			t.Errorf("stale entry %q survived the write-time prune", k)
		}
	}
	if _, ok := certReadTimes["https://ghost-c.invalid:443"]; !ok {
		t.Error("fresh entry pruned: prune window must be certFreshness, not every write")
	}
}

// TestWorkerGraphMethodParity: ProbeWorker.Graph returns exactly what
// graphPoints computes under the same anchor, nil for an unknown sensor,
// and is the only lock-taking door into the series for handlers.
func TestWorkerGraphMethodParity(t *testing.T) {
	pw := NewProbeWorker(nil)
	now := time.Now().Unix()
	for i := 0; i < 10; i++ {
		pw.recordProbe("g", probeEntry{ts: now - int64(10-i)*60, rtt: 2.0})
	}
	for _, tc := range []struct{ bucket, rng int }{{60, 3600}, {900, 86400}} {
		pw.statsMu.RLock()
		ser := pw.statsCache["g"]
		want := ser.graphPoints(tc.bucket, tc.rng, now)
		pw.statsMu.RUnlock()
		got := pw.Graph("g", tc.bucket, tc.rng)
		if len(got) != len(want) {
			t.Fatalf("bucket=%d: Graph returned %d points, graphPoints %d", tc.bucket, len(got), len(want))
		}
		for i := range want {
			fv := func(p *float64) float64 {
				if p == nil {
					return -1
				}
				return *p
			}
			if got[i].T != want[i].T || got[i].Total != want[i].Total ||
				got[i].Lost != want[i].Lost || got[i].LossPct != want[i].LossPct ||
				fv(got[i].Avg) != fv(want[i].Avg) || fv(got[i].Max) != fv(want[i].Max) {
				t.Fatalf("bucket=%d point %d: Graph %+v != graphPoints %+v", tc.bucket, i, got[i], want[i])
			}
		}
	}
	if pw.Graph("missing", 60, 3600) != nil {
		t.Fatal("Graph(unknown sensor) must be nil (handler maps nil -> empty graph)")
	}
}
