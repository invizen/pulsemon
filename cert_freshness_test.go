package main

// Cert-freshness: a pooled conn is reused within certFreshness (no forced
// handshake), and the cert-cache key is the ORIGINAL target (not the final hop).

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

// TestCertFreshnessReusesConn verifies the cert-freshness optimization:
// after a successful HTTPS probe with cert data, certReadTimes records the
// host; a subsequent probe within certFreshness reuses the pooled
// connection (no forced fresh handshake). After the threshold expires, a
// fresh handshake is forced again.
func TestCertFreshnessReusesConn(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Clear the map so the first probe definitely forces a fresh handshake.
	certReadMu.Lock()
	oldMap := certReadTimes
	certReadTimes = make(map[string]time.Time)
	certReadMu.Unlock()
	t.Cleanup(func() {
		certReadMu.Lock()
		certReadTimes = oldMap
		certReadMu.Unlock()
	})

	// Extract the host key the probe will use.
	hostKey := "https://" + srv.Listener.Addr().String()

	// 1. First probe: no entry in certReadTimes → req.Close = true
	//    (fresh handshake). After the probe, certReadTimes must have an
	//    entry for the host.
	res := probeHTTP(context.Background(), srv.URL, 5*time.Second)
	if res.Lost {
		t.Fatalf("first probe lost: %+v", res)
	}
	if res.CertExpiry == nil {
		t.Fatal("first probe: no cert expiry captured")
	}
	certReadMu.Lock()
	firstRead, ok := certReadTimes[hostKey]
	certReadMu.Unlock()
	if !ok {
		t.Fatalf("certReadTimes has no entry for %q after first probe", hostKey)
	}

	// 2. Second probe (immediately after): cert is fresh → req.Close =
	//    false (reuses the pooled conn). The entry timestamp should be
	//    updated (newer than the first read).
	time.Sleep(5 * time.Millisecond) // ensure a distinguishable timestamp
	res = probeHTTP(context.Background(), srv.URL, 5*time.Second)
	if res.Lost {
		t.Fatalf("second probe lost: %+v", res)
	}
	certReadMu.Lock()
	secondRead, ok := certReadTimes[hostKey]
	certReadMu.Unlock()
	if !ok {
		t.Fatal("certReadTimes entry disappeared after second probe")
	}
	if !secondRead.After(firstRead) {
		t.Errorf("certReadTimes not updated: first=%v second=%v", firstRead, secondRead)
	}

	// 3. Simulate staleness: backdate the entry past certFreshness.
	//    The next probe must force a fresh handshake again (req.Close =
	//    true). We verify this indirectly: the entry is updated again.
	certReadMu.Lock()
	certReadTimes[hostKey] = time.Now().Add(-certFreshness - time.Second)
	certReadMu.Unlock()
	time.Sleep(5 * time.Millisecond)
	res = probeHTTP(context.Background(), srv.URL, 5*time.Second)
	if res.Lost {
		t.Fatalf("third probe (stale cert) lost: %+v", res)
	}
	certReadMu.Lock()
	thirdRead := certReadTimes[hostKey]
	certReadMu.Unlock()
	if thirdRead.IsZero() || thirdRead.Before(time.Now().Add(-time.Second)) {
		t.Errorf("stale cert not re-read: entry=%v, want recent", thirdRead)
	}
}

// TestCertReadKeyIsOriginalTarget pins the redirect cert-cache key: for an
// HTTPS target that redirects, the cert read is recorded under the ORIGINAL
// target (req.URL, the first hop) — the same key probeHTTP reads — not the
// final hop. Pre-fix it was keyed on the final hop, so read and write used
// different keys and a redirecting target forced a fresh handshake on every
// probe.

// TestCertReadKeyIsOriginalTarget pins the redirect cert-cache key: for an
// HTTPS target that redirects, the cert read is recorded under the ORIGINAL
// target (req.URL, the first hop) — the same key probeHTTP reads — not the
// final hop. Pre-fix it was keyed on the final hop, so read and write used
// different keys and a redirecting target forced a fresh handshake on every
// probe.
func TestCertReadKeyIsOriginalTarget(t *testing.T) {
	const targetHost = "certkey-target.example.test"
	cert := selfSignedTLSForHost(t, targetHost)

	tlsSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	tlsSrv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	tlsSrv.StartTLS()
	defer tlsSrv.Close()
	targetPort := tlsSrv.Listener.Addr().(*net.TCPAddr).Port

	// Origin 302s to the cross-host TLS target.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, fmt.Sprintf("https://%s:%d/", targetHost, targetPort), http.StatusFound)
	}))
	defer origin.Close()

	startFakeDNS(t, "10.99.99.50") // target → RFC1918 (passes the redirect guard)
	oldDialer := probeDialer
	probeDialer = loopbackDialer{}
	t.Cleanup(func() { probeDialer = oldDialer })

	// Clear the map so we can assert exactly which key the probe writes.
	certReadMu.Lock()
	oldMap := certReadTimes
	certReadTimes = make(map[string]time.Time)
	certReadMu.Unlock()
	t.Cleanup(func() {
		certReadMu.Lock()
		certReadTimes = oldMap
		certReadMu.Unlock()
	})

	originKey := "http://" + origin.Listener.Addr().String()

	res := probeHTTP(context.Background(), origin.URL, 5*time.Second)
	if res.Lost {
		t.Fatalf("probe lost, want 200: %+v", res)
	}
	if res.CertExpiry == nil {
		t.Fatal("no cert captured (the TLS hop was not reached)")
	}
	certReadMu.Lock()
	_, origOK := certReadTimes[originKey]
	var keys []string
	for k := range certReadTimes {
		keys = append(keys, k)
	}
	_, finalOK := certReadTimes["https://"+fmt.Sprintf("%s:%d", targetHost, targetPort)]
	certReadMu.Unlock()
	if !origOK {
		t.Fatalf("certReadTimes not keyed under the original target %q; got %v", originKey, keys)
	}
	if finalOK {
		t.Errorf("certReadTimes keyed under the final hop (pre-fix behavior)")
	}
}

// TestStaleCertProbeForcesFreshDial proves the stale-cert refresh lands in
// the SAME probe, not one probe late: probe 1 (no cert entry) dials and
// closes, probe 2 (fresh cert) keep-alives into the pool, the entry is then
// backdated past certFreshness, and probe 3 (req.Close set) must open a
// THIRD connection — a fresh handshake whose cert is the one reported. On
// the pooled transport req.Close rides probe 2's idle conn (getConn serves
// it regardless of the flag; verified on Go 1.26), so the "fresh handshake"
// the flag claimed to force was a lie until the flagged-request routing
// (probeFreshTransport) made it real.
func TestStaleCertProbeForcesFreshDial(t *testing.T) {
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
	certReadTimes = make(map[string]time.Time)
	certReadMu.Unlock()
	t.Cleanup(func() {
		certReadMu.Lock()
		certReadTimes = oldMap
		certReadMu.Unlock()
	})

	ctx := context.Background()
	for i := 1; i <= 2; i++ {
		if res := probeHTTP(ctx, srv.URL, 5*time.Second); res.Lost {
			t.Fatalf("probe %d lost: %+v", i, res)
		}
	}
	certReadMu.Lock()
	certReadTimes[hostKey] = time.Now().Add(-certFreshness - time.Second)
	certReadMu.Unlock()
	if res := probeHTTP(ctx, srv.URL, 5*time.Second); res.Lost {
		t.Fatalf("stale-cert probe lost: %+v", res)
	}
	mu.Lock()
	n := len(seen)
	mu.Unlock()
	if n != 3 {
		t.Fatalf("server saw %d distinct connections over 3 probes, want 3 — the stale-cert probe rode the pooled conn (cert re-read lags one probe)", n)
	}
}
