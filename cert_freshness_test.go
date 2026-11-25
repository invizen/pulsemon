package main

// Cert-freshness: a pooled conn is reused within certFreshness (no forced
// handshake), and the cert-cache key is the ORIGINAL target (not the final hop).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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
	//    false (pooled transport). Probe 1's conn was on the no-reuse
	//    transport (probe 1 had no entry → req.Close), so nothing is
	//    pooled yet — this probe dials fresh ON the pooled transport, a
	//    real handshake, so the timestamp advances. The keep-alive-reuse
	//    case (which must NOT advance it) is pinned in
	//    TestCertReadTimesNotRefreshedOnKeepAliveReuse.
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

// TestCertRefreshEvictsPooledConn proves the pool rotates when the target
// RENEWS its cert: probe 1 dials (no cert entry), probe 2 keep-alives the
// pre-renewal conn into the pooled transport, the target then renews and
// the entry is backdated past certFreshness, so probe 3 forces a fresh
// handshake (must see the NEW cert) and probe 4 (entry fresh again,
// req.Close = false) must NOT reuse probe 2's old conn — it must report
// the new cert. Pre-fix, probe 4 reused the pooled pre-renewal conn and
// flipped the reported cert_expiry back to the old cert for up to
// IdleConnTimeout (10 min) after every renewal, oscillating until the
// target closed the idle socket. The server's cert slice is swapped at
// renewal, so each fresh dial presents the new cert while existing conns
// keep the cert from their original handshake. History: docs/DECISIONS.md
// -> cert-freshness-pool-eviction
func TestCertRefreshEvictsPooledConn(t *testing.T) {
	oldCert := testSelfSigned(t, time.Now().Add(24*time.Hour))
	newCert := testSelfSigned(t, time.Now().Add(72*time.Hour))
	newLeaf, err := x509.ParseCertificate(newCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse renewed cert: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	// Certificates is PRE-SEEDED: Go 1.27's StartTLS injects a default
	// test cert whenever the slice is empty - and a non-empty Certificates
	// takes precedence over GetCertificate (which it then never calls),
	// so the GetCertificate hot-swap trick no longer works. Replacing the
	// slice is the renewal hook: the next handshake presents the new cert
	// while existing conns keep their original-handshake cert.
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{oldCert}}
	srv.StartTLS()
	defer srv.Close()
	t.Cleanup(func() {
		probeTransport.CloseIdleConnections()
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
	// Probe 1: no cert entry -> fresh dial on the no-reuse transport.
	if res := probeHTTP(ctx, srv.URL, 5*time.Second); res.Lost {
		t.Fatalf("probe 1 lost: %+v", res)
	}
	// Probe 2: entry fresh -> pooled transport dials and keep-alives the
	// pre-renewal conn into the idle pool.
	if res := probeHTTP(ctx, srv.URL, 5*time.Second); res.Lost {
		t.Fatalf("probe 2 lost: %+v", res)
	}
	// The target renews its cert, and the freshness window elapses.
	srv.TLS.Certificates = []tls.Certificate{newCert}
	certReadMu.Lock()
	certReadTimes[hostKey] = time.Now().Add(-certFreshness - time.Second)
	certReadMu.Unlock()
	// Probe 3: stale entry -> forced fresh handshake: must see the NEW
	// cert (also proves the renewal landed before this probe's dial).
	res3 := probeHTTP(ctx, srv.URL, 5*time.Second)
	if res3.Lost {
		t.Fatalf("probe 3 (stale) lost: %+v", res3)
	}
	if res3.CertExpiry == nil || !res3.CertExpiry.Equal(newLeaf.NotAfter) {
		t.Fatalf("probe 3 reported cert expiry %v, want the renewed cert's %v (the renewal must land in the same probe)", res3.CertExpiry, newLeaf.NotAfter)
	}
	// Probe 4: entry fresh again -> pooled transport. Pre-fix this reused
	// probe 2's old conn and reported the pre-renewal cert (the
	// cert_expiry oscillation).
	res4 := probeHTTP(ctx, srv.URL, 5*time.Second)
	if res4.Lost {
		t.Fatalf("probe 4 lost: %+v", res4)
	}
	if res4.CertExpiry == nil || !res4.CertExpiry.Equal(newLeaf.NotAfter) {
		t.Fatalf("probe 4 reported cert expiry %v, want the renewed cert's %v — the pooled pre-renewal conn was not evicted on the cert refresh", res4.CertExpiry, newLeaf.NotAfter)
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
	oldPrune := certReadLastPrune
	certReadTimes = map[string]time.Time{
		"https://ghost-a.invalid:443": time.Now().Add(-certFreshness - time.Minute),
		"https://ghost-b.invalid:443": time.Now().Add(-certFreshness - time.Hour),
		"https://ghost-c.invalid:443": time.Now().Add(-time.Second), // fresh: must survive
	}
	// Prune-window precondition: the window has elapsed, so this write
	// MUST run the scan (pruning is throttled to once per window).
	certReadLastPrune = time.Time{}
	certReadMu.Unlock()
	t.Cleanup(func() {
		certReadMu.Lock()
		certReadTimes = oldMap
		certReadLastPrune = oldPrune
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
