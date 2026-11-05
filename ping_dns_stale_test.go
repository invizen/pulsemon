package main

// Bounded-staleness DNS tests (finding 3, 2026-11-05): a homelab resolver
// (Pi-hole/AdGuard) is itself a monitored sensor. When it dies, every
// hostname sensor's re-resolution fails at once — pre-fix each probe
// became a loss, so one root cause read as "N hosts down" and tripped the
// storm path. The fix serves the last good IP while re-resolution fails
// (bounded by dnsStaleMaxAge), collapses concurrent lookups through
// singleflight, and surfaces a DNS loss on the probe row (probes.dns_error)
// instead of recording it as packet loss.
//
// Tests stub resolveIPAddrWithTimeout (a var, like probeTarget) and seed
// dnsCache directly, so they are deterministic: no real network, no
// /etc/hosts dependence, no resolver swapping.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"pulsemon/internal/store"
)

// stubResolver replaces resolveIPAddrWithTimeout for the test and restores
// the real one afterwards.
func stubResolver(t *testing.T, fn func(ctx context.Context, host string, timeout time.Duration) (*net.IPAddr, error)) {
	t.Helper()
	orig := resolveIPAddrWithTimeout
	resolveIPAddrWithTimeout = fn
	t.Cleanup(func() { resolveIPAddrWithTimeout = orig })
}

// clearDNSCache drops one target from the cache.
func clearDNSCache(t *testing.T, target string) {
	t.Helper()
	dnsCacheMu.Lock()
	delete(dnsCache, target)
	dnsCacheMu.Unlock()
}

// seedDNSCache writes a cache entry whose expiry is `age` in the PAST
// (age > 0 = already expired; age < 0 = still fresh). Seeding directly lets
// a test start from an expired-without-a-failure state, which is exactly the
// resolver-death moment.
func seedDNSCache(t *testing.T, target string, ip net.IP, age time.Duration) {
	t.Helper()
	dnsCacheMu.Lock()
	dnsCache[target] = dnsCacheEntry{ip: ip, expires: time.Now().Add(-age)}
	dnsCacheMu.Unlock()
	t.Cleanup(func() { clearDNSCache(t, target) })
}

// failResolver makes every resolution fail (a dead resolver).
func failResolver(t *testing.T) {
	t.Helper()
	stubResolver(t, func(ctx context.Context, host string, timeout time.Duration) (*net.IPAddr, error) {
		return nil, errors.New("resolver down (test)")
	})
}

// TestResolveICMPTargetServesStaleOnResolutionFailure: the resolver-death
// scenario — an entry is cached, it expires, the resolver dies; the stale IP
// is served (no loss) while re-resolution fails.
func TestResolveICMPTargetServesStaleOnResolutionFailure(t *testing.T) {
	const target = "stale-serve-pulsemon-test.invalid"
	good := net.ParseIP("10.9.9.9").To4()
	seedDNSCache(t, target, good, time.Second) // expired 1s ago
	failResolver(t)

	got, err := resolveICMPTarget(context.Background(), target)
	if err != nil {
		t.Fatalf("stale resolution returned an error (the resolver-death loss): %v", err)
	}
	if !got.Equal(good) {
		t.Fatalf("stale IP = %v, want the last good %v", got, good)
	}
}

// TestResolveICMPTargetStaleBound: past dnsStaleMaxAge the stale IP is no
// longer trusted and the DNS error surfaces again (bounded staleness, not
// eternal).
func TestResolveICMPTargetStaleBound(t *testing.T) {
	const target = "stale-bound-pulsemon-test.invalid"
	seedDNSCache(t, target, net.ParseIP("10.9.9.9").To4(), dnsStaleMaxAge+time.Minute)
	failResolver(t)

	if _, err := resolveICMPTarget(context.Background(), target); err == nil {
		t.Fatal("an IP older than the staleness window was served; the DNS error must surface")
	}
}

// TestResolveICMPTargetRecoversAfterResolverReturns: when the resolver
// comes back, a fresh resolution replaces the stale entry — no permanent
// pin to the old IP.
func TestResolveICMPTargetRecoversAfterResolverReturns(t *testing.T) {
	const target = "recover-pulsemon-test.invalid"
	old := net.ParseIP("10.9.9.9").To4()
	fresh := net.ParseIP("10.9.9.25").To4()
	seedDNSCache(t, target, old, time.Second) // expired

	// Resolver is down → stale IP served.
	failResolver(t)
	if got, err := resolveICMPTarget(context.Background(), target); err != nil || !got.Equal(old) {
		t.Fatalf("stale phase: got %v, %v; want the stale %v", got, err, old)
	}

	// Resolver recovers → a fresh resolution is cached and returned.
	stubResolver(t, func(ctx context.Context, host string, timeout time.Duration) (*net.IPAddr, error) {
		return &net.IPAddr{IP: fresh}, nil
	})
	got, err := resolveICMPTarget(context.Background(), target)
	if err != nil {
		t.Fatalf("post-recovery resolution failed: %v", err)
	}
	if !got.Equal(fresh) {
		t.Fatalf("post-recovery IP = %v, want the fresh %v", got, fresh)
	}
	dnsCacheMu.Lock()
	e := dnsCache[target]
	dnsCacheMu.Unlock()
	if !e.ip.Equal(fresh) || !time.Now().Before(e.expires) {
		t.Fatalf("the recovered resolution did not refresh the cache entry (ip=%v expires=%v)", e.ip, e.expires)
	}
}

// TestDNSLookupSingleflight: concurrent lookups of the same name collapse
// into ONE underlying resolution (many sensors expiring together must not
// fire N lookups at a dying resolver). Counted at the resolver boundary, so
// it is independent of the resolver's own internal behavior.
func TestDNSLookupSingleflight(t *testing.T) {
	const target = "singleflight-host-pulsemon-test.invalid"
	clearDNSCache(t, target)
	var calls int32
	stubResolver(t, func(ctx context.Context, host string, timeout time.Duration) (*net.IPAddr, error) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(150 * time.Millisecond) // force real overlap
		return nil, errors.New("dns down (test)")
	})

	const n = 6
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = resolveICMPTarget(context.Background(), target)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err == nil {
			t.Fatalf("caller %d: expected a resolution failure", i)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("resolveIPAddrWithTimeout calls = %d, want 1 (singleflight must collapse concurrent same-name lookups)", got)
	}
}

// TestResolveICMPTargetSweepKeepsStaleWindow: the opportunistic sweep
// (triggered by a successful write once the map is over 128 entries) must
// not destroy an entry that is still inside its staleness window — that
// entry is a live fallback for a failing re-resolution — while it DOES drop
// an entry expired past the window.
func TestResolveICMPTargetSweepKeepsStaleWindow(t *testing.T) {
	const keep = "sweep-keep-pulsemon-test.invalid"
	const drop = "sweep-drop-pulsemon-test.invalid"
	seedDNSCache(t, keep, net.ParseIP("10.1.1.1").To4(), time.Minute)              // expired, inside the window
	seedDNSCache(t, drop, net.ParseIP("10.1.2.2").To4(), dnsStaleMaxAge+time.Hour) // expired past the window
	dnsCacheMu.Lock()
	now := time.Now()
	for i := 0; i < 130; i++ {
		dnsCache[fmt.Sprintf("sweep-fill-%03d", i)] = dnsCacheEntry{ip: net.ParseIP("10.2.0.1").To4(), expires: now.Add(time.Minute)}
	}
	dnsCacheMu.Unlock()
	t.Cleanup(func() {
		dnsCacheMu.Lock()
		defer dnsCacheMu.Unlock()
		for k := range dnsCache {
			if strings.HasPrefix(k, "sweep-") {
				delete(dnsCache, k)
			}
		}
	})

	// Trigger the sweep with a successful resolution.
	stubResolver(t, func(ctx context.Context, host string, timeout time.Duration) (*net.IPAddr, error) {
		return &net.IPAddr{IP: net.ParseIP("127.0.0.1")}, nil
	})
	if _, err := resolveICMPTarget(context.Background(), "localhost"); err != nil {
		t.Fatalf("trigger resolution failed: %v", err)
	}
	dnsCacheMu.Lock()
	keepAlive := dnsCache[keep].ip != nil
	dropGone := dnsCache[drop].ip != nil
	dnsCacheMu.Unlock()
	if !keepAlive {
		t.Fatal("the sweep dropped an entry that is still inside its staleness window")
	}
	if dropGone {
		t.Fatal("the sweep kept an entry past its staleness window")
	}
}

// TestPingHostDNSFailureMarked: a probe lost at name resolution is marked
// DNS (surfaced on the probe row), not recorded as a plain packet loss.
func TestPingHostDNSFailureMarked(t *testing.T) {
	const target = "no-such-host-pulsemon-test.invalid"
	clearDNSCache(t, target)
	failResolver(t)

	res := pingHost(context.Background(), target, time.Second)
	if !res.Lost {
		t.Fatal("expected a lost probe")
	}
	if !res.DNS {
		t.Fatal("a name-resolution loss is not marked DNS")
	}
	if res.Error == nil {
		t.Fatal("the DNS error was not carried")
	}
}

// TestDoProbeRecordsDNSLossOnRow: a DNS loss is written to the probe row
// WITH its dns_error; a plain packet loss writes NULL. The row is what the
// operator (and the UI) see — a dead resolver must read as "DNS failure",
// not "N hosts down".
func TestDoProbeRecordsDNSLossOnRow(t *testing.T) {
	db, err := store.NewStore(t.TempDir() + "/dnsrow.db")
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('dnsr','dnsr','no-such-host-pulsemon-test.invalid','icmp',15,1000,25,1,3,'active','up','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}
	pw := NewProbeWorker(db)

	orig := probeTarget
	probeTarget = func(ctx context.Context, probeType, target string, timeout time.Duration) probeOutcome {
		return probeOutcome{lost: true, dnsErr: "DNS resolution of \"no-such-host-pulsemon-test.invalid\" timed out after 5s (test)"}
	}
	defer func() { probeTarget = orig }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pw.doProbe(ctx, sensorConfig{id: "dnsr", name: "dnsr", target: "no-such-host-pulsemon-test.invalid", probeType: "icmp", intervalS: 15, timeoutMS: 1000, lossWarn: 25, downAfter: 1})

	var dnsErr any
	if err := db.QueryRow("SELECT dns_error FROM probes WHERE sensor_id = 'dnsr'").Scan(&dnsErr); err != nil {
		t.Fatalf("read dns_error: %v", err)
	}
	if s, ok := dnsErr.(string); !ok || s == "" {
		t.Fatalf("dns loss row has no dns_error (got %v); it must be surfaced separately from packet loss", dnsErr)
	}

	// A plain packet loss writes NULL.
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('pktr','pktr','127.0.0.1','icmp',15,1000,25,1,3,'active','up','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}
	probeTarget = func(ctx context.Context, probeType, target string, timeout time.Duration) probeOutcome {
		return probeOutcome{lost: true, ip: "127.0.0.1"}
	}
	pw.doProbe(ctx, sensorConfig{id: "pktr", name: "pktr", target: "127.0.0.1", probeType: "icmp", intervalS: 15, timeoutMS: 1000, lossWarn: 25, downAfter: 1})
	if err := db.QueryRow("SELECT dns_error FROM probes WHERE sensor_id = 'pktr'").Scan(&dnsErr); err != nil {
		t.Fatalf("read dns_error: %v", err)
	}
	if dnsErr != nil {
		t.Fatalf("packet-loss row has dns_error %v; it must be NULL", dnsErr)
	}
}
