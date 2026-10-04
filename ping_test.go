package main

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"
)

// TestDeliverStaleReplyDoesNotEvict locks the core fix for the seq-collision
// bug: a reply for a seq that a DIFFERENT destination also uses must NOT
// evict the live probe's slot. With the old seq-only key, deliver() removed
// the (overwritten) entry before its source-IP check, so the live probe's
// genuine reply was later dropped as a false loss.
func TestDeliverStaleReplyDoesNotEvict(t *testing.T) {
	dstA := net.ParseIP("10.0.0.1").To4()
	dstB := net.ParseIP("10.0.0.2").To4()
	const seq = uint16(42)

	pendingMu.Lock()
	delete(pending, mkKey(seq, dstA))
	pendingMu.Unlock()

	e := &Engine{}

	// Probe A is in flight to dstA.
	chA := make(chan time.Duration, 1)
	pendingMu.Lock()
	pending[mkKey(seq, dstA)] = &pendingPing{dst: dstA, start: time.Now(), ch: chA}
	pendingMu.Unlock()

	// A stale reply for the same seq but from a DIFFERENT destination must
	// not evict probe A's slot.
	e.deliver(seq, dstB)

	pendingMu.Lock()
	_, stillThere := pending[mkKey(seq, dstA)]
	pendingMu.Unlock()
	if !stillThere {
		t.Fatal("stale cross-destination reply evicted the live probe's slot")
	}

	// The genuine reply from dstA still delivers and removes the entry.
	e.deliver(seq, dstA)
	select {
	case <-chA:
	default:
		t.Fatal("genuine reply did not deliver to the probe channel")
	}
	pendingMu.Lock()
	_, gone := pending[mkKey(seq, dstA)]
	pendingMu.Unlock()
	if gone {
		t.Fatal("entry not removed after genuine reply")
	}
}

// TestDeliverSameSeqDifferentDsts locks the compound-key isolation: two
// in-flight probes that happen to share a seq but target different
// destinations each receive their own reply. With the old seq-only key the
// second insert overwrote the first, so neither probe was delivered.
func TestDeliverSameSeqDifferentDsts(t *testing.T) {
	dstA := net.ParseIP("10.0.0.1").To4()
	dstB := net.ParseIP("10.0.0.2").To4()
	const seq = uint16(99)

	pendingMu.Lock()
	delete(pending, mkKey(seq, dstA))
	delete(pending, mkKey(seq, dstB))
	pendingMu.Unlock()

	e := &Engine{}
	chA := make(chan time.Duration, 1)
	chB := make(chan time.Duration, 1)
	pendingMu.Lock()
	pending[mkKey(seq, dstA)] = &pendingPing{dst: dstA, start: time.Now(), ch: chA}
	pending[mkKey(seq, dstB)] = &pendingPing{dst: dstB, start: time.Now(), ch: chB}
	pendingMu.Unlock()

	e.deliver(seq, dstA)
	e.deliver(seq, dstB)

	for name, ch := range map[string]chan time.Duration{"A": chA, "B": chB} {
		select {
		case <-ch:
		default:
			t.Fatalf("probe %s did not receive its reply", name)
		}
	}
	pendingMu.Lock()
	if _, a := pending[mkKey(seq, dstA)]; a {
		t.Error("probe A entry not removed")
	}
	if _, b := pending[mkKey(seq, dstB)]; b {
		t.Error("probe B entry not removed")
	}
	pendingMu.Unlock()
}

// TestResolveIPAddrWithTimeout locks the context-based resolver: literal IPs
// pass through, and a lookup that exceeds the deadline is CANCELLED — the
// function returns on time AND the resolver work does not keep running
// (the old goroutine+net.ResolveIPAddr pattern leaked one goroutine per
// timed-out probe).
func TestResolveIPAddrWithTimeout(t *testing.T) {
	// Literal IP: no DNS involved.
	ip, err := resolveIPAddrWithTimeout(context.Background(), "10.1.2.3", 5*time.Second)
	if err != nil {
		t.Fatalf("literal IP: %v", err)
	}
	if ip == nil || ip.IP.String() != "10.1.2.3" {
		t.Fatalf("literal IP: got %v, want 10.1.2.3", ip)
	}

	// Non-existent hostname: must fail (NXDOMAIN or no address), not hang.
	_, err = resolveIPAddrWithTimeout(context.Background(), "nonexistent-host-zenmon-test.invalid", 5*time.Second)
	if err == nil {
		t.Fatal("unresolvable host: got nil error, want a failure")
	}

	// Hanging resolver: a custom Dial that blocks until its context is done
	// (simulates a blackholed nameserver). With the old goroutine +
	// net.ResolveIPAddr pattern, that dial would never see the 150ms
	// deadline and the goroutine would leak. The context-based implementation
	// must return on the deadline with the dial cancelled, and no goroutines
	// left behind.
	old := net.DefaultResolver
	defer func() { net.DefaultResolver = old }()
	hangDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: hangDial}
	base := runtime.NumGoroutine()
	start := time.Now()
	ip, err = resolveIPAddrWithTimeout(context.Background(), "hanging-host-zenmon-test.invalid", 150*time.Millisecond)
	elapsed := time.Since(start)
	if ip != nil {
		t.Fatal("hanging resolver: expected nil IP")
	}
	if err == nil {
		t.Fatal("hanging resolver: expected timeout error")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("hanging resolver: took %v, want ~150ms deadline", elapsed)
	}

	// Give any leaked resolver goroutines a beat to show up, then confirm
	// the count has settled (small margin for scheduler noise).
	time.Sleep(500 * time.Millisecond)
	now := runtime.NumGoroutine()
	if now > base+5 {
		t.Errorf("resolver leak: goroutines %d -> %d after timed-out lookup", base, now)
	}
}
