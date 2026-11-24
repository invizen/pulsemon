package main

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync/atomic"
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
	pending[mkKey(seq, dstA)] = &pendingPing{start: time.Now(), ch: chA}
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
	pending[mkKey(seq, dstA)] = &pendingPing{start: time.Now(), ch: chA}
	pending[mkKey(seq, dstB)] = &pendingPing{start: time.Now(), ch: chB}
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

// TestProbePayloadWithinCap locks the payload-size invariant: the probe
// identifier must stay within payloadSize (enforced at startup by init).
// If a future edit lengthens the identifier past the cap, this test fails
// alongside the init() panic, catching the regression before it ships.
func TestProbePayloadWithinCap(t *testing.T) {
	if len(probePayload) > payloadSize {
		t.Fatalf("probePayload is %d bytes, exceeds payloadSize %d", len(probePayload), payloadSize)
	}
	// The on-wire echo request is header + payload; confirm it stays small.
	if total := 8 + len(probePayload); total > 40 {
		t.Fatalf("echo request would be %d bytes, unexpectedly large", total)
	}
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
	_, err = resolveIPAddrWithTimeout(context.Background(), "nonexistent-host-pulsemon-test.invalid", 5*time.Second)
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
	ip, err = resolveIPAddrWithTimeout(context.Background(), "hanging-host-pulsemon-test.invalid", 150*time.Millisecond)
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

// TestPingStartStampedAtPublish pins that a probe's start time is stamped
// before the pendingPing is visible to the reader, so a reply processed
// inside the send path (the tightest possible reader/probe overlap)
// measures against a stamped start — not the zero time. On the old shape
// (stamp after publish) the synchronous reply read p.start before its
// write and the RTT came out as the distance from January 1, 1970.
// The mutex is the synchronization edge; the fdMutex atomics in the real
// send path made the old order benign in practice, not in law.
func TestPingStartStampedAtPublish(t *testing.T) {
	dst := net.ParseIP("10.9.9.9").To4()
	e := &Engine{}
	e.send = func(d net.IP, seq uint16) error {
		e.deliver(seq, d) // loopback-style reply: reader runs inside send
		return nil
	}
	res := e.Ping(context.Background(), dst, time.Second)
	if res.Lost {
		t.Fatalf("synchronous reply did not deliver: %+v", res)
	}
	if res.RTT > time.Second {
		t.Fatalf("RTT %v stamped against a zero start — start must be stamped under pendingMu at publish", res.RTT)
	}
}

// TestDeliverRacesPublishStampSynchronized drives the memory-model edge
// directly: with the start stamp taken under pendingMu at the publish
// point, a reader that picks up the entry under the same mutex is ordered
// against the stamp. Under the old shape (stamp after publish, outside
// the lock) the reader's time.Since(p.start) and the stamp are two
// unsynchronized accesses on different goroutines — -race fires.
func TestDeliverRacesPublishStampSynchronized(t *testing.T) {
	dst := net.ParseIP("10.9.9.8").To4()
	e := &Engine{send: func(net.IP, uint16) error {
		time.Sleep(20 * time.Millisecond) // hold the entry open for the hammer
		return errors.New("test: send held")
	}}
	for round := 0; round < 20; round++ {
		// Ping's first seq is the counter's next value after this Add.
		seq := uint16(atomic.LoadUint32(&seqCounter) + 1)
		done := make(chan struct{})
		go func() {
			for i := 0; i < 500; i++ {
				e.deliver(seq, dst)
			}
			close(done)
		}()
		e.Ping(context.Background(), dst, 200*time.Millisecond)
		<-done
	}
}

// TestPingHostBoundsDNSToTimeout pins the ICMP fix: the DNS lookup and the
// reply wait are bounded TOGETHER by the probe timeout (mirror of probeTCP /
// probeHTTP). Before the fix the DNS ran its own latency ON TOP of the
// timeout, so a slow resolver + a 30s Pulse Now could outlast the server's
// 30s WriteTimeout and the client got nothing. A resolver that takes 1s must
// not make a 200ms probe take 1s.
func TestPingHostBoundsDNSToTimeout(t *testing.T) {
	const target = "slowdns.example"
	stubResolver(t, func(ctx context.Context, host string, timeout time.Duration) (*net.IPAddr, error) {
		// Simulate a slow/hung resolver (far longer than the probe timeout).
		<-time.After(1 * time.Second)
		return &net.IPAddr{IP: net.ParseIP("192.0.2.1")}, nil
	})
	clearDNSCache(t, target)

	start := time.Now()
	res := pingHost(context.Background(), target, 200*time.Millisecond)
	elapsed := time.Since(start)
	if !res.Lost || !res.DNS {
		t.Fatalf("1s-slow DNS on a 200ms timeout: want a DNS loss, got %+v", res)
	}
	if elapsed > 800*time.Millisecond {
		t.Fatalf("pingHost took %v; the DNS phase must be bounded by the 200ms probe timeout, not added on top of it", elapsed)
	}
	// Drain the background singleflight call so the stub-swap cleanup in
	// t.Cleanup doesn't race the still-running shared-call goroutine: a
	// second dnsLookup on the same target JOINS the in-flight call and
	// blocks until it completes — the channel receive is the happens-before
	// edge that orders the cleanup's write after the shared call's read.
	// (pingHost returned early via ctx.Done() without joining, so without
	// this the -race run flags the stub swap.)
	_, _ = dnsLookup(context.Background(), target)
}
