package main

import (
	"net"
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
