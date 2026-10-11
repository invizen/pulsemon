//go:build linux

package main

import (
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestEngineReaderRetriesEINTR is the deterministic regression test for the
// v0.1.21 production incident: a SIGURG (the runtime's thread-wake signal)
// interrupts the reader's poll() with EINTR, and unix.Poll — unlike
// syscall.Recvfrom — surfaces EINTR instead of retrying. If the reader treats
// EINTR as fatal, one signal ends the goroutine and every later probe is a
// false loss, silently. This test injects EINTR directly (no signal
// threading luck): the reader must survive and still be alive.
func TestEngineReaderRetriesEINTR(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("datagram ICMP + poll EINTR behavior is Linux-specific here")
	}
	e, err := NewEngine()
	if err != nil {
		t.Skipf("ICMP engine unavailable on this host: %v", err)
	}
	defer e.Close()
	if !e.isDgram {
		t.Skip("datagram transport unavailable; EINTR path is datagram-only")
	}

	// Inject EINTR on the first 3 poll calls, then real behavior. The poll
	// seam lives on the Linux datagram driver (ping_linux.go), not the Engine.
	var calls int32
	e.dgram.(*dgramTransport).pollFn = func(fds []unix.PollFd, timeout int) (int, error) {
		if atomic.AddInt32(&calls, 1) <= 3 {
			return 0, unix.EINTR
		}
		return unix.Poll(fds, timeout)
	}

	e.run()
	defer e.Close()

	// The reader must survive the injected EINTRs and still be running.
	deadline := time.Now().Add(3 * time.Second)
	for atomic.LoadInt32(&e.readerAlive) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt32(&e.readerAlive) != 1 {
		t.Fatal("reader exited after injected EINTR — EINTR must be retried, not fatal (v0.1.21 regression)")
	}
	if got := atomic.LoadInt32(&calls); got < 3 {
		t.Fatalf("poll was only called %d times — reader exited before consuming the injected EINTRs", got)
	}

	// And it must still deliver real replies after the interruptions.
	if res := e.Ping(net.ParseIP("127.0.0.1"), 500*time.Millisecond); res.Lost {
		t.Fatal("reader not delivering after EINTR interruptions")
	}
}

// TestEngineReaderSurvivesSignalInterrupt reproduces a real production
// regression: the datagram reader must NOT die when the process is hit by a
// signal. The Go runtime wakes parked threads with SIGURG, and unix.Poll
// (unlike syscall.Recvfrom, which retries internally) surfaces EINTR to us.
// If the reader treated EINTR as fatal, one SIGURG during its poll would end
// the goroutine and every later probe would be a false loss — with no log
// line, so it looks like "all sensors dropped".
//
// We storm the process with self-SIGURG while pinging loopback; the reader
// must keep delivering. On the old code the reader dies mid-storm and the
// final pings are lost.
func TestEngineReaderSurvivesSignalInterrupt(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SIGURG/EINTR behavior is Linux-specific here")
	}
	e, err := NewEngine()
	if err != nil {
		t.Skipf("ICMP engine unavailable on this host: %v", err)
	}
	defer e.Close()
	e.run()

	// Warm-up: prove the reader is alive and delivering on loopback.
	if res := e.Ping(net.ParseIP("127.0.0.1"), 500*time.Millisecond); res.Lost {
		t.Skip("loopback ICMP not available here — cannot prove reader delivery")
	}

	// Storm SIGURG at the process as fast as possible, exactly like the Go
	// runtime does (async preemption fires SIGURG at a random thread). A
	// reader that dies on its first EINTR — the production v0.1.21 bug —
	// dies on the first SIGURG that lands in its poll().
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			syscall.Kill(os.Getpid(), syscall.SIGURG)
		}
	}()

	const pings = 1000
	lost, consecLost := 0, 0
	for i := 0; i < pings; i++ {
		if res := e.Ping(net.ParseIP("127.0.0.1"), 100*time.Millisecond); res.Lost {
			lost++
			consecLost++
			// 10 consecutive losses = the reader is gone (each loss costs the
			// full 100ms timeout); fail fast instead of burning the rest.
			if consecLost >= 10 {
				close(stop)
				t.Fatalf("reader died under SIGURG storm: %d/%d lost, then 10 consecutive losses (reader must survive EINTR)", lost, i+1)
			}
		} else {
			consecLost = 0
		}
	}
	close(stop)

	// Final proof: after the storm the reader still delivers.
	time.Sleep(50 * time.Millisecond)
	if res := e.Ping(net.ParseIP("127.0.0.1"), 500*time.Millisecond); res.Lost {
		t.Fatal("reader not delivering after SIGURG storm — it exited on EINTR")
	}
}
