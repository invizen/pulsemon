//go:build linux

package main

import (
	"context"
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// TestEngineReaderSurvivesSignalInterrupt reproduces a real production
// regression: the datagram reader must NOT die when the process is hit by a
// signal. The Go runtime wakes parked threads with SIGURG, and the netpoller
// (which drives the x/net/icmp ReadFrom) handles EINTR internally. If the
// reader treated EINTR as fatal, one SIGURG during its read would end the
// goroutine and every later probe would be a false loss — with no log
// line, so it looks as "all sensors dropped".
//
// We storm the process with self-SIGURG while pinging loopback; the reader
// must keep delivering. On the old hand-rolled code (unix.Poll + EINTR
// retry), the reader survived only because of the explicit EINTR retry.
// With the netpoller, EINTR is handled internally, so the reader survives
// without any application-level retry.
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
	if res := e.Ping(context.Background(), net.ParseIP("127.0.0.1"), 500*time.Millisecond); res.Lost {
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
		if res := e.Ping(context.Background(), net.ParseIP("127.0.0.1"), 100*time.Millisecond); res.Lost {
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
	if res := e.Ping(context.Background(), net.ParseIP("127.0.0.1"), 500*time.Millisecond); res.Lost {
		t.Fatal("reader not delivering after SIGURG storm — it exited on EINTR")
	}
}
