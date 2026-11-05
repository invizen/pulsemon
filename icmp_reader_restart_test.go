//go:build linux

package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestFix_ICMPReaderRestartsAfterFatalError: a non-EINTR read error used to
// end the reader goroutine permanently, turning every later ICMP probe into
// a silent false loss. With the x/net/icmp netpoller-driven reader, a fatal
// ReadFrom error (not net.ErrClosed) causes the reader to return, and the
// supervisor loop in run() restarts it after readerRestartDelay.
func TestFix_ICMPReaderRestartsAfterFatalError(t *testing.T) {
	e, err := NewEngine()
	if err != nil {
		t.Skipf("ICMP engine unavailable: %v", err)
	}
	defer e.Close()
	if !e.isDgram {
		t.Skip("datagram transport only")
	}
	old := readerRestartDelay
	readerRestartDelay = 20 * time.Millisecond
	defer func() { readerRestartDelay = old }()

	var calls int32
	d := e.dgram.(*linuxDgram)
	realRead := d.readFn
	d.readFn = func(buf []byte) (int, net.Addr, error) {
		n := atomic.AddInt32(&calls, 1)
		if n <= 2 {
			return 0, nil, unix.EIO // fatal for the reader
		}
		return realRead(buf)
	}
	e.run()
	deadline := time.Now().Add(3 * time.Second)
	// After 2 fatal errors, the supervisor restarts the reader, which makes
	// a 3rd read call (the real ReadFrom, which blocks waiting for data).
	// We only need to confirm the reader came back (3 calls) and is alive.
	for atomic.LoadInt32(&calls) < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt32(&calls) < 3 {
		t.Fatalf("reader did not come back after fatal errors (read calls=%d)", atomic.LoadInt32(&calls))
	}
	if atomic.LoadInt32(&e.readerAlive) != 1 {
		t.Fatal("reader not alive after restart")
	}
}
