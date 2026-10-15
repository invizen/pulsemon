//go:build linux

package main

import (
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestFix_ICMPReaderRestartsAfterFatalError: a non-EINTR poll error used to end the reader goroutine permanently,
// turning every later ICMP probe into a silent false loss.
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
	e.dgram.(*dgramTransport).pollFn = func(fds []unix.PollFd, timeout int) (int, error) {
		n := atomic.AddInt32(&calls, 1)
		if n <= 2 {
			return 0, unix.EIO // fatal for the old reader
		}
		return unix.Poll(fds, timeout)
	}
	e.run()
	deadline := time.Now().Add(3 * time.Second)
	for atomic.LoadInt32(&calls) < 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt32(&calls) < 4 {
		t.Fatalf("reader did not come back after fatal errors (poll calls=%d)", atomic.LoadInt32(&calls))
	}
	if atomic.LoadInt32(&e.readerAlive) != 1 {
		t.Fatal("reader not alive after restart")
	}
}
