//go:build windows

package main

import (
	"encoding/binary"
	"log"
	"net"
	"sync/atomic"

	"golang.org/x/sys/windows"
)

// winDgram: unprivileged SOCK_DGRAM ICMP on Windows — the same socket kind
// ping.exe uses as a normal user (no admin, no CAP_NET_RAW). The Windows IP
// driver demuxes echo replies to the socket by the ICMP identifier, so we set
// a constant ID (probeID) in every request; replies are then dispatched by
// seq + source IP (the source-IP check in Engine.deliver stops cross-sensor
// misattribution — the same invariant as the Linux datagram path).
//
// Unlike Linux, the reader uses a BLOCKING Recvfrom: closing the handle from
// Close() (via stop) is what unblocks a pending receive (Winsock returns
// WSAENOTSOCK), so no Poll loop is needed here. This is simpler than the Linux
// path and sidesteps the SIGURG/EINTR trap entirely.
type winDgram struct {
	fd windows.Handle
}

func newWinDgram() (*winDgram, error) {
	fd, err := windows.Socket(windows.AF_INET, windows.SOCK_DGRAM, windows.IPPROTO_ICMP)
	if err != nil {
		return nil, err
	}
	if err := windows.Bind(fd, &windows.SockaddrInet4{}); err != nil {
		_ = windows.Close(fd)
		return nil, err
	}
	return &winDgram{fd: fd}, nil
}

func (t *winDgram) send(dst net.IP, seq uint16) error {
	// Full ICMP echo request: 8-byte header + payload, incl. checksum. The ID
	// is set to probeID — the Windows driver uses it to demux replies to our
	// socket (unlike Linux, the kernel does NOT overwrite the ID).
	msg := make([]byte, 8+len(probePayload))
	msg[0] = 8 // ICMPTypeEcho
	binary.BigEndian.PutUint16(msg[4:], probeID) // ID (driver demux key)
	binary.BigEndian.PutUint16(msg[6:], seq)     // seq
	copy(msg[8:], probePayload)
	binary.BigEndian.PutUint16(msg[2:], icmpChecksum(msg))

	addr := &windows.SockaddrInet4{}
	copy(addr.Addr[:], dst.To4())
	return windows.Sendto(t.fd, msg, 0, addr)
}

func (t *winDgram) close() error { return windows.Close(t.fd) }

// run starts the reader goroutine, tracked by the Engine's wg so Close() can
// block until it has stopped.
func (t *winDgram) run(e *Engine) {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		t.readDgram(e)
	}()
}

// stop closes the socket, which unblocks the reader's pending Recvfrom
// (Winsock returns WSAENOTSOCK). Engine.Close calls this BEFORE wg.Wait() — a
// blocking receive is not woken by the done channel alone, so the handle must
// go first.
func (t *winDgram) stop() { _ = t.close() }

// readDgram is the reader for the Windows datagram socket: a blocking
// Recvfrom loop. A ready reply returns immediately (no RTT impact); the done
// channel gives a fast exit between reads; and Close() (via stop) closes the
// handle to unblock a pending receive, so the reader always terminates.
func (t *winDgram) readDgram(e *Engine) {
	atomic.StoreInt32(&e.readerAlive, 1)
	defer atomic.StoreInt32(&e.readerAlive, 0)
	buf := make([]byte, 1500)
	for {
		select {
		case <-e.done:
			return
		default:
		}
		n, from, err := windows.Recvfrom(t.fd, buf, 0)
		if err != nil {
			// WSAENOTSOCK (the handle was closed by stop) is the normal
			// shutdown path — exit quietly. Any other error stops the reader
			// (logged, never silent: a dead probe path must leave a trace).
			select {
			case <-e.done:
				return
			default:
			}
			log.Printf("pulsemon: icmp reader (win dgram): recvfrom: %v (reader stopping)", err)
			return
		}
		if n >= 8 && buf[0] == 0 { // ICMPTypeEchoReply
			seq := binary.BigEndian.Uint16(buf[6:])
			if sa, ok := from.(*windows.SockaddrInet4); ok {
				src := make(net.IP, 4)
				copy(src, sa.Addr[:])
				e.deliver(seq, src)
			}
		}
	}
}

// openDgram is the Windows implementation of the shared datagram opener (see
// ping.go). closeFn is a no-op: the handle is closed by stop() (before the
// reader wait), so the post-wait close in Engine.Close must not run again.
func openDgram() (dgramState, sendFunc, closeFunc, error) {
	t, err := newWinDgram()
	if err != nil {
		return nil, nil, nil, err
	}
	return t, t.send, func() error { return nil }, nil
}
