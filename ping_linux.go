//go:build linux

package main

import (
	"errors"
	"log"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// linuxDgram: unprivileged SOCK_DGRAM ICMP via x/net/icmp (the Linux
// datagram path). The kernel fills in the ICMP identifier itself, so
// replies are dispatched by seq + source IP (no constant-ID filter).
//
// x/net/icmp.ListenPacket("udp4", "0.0.0.0") opens the same
// SOCK_DGRAM/IPPROTO_ICMP socket the `ping` binary uses as a normal user
// (gated by the kernel's ping_group_range, NO CAP_NET_RAW, NO root). The
// socket integrates with the netpoller: Close() wakes a blocked ReadFrom,
// so no Poll loop is needed. This replaces the old hand-rolled
// dgramTransport (raw syscall + SOCK_NONBLOCK + unix.Poll loop), which
// existed because the comment in ping.go claimed Message.Marshal() cannot
// write to the datagram socket — that claim was inaccurate (verified
// empirically: the round-trip works, and the kernel overwrites the ID
// exactly as the old code expected).
//
// This type implements the shared dgramState interface (run + stop), so
// the portable Engine in ping.go drives it without knowing about sockets.
type linuxDgram struct {
	conn *icmp.PacketConn

	// readFn is the read implementation readDgram drives. It is a field
	// (not a direct conn.ReadFrom call) so a test can inject a fatal
	// error and deterministically verify the restart path — see
	// TestFix_ICMPReaderRestartsAfterFatalError. Set in newLinuxDgram;
	// Engine literals in unit tests that only exercise deliver() never
	// touch it.
	readFn func(buf []byte) (int, net.Addr, error)
}

func newLinuxDgram() (*linuxDgram, error) {
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	return &linuxDgram{conn: c, readFn: c.ReadFrom}, nil
}

func (t *linuxDgram) send(dst net.IP, seq uint16) error {
	// x/net/icmp: marshal a full message (we control seq + payload), then
	// write to the destination. The kernel overwrites the ID on Linux
	// datagram ICMP, so the ID here is a socket-binding key the kernel
	// manages, not an application-level filter.
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: int(probeID), Seq: int(seq), Data: probePayload},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	_, err = t.conn.WriteTo(wb, &net.UDPAddr{IP: dst})
	return err
}

func (t *linuxDgram) close() error { return t.conn.Close() }

// run starts the reader goroutine, tracked by the Engine's wg so Close()
// can block until it has stopped.
func (t *linuxDgram) run(e *Engine) {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			t.readDgram(e)
			// readDgram only returns on done (clean) or an unexpected
			// error. An unsupervised exit would turn every later probe
			// into a silent false loss, so come back after a short pause
			// unless we are closing.
			select {
			case <-e.done:
				return
			case <-time.After(readerRestartDelay):
				log.Printf("pulsemon: icmp reader (linux dgram) restarted after an unexpected stop")
			}
		}
	}()
}

// stop closes the socket, which unblocks the reader's pending ReadFrom
// (the netpoller delivers net.ErrClosed). Engine.Close calls this BEFORE
// wg.Wait() — a blocking receive is not woken by the done channel alone,
// so the conn must go first. This is the same pattern as the Windows
// datagram path (stop closes the handle) and the raw transport (stop
// closes the conn).
func (t *linuxDgram) stop() { _ = t.conn.Close() }

// readDgram is the reader for the datagram socket. The kernel strips the
// IP header and demuxes by the per-socket identifier, so replies are
// dispatched by seq + source IP. The socket is managed by the netpoller:
// a ready reply wakes ReadFrom immediately (no RTT impact), EINTR is
// retried internally (the v0.1.21 SIGURG bug is gone — the netpoller
// handles it), and Close() (called by stop) returns net.ErrClosed, so the
// reader always terminates.
func (t *linuxDgram) readDgram(e *Engine) {
	atomic.StoreInt32(&e.readerAlive, 1)
	defer atomic.StoreInt32(&e.readerAlive, 0)
	buf := make([]byte, 1500)
	for {
		// Stop signal first, every iteration — so a busy socket still exits.
		select {
		case <-e.done:
			return
		default:
		}
		read := t.readFn
		if read == nil {
			read = t.conn.ReadFrom
		}
		n, addr, err := read(buf)
		if err != nil {
			// errors.Is, not ==: ReadFrom wraps it in a *net.OpError.
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("pulsemon: icmp reader (linux dgram): read: %v (reader stopping)", err)
			}
			return
		}
		rm, err := icmp.ParseMessage(1, buf[:n])
		if err != nil || rm.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		em, isEcho := rm.Body.(*icmp.Echo)
		if !isEcho {
			continue
		}
		// The kernel overwrites the ID, so we can't filter by ID.
		// Dispatch by seq + source IP (the same invariant as the old
		// hand-rolled code). The source IP comes from the ReadFrom
		// address.
		if ua, ok := addr.(*net.UDPAddr); ok && ua.IP != nil {
			e.deliver(uint16(em.Seq), ua.IP)
		}
	}
}

// openDgram is the Linux implementation of the shared datagram opener (see
// ping.go). It returns the dgramState driver plus the send/close funcs the
// Engine uses for the datagram path. closeFn is a no-op: the conn is closed
// by stop() (before the reader wait), so the post-wait close in
// Engine.Close must not run again (same pattern as the Windows datagram
// path).
func openDgram() (dgramState, sendFunc, closeFunc, error) {
	t, err := newLinuxDgram()
	if err != nil {
		return nil, nil, nil, err
	}
	return t, t.send, func() error { return nil }, nil
}
