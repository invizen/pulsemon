//go:build linux

package main

import (
	"encoding/binary"
	"log"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// dgramTransport: unprivileged SOCK_DGRAM ICMP (the Linux datagram path).
// The kernel fills in the ICMP identifier itself, so replies are dispatched
// by seq + source IP (no constant-ID filter). The fd is non-blocking and
// driven by a bounded Poll loop so Close() can stop the reader: a blocking
// Recvfrom is NOT woken by close(fd) on Linux (verified), which is exactly
// why the socket is non-blocking and the loop is Poll-based.
//
// This type implements the shared dgramState interface (run + stop), so the
// portable Engine in ping.go drives it without knowing about fds or Poll.
type dgramTransport struct {
	fd int

	// pollFn is the poll implementation readDgram drives. It is a field (not
	// a direct unix.Poll call) so a test can inject EINTR and deterministically
	// verify the retry path — see TestEngineReaderRetriesEINTR. Set in
	// openDgram; Engine literals in unit tests that only exercise deliver()
	// never touch it.
	pollFn func(fds []unix.PollFd, timeout int) (int, error)
}

func newDgramTransport() (*dgramTransport, error) {
	// SOCK_CLOEXEC: the fd is auto-closed if this process ever execs a child,
	// so the raw ICMP descriptor can never leak into a subprocess's fd table.
	// The stdlib net package sets CLOEXEC on every socket it creates; this
	// hand-rolled syscall should match.
	//
	// SOCK_NONBLOCK: the reader (readDgram) drives the socket with a bounded
	// Poll loop that must be stoppable by Close(). A blocking fd is NOT
	// interruptible by close() (a goroutine blocked in Recvfrom stays stuck —
	// verified empirically), so the socket is non-blocking and the reader only
	// Recvfrom's after Poll reports readability. Sendto is unaffected: a small
	// ICMP datagram that fits the send buffer is written immediately.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, syscall.IPPROTO_ICMP)
	if err != nil {
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: 0}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return &dgramTransport{fd: fd, pollFn: unix.Poll}, nil
}

func (t *dgramTransport) send(dst net.IP, seq uint16) error {
	// Full ICMP echo request: 8-byte header + payload, incl. checksum.
	msg := make([]byte, 8+len(probePayload))
	msg[0] = 8 // ICMPTypeEcho
	// msg[2:4] checksum, msg[4:6] ID (kernel overwrites), msg[6:8] seq
	binary.BigEndian.PutUint16(msg[6:], seq)
	copy(msg[8:], probePayload)
	binary.BigEndian.PutUint16(msg[2:], icmpChecksum(msg))

	addr := &syscall.SockaddrInet4{Port: 0}
	copy(addr.Addr[:], dst.To4())
	return syscall.Sendto(t.fd, msg, 0, addr)
}

func (t *dgramTransport) close() error { return syscall.Close(t.fd) }

// run starts the reader goroutine, tracked by the Engine's wg so Close() can
// block until it has stopped.
func (t *dgramTransport) run(e *Engine) {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			t.readDgram(e)
			// readDgram only returns on done (clean) or an unexpected error.
			// An unsupervised exit would turn every later probe into a silent
			// false loss, so come back after a short pause unless we are closing.
			select {
			case <-e.done:
				return
			case <-time.After(readerRestartDelay):
				log.Printf("pulsemon: icmp reader restarted after an unexpected stop")
			}
		}
	}()
}

// stop is a no-op on Linux: the reader is a Poll loop with a 100ms slice and a
// done select, so the done signal alone stops it within one slice. The fd is
// closed AFTER wg.Wait() (in Engine.Close) to keep the socket alive for any
// in-flight Sendto until the reader is confirmed stopped.
func (t *dgramTransport) stop() {}

// readDgram is the reader for the datagram socket. The kernel strips the IP
// header and demuxes by the per-socket identifier, so replies are dispatched
// by seq only. The socket is non-blocking (SOCK_NONBLOCK, see
// newDgramTransport) and driven with a bounded Poll loop: a ready reply wakes
// Poll immediately (no RTT impact), and a closed done channel exits the loop
// at the next iteration. A blocking Recvfrom here would be un-interruptible —
// close(fd) does not wake it (verified) — which is exactly why the socket is
// non-blocking and the loop is Poll-based.
func (t *dgramTransport) readDgram(e *Engine) {
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
		fds := []unix.PollFd{{Fd: int32(t.fd), Events: unix.POLLIN}}
		poll := t.pollFn
		if poll == nil {
			poll = unix.Poll
		}
		if _, err := poll(fds, 100); err == unix.EINTR {
			continue // signal (the runtime fires SIGURG to wake parked threads);
			// x/sys's Poll returns EINTR to us — unlike syscall.Recvfrom,
			// which retries internally — so it must NOT be fatal or the
			// reader dies on the first interrupt and every later probe is a
			// false loss.
		} else if err != nil {
			log.Printf("pulsemon: icmp reader: poll: %v (reader stopping)", err)
			return
		}
		if fds[0].Revents&unix.POLLIN != 0 {
			if rn, from, rerr := syscall.Recvfrom(t.fd, buf, 0); rerr == nil {
				if rn >= 8 && buf[0] == 0 { // ICMPTypeEchoReply
					seq := binary.BigEndian.Uint16(buf[6:])
					if sa, ok := from.(*syscall.SockaddrInet4); ok {
						src := make(net.IP, 4)
						copy(src, sa.Addr[:])
						e.deliver(seq, src)
					}
				}
			} else if rerr == syscall.EINTR {
				continue // defensive: the syscall layer retries EINTR, but if
				// it ever surfaces, retry rather than kill the reader
			} else if rerr != syscall.EAGAIN && rerr != syscall.EWOULDBLOCK {
				log.Printf("pulsemon: icmp reader: recvfrom: %v (reader stopping)", rerr)
				return // real error (e.g. socket closed)
			}
		}
	}
}

// openDgram is the Linux implementation of the shared datagram opener (see
// ping.go). It returns the dgramState driver plus the send/close funcs the
// Engine uses for the datagram path.
func openDgram() (dgramState, sendFunc, closeFunc, error) {
	t, err := newDgramTransport()
	if err != nil {
		return nil, nil, nil, err
	}
	return t, t.send, t.close, nil
}
