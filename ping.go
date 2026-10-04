package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type PingResult struct {
	RTT        time.Duration
	Lost       bool
	Error      error
	ResolvedIP string // "" when the lookup failed/timed out
}

// All probes share ONE ICMP socket. With many sensors probing concurrently,
// per-probe sockets bound to 0.0.0.0 let the kernel deliver a reply to the
// wrong socket, so a probe timed another sensor's reply — producing
// sub-millisecond "RTTs" to hosts that are 18ms away. A single socket plus
// per-probe sequence numbers makes every reply unambiguous.
var (
	probeID = os.Getpid() & 0xffff

	connOnce     sync.Once
	sharedConn   *icmp.PacketConn
	sharedConnErr error

	// probeErrCount grows on every probe attempt that hit a socket-level
	// error (e.g. the ICMP socket cannot be created). deriveStatus uses
	// the delta to flag "degraded" instead of silently defaulting to up.
	probeErrCount atomic.Int64

	pendingMu sync.Mutex
	pending   = map[int]*pendingProbe{}
	seqCtr    atomic.Int32
)

// LastProbeError returns the shared-socket error if one exists ("" when
// healthy) — surfaced in /api/healthz so the dashboard can show a banner.
func LastProbeError() string {
	if sharedConnErr != nil {
		return sharedConnErr.Error()
	}
	return ""
}

// resolveIPAddrWithTimeout runs net.ResolveIPAddr in a goroutine and returns
// if it finishes or the deadline passes — whichever comes first. DNS lookups
// via the container's 127.0.0.11 resolver can hang indefinitely when the
// upstream (host systemd-resolved) is slow or a zone has no answer; an
// unbounded call would stall the sensor's probe goroutine forever.
func resolveIPAddrWithTimeout(network, host string, d time.Duration) (*net.IPAddr, error) {
	type result struct {
		ip  *net.IPAddr
		err error
	}
	ch := make(chan result, 1)
	go func() {
		ip, err := net.ResolveIPAddr(network, host)
		ch <- result{ip, err}
	}()
	select {
	case r := <-ch:
		return r.ip, r.err
	case <-time.After(d):
		return nil, fmt.Errorf("dns: %s timed out after %s", host, d)
	}
}

type pendingProbe struct {
	dst   net.IP
	start time.Time
	ch    chan PingResult
}

func getSharedConn() (*icmp.PacketConn, error) {
	connOnce.Do(func() {
		sharedConn, sharedConnErr = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if sharedConnErr == nil {
			go replyReader(sharedConn)
		}
	})
	return sharedConn, sharedConnErr
}

// replyReader dispatches every echo reply to the probe that owns its seq.
// Replies from other hosts, other tools (wrong ID), or already-timed-out
// probes are dropped.
func replyReader(conn *icmp.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("ping: reader closed: %v", err)
			return
		}
		rm, err := icmp.ParseMessage(1, buf[:n])
		if err != nil || rm.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		em, isEcho := rm.Body.(*icmp.Echo)
		if !isEcho || em.ID != probeID {
			continue // not ours
		}
		if src == nil {
			continue
		}
		pendingMu.Lock()
		p, found := pending[em.Seq]
		if found {
			delete(pending, em.Seq)
		}
		pendingMu.Unlock()
		if !found {
			continue // timed out or duplicate
		}
		if !src.(*net.IPAddr).IP.Equal(p.dst) {
			continue // reply from somewhere other than the target
		}
		select {
		case p.ch <- PingResult{RTT: time.Since(p.start), Lost: false}:
		default:
		}
	}
}

// pingHost sends one echo to target and waits up to timeout for its reply.
func pingHost(target string, timeout time.Duration) PingResult {
	conn, err := getSharedConn()
	if err != nil {
		probeErrCount.Add(1)
		return PingResult{Lost: true, Error: err}
	}
	// Resolve with a timeout: an unbounded net.ResolveIPAddr would wedge the
	// sensor's probe goroutine forever if a DNS lookup hangs (the reply-wait
	// below is capped at `timeout`, but resolution is not). A hung lookup must
	// become a loss row, not a permanent stall.
	dst, err := resolveIPAddrWithTimeout("ip4", target, 5*time.Second)
	if err != nil {
		probeErrCount.Add(1)
		return PingResult{Lost: true, Error: err}
	}

	seq := int(seqCtr.Add(1) & 0xffffff)
	p := &pendingProbe{dst: dst.IP, start: time.Now(), ch: make(chan PingResult, 1)}

	pendingMu.Lock()
	pending[seq] = p
	pendingMu.Unlock()
	defer func() {
		pendingMu.Lock()
		if cur, ok := pending[seq]; ok && cur == p {
			delete(pending, seq)
		}
		pendingMu.Unlock()
	}()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   probeID,
			Seq:  seq,
			Data: []byte("ZENMON-PROBE"),
		},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return PingResult{Lost: true, Error: err}
	}
	if _, err := conn.WriteTo(wb, dst); err != nil {
		return PingResult{Lost: true, Error: err}
	}

	select {
	case res := <-p.ch:
		res.ResolvedIP = dst.String()
		return res
	case <-time.After(timeout):
		// Resolved fine but no echo reply within the timeout.
		return PingResult{Lost: true, ResolvedIP: dst.String()}
	}
}
