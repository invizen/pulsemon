package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// One shared ICMP socket for the whole process.
//
// TWO TRANSPORTS, same architecture (one socket, one reader goroutine,
// seq-dispatched replies, source-IP verification — the fix that stopped
// replies being attributed to the wrong sensor under load):
//
//  1. "unprivileged-datagram" (preferred): a SOCK_DGRAM / IPPROTO_ICMP
//     socket — the same kind the `ping` binary uses as a normal user.
//     Gated by the kernel's `ping_group_range` (readable as non-root),
//     NO CAP_NET_RAW, NO root. On Linux the kernel overwrites the ICMP
//     identifier with a per-socket value and only delivers replies for
//     OUR socket, so on this path we dispatch by sequence number +
//     source IP (no constant-ID filter).
//
//  2. "raw" (fallback): icmp.ListenPacket("ip4:icmp") — SOCK_RAW, needs
//     root or CAP_NET_RAW. Kept so the tool also works where the
//     datagram socket is unavailable (ping_group_range not configured).
//
// EngineMode() reports which transport is active (shown in /api/healthz).

const (
	probeID     = 0x5a11
	payloadSize = 32
)

var probePayload = []byte("ZENMON-PING-0123456789ABCDEF") // 24 bytes, fits payloadSize

type PingResult struct {
	RTT        time.Duration
	Lost       bool
	Error      error
	ResolvedIP string
}

// pendingPing is one in-flight probe; the reader delivers its RTT by key.
type pendingPing struct {
	dst   net.IP
	start time.Time
	ch    chan time.Duration
}

// pingKey uniquely identifies an in-flight probe. The sequence number alone
// is not enough: a 16-bit seq recycles every 65536 pings, and a stale reply
// (latency > timeout) arriving after the slot was handed to a NEW probe
// would, with a seq-only key, be looked up against the new probe and —
// because deliver() removed the entry before its source-IP check ran —
// prematurely evict the new probe's slot, dropping its genuine reply as a
// false loss. Keying by seq + destination makes a reply only ever match the
// probe that actually sent to that destination.
type pingKey struct {
	seq uint16
	dst string // normalized 4-byte IP string (see mkKey)
}

// mkKey builds the map key, normalizing the IP to its 4-byte form so a
// 16-byte IPv4-in-IPv6 source (possible from the raw transport) matches the
// 4-byte destination stored at send time. IPv6 (To4() nil) falls back to the
// full string, which never collides with a 4-byte key.
func mkKey(seq uint16, ip net.IP) pingKey {
	if v4 := ip.To4(); v4 != nil {
		return pingKey{seq: seq, dst: v4.String()}
	}
	return pingKey{seq: seq, dst: ip.String()}
}

var (
	pendingMu sync.Mutex
	pending   = map[pingKey]*pendingPing{}

	// Monotonic counter of send errors since start.
	probeErrCount atomic.Int64
)

// LastProbeError returns a human-readable description of the most recent
// shared-socket send error, or "" if none. A persistent non-empty value
// means ICMP is not working at all (e.g. no CAP_NET_RAW and no
// ping_group_range) rather than any sensor being down.
func LastProbeError() string {
	if probeErrCount.Load() == 0 {
		return ""
	}
	return fmt.Sprintf("%d probe send errors since start (ICMP socket unavailable? check CAP_NET_RAW / ping_group_range)",
		probeErrCount.Load())
}

// ---------------------------------------------------------------------------
// Transports
// ---------------------------------------------------------------------------

type sendFunc func(dst net.IP, seq uint16) error
type closeFunc func() error

// dgramTransport: unprivileged SOCK_DGRAM ICMP. The kernel fills in the
// ICMP identifier itself, so callers must not assume a constant ID in
// replies (dispatch is by seq).
type dgramTransport struct {
	fd int
}

func newDgramTransport() (*dgramTransport, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
	if err != nil {
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: 0}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return &dgramTransport{fd: fd}, nil
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

// rawTransport: SOCK_RAW via x/net/icmp (root / CAP_NET_RAW).
type rawTransport struct {
	conn *icmp.PacketConn
}

func newRawTransport() (*rawTransport, error) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	return &rawTransport{conn: c}, nil
}

func (t *rawTransport) send(dst net.IP, seq uint16) error {
	// x/net/icmp: marshal a full message (we control ID + seq), then write
	// to the destination.
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: probeID, Seq: int(seq), Data: probePayload},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	_, err = t.conn.WriteTo(wb, &net.IPAddr{IP: dst})
	return err
}

func (t *rawTransport) close() error { return t.conn.Close() }

// icmpChecksum computes the ICMP one's-complement checksum over a message.
func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

type Engine struct {
	send    sendFunc
	closeFn closeFunc
	isDgram bool
	mode    string

	// Concrete handles for the reader goroutine (exactly one is set).
	dgramFd  int
	rawConn  *icmp.PacketConn
}

// NewEngine opens the shared ICMP socket: datagram (unprivileged) first,
// raw (root/CAP_NET_RAW) as fallback. Failing both means ICMP cannot work
// on this host at all.
func NewEngine() (*Engine, error) {
	if t, err := newDgramTransport(); err == nil {
		return &Engine{send: t.send, closeFn: t.close, isDgram: true, mode: "unprivileged-datagram", dgramFd: t.fd}, nil
	} else {
		fmt.Fprintf(os.Stderr, "zenmon: datagram ICMP socket unavailable (%v); falling back to raw\n", err)
	}
	if t, err := newRawTransport(); err == nil {
		return &Engine{send: t.send, closeFn: t.close, isDgram: false, mode: "raw", rawConn: t.conn}, nil
	} else {
		return nil, fmt.Errorf("icmp: cannot open socket (need root/CAP_NET_RAW or ping_group_range): %w", err)
	}
}

// Mode reports the active transport: "unprivileged-datagram" or "raw".
func (e *Engine) Mode() string { return e.mode }

// Close releases the shared socket.
func (e *Engine) Close() {
	if e.closeFn != nil {
		e.closeFn()
	}
}

// deliver hands a reply's RTT to its waiting probe (keyed by seq +
// destination, source-IP verified). Called by the reader goroutine.
//
// The destination check runs BEFORE the map delete: a stale reply from a
// previous probe that reused this seq must be dropped WITHOUT removing the
// new probe's entry, or the new probe's genuine reply would later be
// discarded as untracked (false loss).
func (e *Engine) deliver(seq uint16, src net.IP) {
	key := mkKey(seq, src)
	pendingMu.Lock()
	p, ok := pending[key]
	if ok && !p.dst.Equal(src) {
		// Entry exists but is for a different destination: this reply is
		// stale (belongs to a prior probe that recycled the seq). Drop it
		// and keep the new probe's entry intact.
		pendingMu.Unlock()
		return
	}
	if ok {
		delete(pending, key)
	}
	pendingMu.Unlock()
	if !ok {
		return
	}
	select {
	case p.ch <- time.Since(p.start):
	default:
	}
}

// run starts the single reply-reader goroutine for the active transport.
func (e *Engine) run() {
	if e.isDgram {
		go e.readDgram()
	} else {
		go e.readRaw()
	}
}

// readDgram is the reader for the datagram socket. The kernel strips the
// IP header and delivers the ICMP message directly, and has already
// demuxed by its per-socket identifier — we dispatch by seq only.
func (e *Engine) readDgram() {
	buf := make([]byte, 1500)
	for {
		n, from, err := syscall.Recvfrom(e.dgramFd, buf, 0)
		if err != nil {
			return
		}
		if n < 8 {
			continue
		}
		if buf[0] != 0 { // ICMPTypeEchoReply
			continue
		}
		seq := binary.BigEndian.Uint16(buf[6:])
		sa, isSA := from.(*syscall.SockaddrInet4)
		if !isSA {
			continue
		}
		src := make(net.IP, 4)
		copy(src, sa.Addr[:])
		e.deliver(seq, src)
	}
}

// readRaw is the reader for the raw socket: parse IP/ICMP, filter by our
// constant ID, dispatch by seq (source-IP verified in deliver).
func (e *Engine) readRaw() {
	buf := make([]byte, 1500)
	for {
		n, src, err := e.rawConn.ReadFrom(buf)
		if err != nil {
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
		ipAddr, ok := src.(*net.IPAddr)
		if !ok {
			continue
		}
		e.deliver(uint16(em.Seq), ipAddr.IP)
	}
}

// Ping sends one ICMP echo to dst and waits for the reply.
func (e *Engine) Ping(dst net.IP, timeout time.Duration) PingResult {
	// Sequence is 16-bit (the ICMP field width, RFC 792). The pending map is
	// keyed by (seq, destination), so a reply only ever matches the probe
	// that sent to that destination. Normally the counter's next value is
	// free for this destination, but if a stale probe to the SAME destination
	// (latency > timeout) still occupies that (seq, dst) slot, skip to the
	// next free value — up to 16 tries. Overwriting it would let the stale
	// reply deliver its RTT into the NEW probe's channel (a false success);
	// the destination in the key stops the cross-destination variant. The
	// loop is bounded so a full table can never deadlock on the lock — after
	// 16 misses we fall through and take the next counter value unconditionally.
	seq := uint16(atomic.AddUint32(&seqCounter, 1) & 0xffff)
	key := mkKey(seq, dst)
	p := &pendingPing{dst: dst, start: time.Now(), ch: make(chan time.Duration, 1)}
	tries := 0
	for ; tries < 16; tries++ {
		pendingMu.Lock()
		if _, busy := pending[key]; !busy {
			pending[key] = p
			pendingMu.Unlock()
			break
		}
		pendingMu.Unlock()
		seq = uint16(atomic.AddUint32(&seqCounter, 1) & 0xffff)
		key = mkKey(seq, dst)
	}
	if tries == 16 {
		// Table full: no free (seq, dst) slot in 16 tries. Take the next
		// counter value anyway (least-bad option here).
		pendingMu.Lock()
		pending[key] = p
		pendingMu.Unlock()
	}
	defer func() {
		pendingMu.Lock()
		if cur, ok := pending[key]; ok && cur == p {
			delete(pending, key)
		}
		pendingMu.Unlock()
	}()

	if err := e.send(dst, seq); err != nil {
		probeErrCount.Add(1)
		return PingResult{Lost: true, Error: err}
	}
	select {
	case d := <-p.ch:
		return PingResult{RTT: d, Lost: false}
	case <-time.After(timeout):
		return PingResult{Lost: true}
	}
}

var seqCounter uint32

var (
	sharedEngineInst *Engine
	sharedEngineErr  error
	sharedEngineOnce sync.Once
)

// SharedEngine returns the process-wide ICMP engine, opening it on first use.
func SharedEngine() (*Engine, error) {
	sharedEngineOnce.Do(func() {
		e, err := NewEngine()
		if err != nil {
			sharedEngineErr = err
			return
		}
		sharedEngineInst = e
		e.run()
	})
	return sharedEngineInst, sharedEngineErr
}

// getSharedConn is kept for the probe worker's startup warm-up. It ensures
// the shared engine (and its reader) is open; in raw mode it returns the
// underlying *icmp.PacketConn, in unprivileged-datagram mode nil with a nil
// error. Callers should only inspect the error.
func getSharedConn() (*icmp.PacketConn, error) {
	e, err := SharedEngine()
	if err != nil {
		return nil, err
	}
	return e.rawConn, nil
}

// EngineMode reports which ICMP transport the shared engine is using
// ("unprivileged-datagram", "raw", or "" if the engine has not started).
// Shown in /api/healthz.
func EngineMode() string {
	if sharedEngineInst != nil {
		return sharedEngineInst.mode
	}
	return ""
}

// pingHost is the probe worker's entry point: resolve the target, then
// ping the resolved IP through the shared engine.
func pingHost(target string, timeout time.Duration) PingResult {
	ip, err := resolveIPAddrWithTimeout("ip4", target, 5*time.Second)
	if err != nil {
		return PingResult{Lost: true, Error: err}
	}
	dst := ip.IP.To4()
	if dst == nil {
		// IPv6-only result — ICMP is IPv4-only by design; count as loss.
		return PingResult{Lost: true, ResolvedIP: ip.IP.String()}
	}
	e, err := SharedEngine()
	if err != nil {
		probeErrCount.Add(1)
		return PingResult{Lost: true, Error: err, ResolvedIP: dst.String()}
	}
	res := e.Ping(dst, timeout)
	res.ResolvedIP = dst.String()
	return res
}

// resolveIPAddrWithTimeout resolves an IP with a hard deadline so a hung
// DNS lookup can't wedge a sensor's goroutine forever (it becomes a loss
// row instead of a permanent block).
func resolveIPAddrWithTimeout(network, host string, timeout time.Duration) (*net.IPAddr, error) {
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
	case <-time.After(timeout):
		return nil, fmt.Errorf("DNS resolution of %q timed out after %s", host, timeout)
	}
}
