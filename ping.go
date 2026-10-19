package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
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
//     socket — the same kind the `ping` binary uses as a normal user. On
//     Linux it is gated by the kernel's `ping_group_range` (NO CAP_NET_RAW,
//     NO root); on Windows the IP driver allows it for any user. The
//     datagram driver is platform-specific (ping_linux.go / ping_windows.go)
//     and implements the dgramState interface below.
//
//  2. "raw" (fallback): icmp.ListenPacket("ip4:icmp") — SOCK_RAW, needs
//     root / CAP_NET_RAW (Linux) or an elevated process (Windows). Kept so
//     the tool also works where the datagram socket is unavailable.
//
// EngineMode() reports which transport is active (shown in /api/healthz).

const (
	probeID     = 0x5a11
	payloadSize = 32 // max probe payload in bytes (probePayload must fit within this)
)

// probePayload is the ICMP echo payload: a fixed human-readable identifier.
// Its size is bounded by payloadSize (enforced in init) so the on-wire
// echo request stays well under any MTU concern.
var probePayload = []byte("PULSEMON-PING-0123456789ABCDEF") // 28 bytes, <= payloadSize

func init() {
	// Enforce the payload cap at startup: a future edit that lengthens the
	// identifier past payloadSize would otherwise silently send an oversized
	// ICMP echo payload, so fail loudly instead.
	if len(probePayload) > payloadSize {
		panic(fmt.Sprintf("ping: probePayload is %d bytes, exceeds max payloadSize %d", len(probePayload), payloadSize))
	}
}

type PingResult struct {
	RTT        time.Duration
	Lost       bool
	Error      error
	ResolvedIP string
	// Broken is true when the probe could not even be ATTEMPTED because the
	// ICMP engine itself is unusable (socket closed/invalid, no transport).
	// A per-target send failure (ENETUNREACH, EHOSTUNREACH, a netfilter EPERM)
	// is NOT broken: it is simply a lost probe for that one sensor.
	Broken bool
}

// isBrokenSendErr reports whether a send error means the shared ICMP socket
// itself is unusable (as opposed to a problem reaching one particular target).
// Only engine-level failures may degrade OTHER sensors' status; treating a
// per-target error (a withdrawn VPN route, say) as engine-wide used to flag
// every concurrently-probed sensor as "warning".
func isBrokenSendErr(err error) bool {
	return errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.ENOTSOCK) ||
		errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed)
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

// LastProbeError returns a human-readable description of the current
// shared-socket send-error state, or "" if none. probeErrCount tracks
// ENGINE-LEVEL send failures (see isBrokenSendErr) SINCE the last successful
// send (reset on success, see Ping); per-target failures are not counted. A
// non-empty value means ICMP sends are CURRENTLY failing (e.g. no
// CAP_NET_RAW and no ping_group_range, or the socket is unavailable) rather
// than any sensor being down. A single transient failure (e.g. the first
// probe at boot, before the network is up) no longer pins this forever.
func LastProbeError() string {
	if probeErrCount.Load() == 0 {
		return ""
	}
	return fmt.Sprintf("%d pulse send failures since the last success (ICMP socket unavailable?)",
		probeErrCount.Load())
}

// ---------------------------------------------------------------------------
// Transports
// ---------------------------------------------------------------------------

type sendFunc func(dst net.IP, seq uint16) error
type closeFunc func() error

// dgramState is the platform-specific unprivileged-datagram transport driver:
// the socket handle plus the reply-reader it runs. Implemented in
// ping_linux.go (non-blocking fd + Poll loop) and ping_windows.go (blocking
// Recvfrom). The portable Engine drives it through this interface so the
// platform socket details never leak into the shared code.
type dgramState interface {
	// run starts the reader goroutine (the Engine tracks it via its wg).
	run(e *Engine)
	// stop interrupts the reader's blocking read so it can exit. Engine.Close
	// calls this BEFORE wg.Wait(). Linux: no-op (the Poll loop exits on the
	// done channel). Windows: closes the handle, which unblocks Recvfrom.
	stop()
}

// rawTransport: SOCK_RAW via x/net/icmp (root / CAP_NET_RAW / elevated).
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

// icmpChecksum computes the ICMP one's-complement checksum (RFC 1071 / RFC
// 792) over a message. Each 16-bit half-word is read big-endian (byte order
// independent); a trailing odd byte is placed in the HIGH-order position
// (<< 8), which is the canonical network-order padding. The final fold is the
// standard two-step end-around carry: the first fold brings a 32-bit sum under
// 2^17, the second clears the remaining carry, and the uint16() on return
// drops any residual carry bit.
//
// Why hand-rolled instead of x/net/icmp: x/net/icmp's checksum is UNEXPORTED
// (message.go `func checksum`, no public Checksum symbol), and its only
// public entry point is Message.Marshal(), which cannot write to the
// SOCK_DGRAM/IPPROTO_ICMP socket the unprivileged-datagram transport uses
// (that path hand-builds the raw packet at the byte level). The raw
// transport (rawTransport.send) DOES use msg.Marshal(nil) and inherits
// x/net/icmp's checksum — this function exists only for the datagram path.
//
// NOTE: the previous odd-length handling was already correct — this is the
// canonical form, not a bug fix. TestIcmpChecksumMatchesReference locks it
// against an independent reference across every length (odd and even).
func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
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

	// Concrete handles for the reader goroutine (exactly one is set): dgram
	// (the platform datagram driver, nil in raw mode) or rawConn.
	dgram   dgramState
	rawConn *icmp.PacketConn

	// wg tracks the reply-reader goroutine so Close() can block until it has
	// actually stopped. Without it, Close() returns the instant the socket
	// closes while the reader is still unwinding — and deliver() targets the
	// package-global pending map, so a not-fully-stopped reader is a hazard
	// for anyone who creates/destroys engines (tests, future code). The reader
	// exits when the socket closes (Recvfrom/ReadFrom return an error), so the
	// wait is bounded. closeOnce guards against a double close.
	wg        sync.WaitGroup
	closeOnce sync.Once

	// done is closed by Close() to signal the reader to exit. The Linux
	// Poll-based reader needs this (a non-blocking socket alone is not enough
	// to stop it); the Windows blocking reader is unblocked by the handle close
	// in stop(). (Closing the fd alone does NOT wake a goroutine blocked in a
	// blocking Recvfrom on Linux — verified — which is why the Linux reader is
	// Poll-based and selects on done.)
	done chan struct{}

	// readerAlive tracks whether the reader goroutine is currently running
	// (set in the platform readDgram, cleared on return). Used by tests to
	// detect the silent-exit regression.
	readerAlive int32 // atomic
}

// NewEngine opens the shared ICMP socket: datagram (unprivileged) first,
// raw (root/CAP_NET_RAW) as fallback. Failing both means ICMP cannot work
// on this host at all.
func NewEngine() (*Engine, error) {
	if d, send, closeFn, err := openDgram(); err == nil {
		return &Engine{send: send, closeFn: closeFn, isDgram: true, mode: "unprivileged-datagram", dgram: d, done: make(chan struct{})}, nil
	} else {
		fmt.Fprintf(os.Stderr, "pulsemon: datagram ICMP socket unavailable (%v); falling back to raw\n", err)
	}
	if t, err := newRawTransport(); err == nil {
		return &Engine{send: t.send, closeFn: t.close, isDgram: false, mode: "raw", rawConn: t.conn, done: make(chan struct{})}, nil
	} else {
		return nil, fmt.Errorf("%w (need root/CAP_NET_RAW or ping_group_range): %w", errNoIcmpTransport, err)
	}
}

// Mode reports the active transport: "unprivileged-datagram" or "raw".
func (e *Engine) Mode() string { return e.mode }

// Close stops the engine: it signals the reader to exit (done), then
// interrupts the reader's blocking read, then blocks until the reader
// goroutine has actually stopped. The interruption is transport-specific:
//
//   - datagram: stop() — a no-op on Linux (the Poll loop exits on done), but
//     a handle-close on Windows (which unblocks the blocking Recvfrom). Both
//     happen before wg.Wait(). The socket is then released after the wait
//     (Linux dgram: closeFn closes the fd, keeping it alive for any in-flight
//     Sendto until the reader is confirmed stopped; Windows dgram: no-op, the
//     handle is already closed by stop()).
//   - raw: ReadFrom blocks indefinitely and is NOT woken by the done channel
//     alone — closing the conn is what makes it return net.ErrClosed. The conn
//     must be closed BEFORE the wait for this transport (closing AFTER
//     wg.Wait() would deadlock: wait for the reader ⇄ reader waits for the
//     close).
//
// wg.Wait() guarantees no stale reader is left delivering into the
// package-global pending map. Safe to call when run() was never called (no
// reader to wait for) and safe to call twice (closeOnce).
func (e *Engine) Close() {
	e.closeOnce.Do(func() {
		e.closeDone()
		if e.isDgram {
			if e.dgram != nil {
				e.dgram.stop()
			}
		} else if e.closeFn != nil {
			// raw transport: closing the conn is the wake-up, so it must
			// happen before wg.Wait(), not after.
			_ = e.closeFn()
		}
		e.wg.Wait()
		if e.isDgram && e.closeFn != nil {
			_ = e.closeFn()
		}
	})
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

// closeDone closes the stop-signal channel exactly once (nil-safe:
// test-constructed engines that never set done are handled).
func (e *Engine) closeDone() {
	if e.done != nil {
		close(e.done)
	}
}

// run starts the single reply-reader goroutine for the active transport,
// tracked by wg so Close() can wait for it to finish.
func (e *Engine) run() {
	if e.done == nil {
		e.done = make(chan struct{})
	}
	if e.isDgram {
		// The platform datagram driver starts (and wg-tracks) its own reader.
		if e.dgram != nil {
			e.dgram.run(e)
		}
		return
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			e.readRaw()
			select { // readRaw returns on done (clean) or an unexpected error: supervise it
			case <-e.done:
				return
			case <-time.After(readerRestartDelay):
				log.Printf("pulsemon: icmp reader (raw) restarted after an unexpected stop")
			}
		}
	}()
}

// readerRestartDelay is the pause before a stopped reader goroutine is
// restarted (both transports). A var so tests can shrink it.
var readerRestartDelay = time.Second

// readRaw is the reader for the raw socket: parse IP/ICMP, filter by our
// constant ID, dispatch by seq (source-IP verified in deliver).
//
// The raw conn is blocking, and Close() closes the connection (before
// waiting for this reader) precisely because that is what makes the pending
// ReadFrom return net.ErrClosed — so this reader always terminates. The done
// check also gives a fast exit between reads.
func (e *Engine) readRaw() {
	atomic.StoreInt32(&e.readerAlive, 1)
	defer atomic.StoreInt32(&e.readerAlive, 0)
	buf := make([]byte, 1500)
	for {
		select {
		case <-e.done:
			return
		default:
		}
		n, src, err := e.rawConn.ReadFrom(buf)
		if err != nil {
			// errors.Is, not ==: ReadFrom wraps it in a *net.OpError, so the
			// bare sentinel compare never matched (2026-10-19 review m4).
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("pulsemon: icmp reader (raw): read: %v (reader stopping)", err)
			}
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

// Ping sends one ICMP echo to dst and waits for the reply. ctx bounds the
// wait: a cancelled ctx (shutdown, sensor remove/restart) returns a loss
// immediately instead of holding the caller until the timeout — this is what
// keeps Run's wg.Wait() (and main's 10s shutdown budget) honest for sensors
// with long timeouts (up to 30s).
func (e *Engine) Ping(ctx context.Context, dst net.IP, timeout time.Duration) PingResult {
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
		// counter value anyway (least-­bad option here).
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
		if isBrokenSendErr(err) {
			probeErrCount.Add(1)
			return PingResult{Lost: true, Error: err, Broken: true}
		}
		return PingResult{Lost: true, Error: err} // per-target failure: just a loss
	}
	// A successful send proves the socket is usable, so clear the error
	// state: probeErrCount tracks failures SINCE the last success, not the
	// total since start. Without this reset, one transient failure (e.g. the
	// first probe at boot, before the network stack is ready) would pin the
	// "pulsing is broken" banner forever even after ICMP recovers.
	probeErrCount.Store(0)
	// Explicit timer, stopped on every return path. (time.After works on
	// Go 1.23+ — the runtime reclaims an abandoned timer's object early,
	// verified empirically on this toolchain — but an abandoned After
	// timer still occupies the runtime's timer heap until it fires, so a
	// 2ms reply on a 1s timeout parks a useless pending wake-up for ~1s.
	// NewTimer + Stop removes it the instant the probe returns.)
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case d := <-p.ch:
		return PingResult{RTT: d, Lost: false}
	case <-t.C:
		return PingResult{Lost: true}
	case <-ctx.Done():
		// Caller is going away (shutdown / sensor removed or reconfigured):
		// stop waiting for a reply that no one will record.
		return PingResult{Lost: true, Error: ctx.Err()}
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
	// Join the Once first: sharedEngineInst is only written inside it, so
	// reading it without having passed through Do is an unsynchronized
	// read racing a concurrent first SharedEngine() call (healthz polled
	// vs first probe tick). Do on an already-run Once is a no-op load.
	sharedEngineOnce.Do(func() {})
	if sharedEngineInst != nil {
		return sharedEngineInst.mode
	}
	return ""
}

// EngineDead reports whether the shared ICMP engine was attempted and BOTH
// transports failed (datagram: gid outside net.ipv4.ping_group_range; raw:
// no CAP_NET_RAW / root). Once dead it stays dead for the process lifetime
// (the open is a sync.Once), so healthz can surface it as a stable condition
// instead of the old silent behavior: server running, healthz "ok", no
// pings. The probe worker warms the engine at startup precisely so this is
// visible immediately, not after the first failed probe tick.
func EngineDead() bool {
	sharedEngineOnce.Do(func() {}) // see EngineMode: synchronize with the Once's writes
	return sharedEngineErr != nil
}

// errNoIcmpTransport is the sentinel for "neither ICMP transport could open".
// It wraps the underlying errors so diagnostics still surface, but gives
// healthz / tests a stable thing to match against (errors.Is).
var errNoIcmpTransport = errors.New("icmp: no transport available")

// pingHost is the probe worker's entry point: resolve the target, then
// ping the resolved IP through the shared engine. ctx bounds BOTH phases
// (DNS + reply wait) so a cancelled probe (shutdown, remove, restart)
// aborts immediately instead of running out its full timeout.
func pingHost(ctx context.Context, target string, timeout time.Duration) PingResult {
	ip, err := resolveIPAddrWithTimeout(ctx, target, 5*time.Second)
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
		return PingResult{Lost: true, Error: err, ResolvedIP: dst.String(), Broken: true}
	}
	res := e.Ping(ctx, dst, timeout)
	res.ResolvedIP = dst.String()
	return res
}

// resolveIPAddrWithTimeout resolves an IP with a hard deadline so a hung
// DNS lookup can't wedge a sensor's probe (it becomes a loss row instead of
// a permanent block). Uses a context so the lookup is CANCELLED on timeout —
// the old pattern (goroutine + net.ResolveIPAddr) returned on time but left
// the un-cancellable resolver goroutine behind, leaking one per probe.
func resolveIPAddrWithTimeout(ctx context.Context, host string, timeout time.Duration) (*net.IPAddr, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("DNS resolution of %q timed out after %s", host, timeout)
		}
		return nil, err
	}
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			return &ip, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address found for %s", host)
}
