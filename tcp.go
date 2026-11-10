package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"
)

// tcpProbeResult is the outcome of one TCP connect probe. It mirrors
// httpProbeResult: a one-shot probe (no persistent socket or goroutine),
// normalized by probeTarget into probeOutcome so doProbe, PingNow, and
// status derivation share one code path.
type tcpProbeResult struct {
	// Elapsed is the connect time (DNS + TCP three-way handshake);
	// meaningful only when !Lost. Unlike ICMP's echo RTT, it includes
	// name resolution for hostname targets — the same TTFB stance the
	// HTTP probe takes (its RTT is DNS + TCP + TLS + response).
	Elapsed time.Duration
	Lost    bool
	// IP is the address the connection was made to (diagnostic; empty
	// when the loss happened before a target IP was known).
	IP string
	// Err is the classification detail (timeout, refusal, DNS). doProbe
	// does not store it on the row — only DNS losses are surfaced, as
	// probes.dns_error.
	Err error
	// DNS is true when the loss happened at name resolution (before a
	// target IP was known). probeTarget maps it to probeOutcome.dnsErr
	// so a dead local resolver reads as "DNS failure", not "N hosts
	// down" — the same stance as ICMP (one root cause, an N-sensor
	// storm).
	DNS bool
}

// validTCPTarget reports whether t is a usable TCP sensor target:
// host:port, where host is the same shape validTarget accepts for ICMP
// (an IPv4 address, a dotted hostname, or a bare single-label LAN name)
// and port is an EXPLICIT 1-65535. The port is required: a bare host has
// no default port that means the same thing for every service (5432 for
// Postgres, 22 for SSH, …), so "10.0.0.5" alone is not a TCP target.
func validTCPTarget(t string) bool {
	if t == "" || len(t) > 253 {
		return false
	}
	host, portStr, err := net.SplitHostPort(t)
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	// validTarget is IPv4-only (net.ParseIP + To4 check), matching the
	// rest of the product: an IPv6 literal like "[::1]:80" is rejected
	// at save time, same as an IPv6 ICMP/HTTP target.
	return validTarget(host)
}

// probeTCP performs one TCP connect against target (host:port) and
// classifies it. The connect IS the probe: success = up, and the RTT is
// the connect time. A timeout, a refused connection, or an unresolvable
// name is a loss — the same loss that drives the card's loss%,
// sparkline, and status state, exactly as an ICMP loss does.
//
// Name resolution goes through resolveICMPTarget (the ICMP path's
// bounded, cached resolver) rather than letting net.Dial resolve: it is
// deadline-bounded (a hung resolver becomes a loss row, never a wedged
// tick), it reuses the short-TTL DNS cache with stale fallback, and its
// errors are the ones the dns_error column has always carried. Dialing
// the resolved IP literal means no second resolution happens inside
// DialContext.
func probeTCP(ctx context.Context, target string, timeout time.Duration) tcpProbeResult {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		// Save-time validation (validTCPTarget) prevents this; a
		// hand-edited DB row still probes as a clean loss, not a panic.
		return tcpProbeResult{Lost: true, Err: fmt.Errorf("target must be host:port: %v", err)}
	}
	if port, perr := strconv.Atoi(portStr); perr != nil || port < 1 || port > 65535 {
		return tcpProbeResult{Lost: true, Err: fmt.Errorf("target port out of range: %q", portStr)}
	}

	ip, rerr := resolveICMPTarget(ctx, host)
	if rerr != nil {
		return tcpProbeResult{Lost: true, Err: rerr, DNS: true}
	}

	addr := net.JoinHostPort(ip.String(), portStr)
	start := time.Now()
	conn, derr := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	elapsed := time.Since(start)
	if derr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return tcpProbeResult{Lost: true, IP: ip.String(), Err: fmt.Errorf("TCP connect to %s timed out after %s", addr, timeout)}
		}
		return tcpProbeResult{Lost: true, IP: ip.String(), Err: derr}
	}
	// The connect is the whole probe: close immediately. No keep-alive
	// (a port check is one-shot, and a held conn would mask a server
	// that accepts but never serves).
	defer conn.Close()
	return tcpProbeResult{Elapsed: elapsed, IP: ip.String()}
}
