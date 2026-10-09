package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Google Chat webhook delivery lives on ProbeWorker (probe.go, sendAlert /
// postCard) — one code path for state-transition alerts. This file holds the
// shared outbound client and destination validation (SSRF hardening,
// 2026-10-04 security review).

// webhookClient is the ONLY client used for alert delivery. Three deliberate
// hardening choices:
//
//  1. No redirects. The default http.Client follows 302s, which is an SSRF
//     pivot: the save-time check requires https://, but a public URL that
//     redirects to http://169.254.169.254/ (cloud metadata) or an internal
//     admin console would get pulsemon's egress for free. Real webhook
//     endpoints (Google Chat, ntfy, …) don't redirect — a redirect is
//     reported to the caller instead of followed.
//  2. 10s timeout. The default client has none; a hung endpoint would
//     block the alert path indefinitely.
//  3. Dial-time IP check (DNS-rebinding defense). validateWebhookURL runs
//     at save time; the default transport resolves the host AGAIN at dial
//     time. A rebinding domain — allowed IP at save time, 127.0.0.1 /
//     169.254.169.254 a second later — would slip past the save-time
//     blocklist. webhookTransport enforces the blocklist at dial time AND
//     connects to the very IP it checked (dialChecked), so the connection
//     cannot land on an address the check never saw — not even one that
//     flips between two lookups microseconds apart.
var webhookDialer = &net.Dialer{KeepAlive: 30 * time.Second}

// dialChecked resolves host (or parses a literal IP), enforces the webhook
// blocklist on every resolved address, and then dials one of the CHECKED
// IPs directly. Checking and then letting the dialer re-resolve the
// hostname would leave a (tiny) window for a rebinding domain to return a
// different, forbidden IP; pinning the dial to the checked address closes
// it. For TLS the transport still performs the handshake with the original
// host as SNI/ServerName, so certificates and HSTS behave normally.
func dialChecked(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		if ips, err = net.DefaultResolver.LookupIP(ctx, "ip", host); err != nil {
			return nil, err
		}
	}
	for _, ip := range ips {
		if err := checkWebhookIP(ip, host); err != nil {
			return nil, err
		}
	}
	// Fall through the checked addresses in order so a blackholed first
	// IP still yields working delivery.
	var lastErr error
	for _, ip := range ips {
		var c net.Conn
		if c, lastErr = webhookDialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port)); lastErr == nil {
			return c, nil
		}
	}
	return nil, lastErr
}

var webhookTransport = &http.Transport{
	// Only DialContext is set: the transport uses it for the TCP connect
	// on BOTH http and https, then performs the TLS handshake itself
	// (default TLSClientConfig, ServerName = the URL host) — so SNI and
	// certificate verification behave normally while the connected IP is
	// still the one dialChecked verified against the blocklist.
	// (Setting DialTLSContext instead would make the transport assume the
	// returned conn is already past the handshake and skip
	// TLSClientConfig entirely — wrong for our purposes.)
	DialContext: dialChecked,
}

var webhookClient = &http.Client{
	Timeout:   10 * time.Second,
	Transport: webhookTransport,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// validateWebhookURL rejects webhook destinations that cannot be legitimate
// alert endpoints. Blocklist: loopback, link-local (covers the 169.254.0.0/16
// cloud-metadata range), unspecified, multicast. RFC1918 (10/8, 172.16/12,
// 192.168/16) and ULA (fc00::/7) are deliberately ALLOWED — a homelab may
// legitimately point at an internal relay (self-hosted ntfy, chat bridge),
// and an attacker on the same LAN can already reach those hosts directly, so
// blocking them buys nothing.
//
// Scheme: https:// anywhere; http:// ONLY when the host itself is (or
// resolves to) such a private address — internal relays commonly run plain
// HTTP with no local TLS certs. Public destinations must use https, because
// an attacker on the LAN who could see a public IP's cleartext can already
// intercept the alert anyway.
//
// Host forms: u.Hostname() already strips brackets and the port, so a
// bracketed IPv6 host ([::1], [fe80::1], [::ffff:127.0.0.1]) lands here as a
// bare address that net.ParseIP understands directly — no separate bracket
// handling is needed. Zone identifiers ([::1%eth0]) are rejected at URL-parse
// ("not a valid URL"), which is the safe direction.
func validateWebhookURL(raw string) error {
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return errors.New("not a valid URL")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("must include a host")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("must be an http:// or https:// URL")
	}
	// A literal IP is judged against the blocklist FIRST, for every scheme.
	// This is where loopback / link-local / unspecified / multicast are
	// rejected with an accurate "blocked address" reason — up front, so a
	// blocked literal over http is never misreported as "not RFC1918".
	// RFC1918 / ULA literals pass the blocklist and are then gated by scheme:
	// https anywhere, http only when private.
	if ip := net.ParseIP(host); ip != nil {
		if err := checkWebhookIP(ip, host); err != nil {
			return err
		}
		if u.Scheme == "http" && !ip.IsPrivate() {
			return fmt.Errorf("must be an https:// URL unless %q is a private RFC1918 host", host)
		}
		return nil
	}
	// Hostname path. Reject mDNS / dev domains that commonly resolve to
	// loopback or LAN addresses. This is NOT redundant with the blocklist:
	// a .local name that mDNS-resolves to a private RFC1918 address PASSES
	// checkWebhookIP (RFC1918 is allowed), so the suffix check is the only
	// thing that keeps those out of the http-relay path.
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") || strings.HasSuffix(lower, ".local") {
		return fmt.Errorf("host %q cannot be used for alerts", host)
	}
	// Resolve ONCE and reuse the answers for both the private-check (http
	// relaxation) and the blocklist pass — the old code resolved twice
	// (httpAllowsPrivate + LookupIP), doubling DNS and letting the two
	// answers disagree across a round-robin/rebind boundary.
	ips, err := net.LookupIP(host)
	if err != nil {
		if u.Scheme == "http" {
			// Match the old failure shape: an http host whose privacy
			// cannot be established is refused the same as a public one.
			return fmt.Errorf("must be an https:// URL unless %q is a private RFC1918 host", host)
		}
		return fmt.Errorf("cannot resolve host %q: %v", host, err)
	}
	if u.Scheme == "http" {
		private := false
		for _, ip := range ips {
			if ip.IsPrivate() {
				private = true
				break
			}
		}
		if !private {
			return fmt.Errorf("must be an https:// URL unless %q is a private RFC1918 host", host)
		}
	}
	for _, ip := range ips {
		if err := checkWebhookIP(ip, host); err != nil {
			return err
		}
	}
	return nil
}

// httpAllowsPrivate was the pre-consolidation double-resolve helper (DNS
// query #2 at save time, whose answer could disagree with the blocklist
// pass). validateWebhookURL now resolves once and judges the same answers;
// the helper is gone.

// blockedSubnets are address ranges a webhook must NEVER target. They are
// not covered by net.IP.IsPrivate() (which is only RFC1918 + ULA), so they
// need an explicit check:
//
//   - 0.0.0.0/8 — on Linux the whole block (not just 0.0.0.0) routes to the
//     local table, so net.IP.IsUnspecified() alone leaves http://0.1.2.3
//     reaching local services.
//   - 198.18.0.0/15 (RFC 2544) — IETF-reserved-for-testing; never a valid
//     destination.
//   - 100.64.0.0/10 (RFC 6598) — Carrier-Grade NAT. This is the ISP's
//     carrier range, NOT the user's LAN: a self-hosted relay reachable from
//     the homelab sits in RFC1918 space (still allowed, see
//     TestCheckWebhookIPDelta), so blocking CGNAT adds defense-in-depth
//     without breaking the documented use case. A webhook pointed at a CGNAT
//     address can never be a working relay.
//
// RFC1918 (10/8, 172.16/12, 192.168/16) and ULA (fc00::/7) are deliberately
// NOT here: the design allows them so a LAN relay works.
var blockedSubnets = []*net.IPNet{
	mustCIDR("0.0.0.0/8"),
	mustCIDR("198.18.0.0/15"),
	mustCIDR("100.64.0.0/10"),
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("pulsemon: bad hardcoded CIDR " + s + ": " + err.Error())
	}
	return n
}

func checkWebhookIP(ip net.IP, host string) error {
	// Also judge the IPv4 view of the address, so IPv4-mapped IPv6 forms
	// (::ffff:127.0.0.1, ::ffff:169.254.1.1) cannot slip past the IPv6
	// range checks.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("host %q resolves to a blocked address (%s)", host, ip)
	}
	// Reserved-for-testing (198.18/15) and carrier-NAT (100.64/10) ranges:
	// never a valid destination (see blockedSubnets).
	for _, n := range blockedSubnets {
		if n.Contains(ip) {
			return fmt.Errorf("host %q resolves to a reserved or carrier-NAT address (%s)", host, ip)
		}
	}
	return nil
}
