package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Google Chat webhook delivery lives on ProbeWorker (probe.go, sendAlert /
// postCard) — one code path for state-transition alerts. This file holds the
// shared outbound client and destination validation (SSRF hardening).

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
// webhookResolver is the DNS seam for the webhook SSRF checks (tests
// inject a fake resolver to exercise mixed-record and rebind shapes
// deterministically). Production value is the system resolver.
type ipResolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// systemIPResolver reads net.DefaultResolver AT CALL TIME, so tests that
// swap the global fake-DNS resolver (startFakeDNS) keep working through
// this seam; a value captured at init would freeze the original pointer.
type systemIPResolver struct{}

func (systemIPResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, network, host)
}

var webhookResolver ipResolver = systemIPResolver{}

// dialCheckedCleartext is the http-scheme dialer. On top of dialChecked it
// refuses every non-private address: a host that was allowed http:// only
// because it resolved PRIVATE must never be dialed in cleartext at a
// PUBLIC address (mixed A records, or DNS rebinding between the validation
// resolution and this one; review 2026-10-24).
func dialCheckedCleartext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	ips, err := webhookResolver.LookupIP(ctx, "ip", host)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP address for host %q", host)
	}
	for _, ip := range ips {
		if err := checkWebhookIP(ip, host); err != nil {
			return nil, err
		}
		if !ip.IsPrivate() {
			return nil, fmt.Errorf("cleartext http:// webhook target %q resolved to a public address (%s); use https://", host, ip)
		}
	}
	var lastErr error
	for _, ip := range ips {
		conn, err := webhookDialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func dialChecked(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		if ips, err = webhookResolver.LookupIP(ctx, "ip", host); err != nil {
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

// webhookClientCleartext serves http:// webhook URLs so the strict
// all-private dial rule (dialCheckedCleartext) applies to every cleartext
// delivery without touching https (review 2026-10-24). Redirects stay off
// on both clients.
var webhookClientCleartext = &http.Client{
	Timeout: 10 * time.Second,
	Transport: func() *http.Transport {
		t := webhookTransport.Clone()
		t.DialContext = dialCheckedCleartext
		return t
	}(),
	CheckRedirect: webhookClient.CheckRedirect,
}

// webhookClientFor picks the delivery client by URL scheme.
func webhookClientFor(u *url.URL) *http.Client {
	if u.Scheme == "http" {
		return webhookClientCleartext
	}
	return webhookClient
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
// handling is needed. Zone identifiers ([fe80::1%eth0], percent-encoded as
// %25eth0 in the URL) SURVIVE url.Parse and net.ParseIP rejects them, so
// they are refused explicitly (a webhook dial has no link scope; a zone'd
// literal is never a valid alert destination) — the old "rejected at
// URL-parse" claim was stale.
// validateWebhookURLNoDNS runs validateWebhookURL's checks WITHOUT the DNS
// resolution pass: URL shape, scheme, IP-literal
// blocklist, mDNS-suffix rejection. It returns the host and scheme so the
// DNS variant can reuse them without re-parsing. The IN-TRANSACTION save
// path uses this: a 5-second DNS lookup must never run while holding the
// SQLite write lock (it stalls every concurrent probe INSERT). The
// pre-transaction validation pass runs the full with-DNS variant, so an
// unresolvable URL is still rejected before any write begins.
func validateWebhookURLNoDNS(raw string) (string, string, error) {
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return "", "", errors.New("not a valid URL")
	}
	host := u.Hostname()
	if host == "" {
		return "", "", errors.New("must include a host")
	}
	// Zone identifiers (P1): a '%' in the host is a percent-encoded IPv6
	// zone id ([fe80::1%eth0] → host "fe80::1%eth0"). It is never a valid
	// webhook target (no link scope in a webhook dial), and letting it fall
	// through to DNS would die with a misleading "cannot resolve" — refuse
	// it here with the accurate reason. No legitimate hostname contains '%'.
	if strings.Contains(host, "%") {
		return "", "", fmt.Errorf("host %q contains a zone identifier; not a valid webhook target", host)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", "", errors.New("must be an http:// or https:// URL")
	}
	// A literal IP is judged against the blocklist FIRST, for every scheme.
	// This is where loopback / link-local / unspecified / multicast are
	// rejected with an accurate "blocked address" reason — up front, so a
	// blocked literal over http is never misreported as "not RFC1918".
	// RFC1918 / ULA literals pass the blocklist and are then gated by
	// scheme: https anywhere, http only when private.
	if ip := net.ParseIP(host); ip != nil {
		if err := checkWebhookIP(ip, host); err != nil {
			return "", "", err
		}
		if u.Scheme == "http" && !ip.IsPrivate() {
			return "", "", fmt.Errorf("must be an https:// URL unless %q is a private RFC1918 host", host)
		}
		return host, u.Scheme, nil
	}
	// Hostname path. Reject mDNS / dev domains that commonly resolve to
	// loopback or LAN addresses. This is NOT redundant with the blocklist:
	// a .local name that mDNS-resolves to a private RFC1918 address PASSES
	// checkWebhookIP (RFC1918 is allowed), so the suffix check is the only
	// thing that keeps those out of the http-relay path.
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") || strings.HasSuffix(lower, ".local") {
		return "", "", fmt.Errorf("host %q cannot be used for alerts", host)
	}
	return host, u.Scheme, nil
}

func validateWebhookURL(raw string) error {
	host, scheme, err := validateWebhookURLNoDNS(raw)
	if err != nil {
		return err
	}
	if net.ParseIP(host) != nil {
		return nil // IP literal: fully judged by the NoDNS pass.
	}
	// Resolve ONCE and reuse the answers for both the private-check (http
	// relaxation) and the blocklist pass — the old code resolved twice
	// (httpAllowsPrivate + LookupIP), doubling DNS and letting the two
	// answers disagree across a round-robin/rebind boundary. Bounded at 5s:
	// a bare net.LookupIP has no deadline and a hung resolver stalled the
	// caller indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := webhookResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		if scheme == "http" {
			// Match the old failure shape: an http host whose privacy
			// cannot be established is refused the same as a public one.
			return fmt.Errorf("must be an https:// URL unless %q is a private RFC1918 host", host)
		}
		return fmt.Errorf("cannot resolve host %q: %v", host, err)
	}
	if scheme == "http" {
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
//   - 100.64.0.0/10 (RFC 6598) — Carrier-Grade NAT. On a plain LAN this is
//     the ISP's carrier range, NOT the user's LAN: a self-hosted relay
//     reachable from the homelab sits in RFC1918 space (still allowed, see
//     TestCheckWebhookIPDelta), so blocking CGNAT adds defense-in-depth.
//     EXCEPTION: a Tailscale/Headscale
//     tailnet assigns EVERY node an address in exactly this range, so on a
//     tailnet the "NOT the user's LAN" comment is false — a webhook to a
//     self-hosted ntfy/Gotify over the tailnet, and an HTTP sensor whose
//     target redirects to a tailnet host, were both refused. The opt-out:
//     PULSEMON_ALLOW_CGNAT=1 skips this entry only (allowCGNAT);
//     169.254/16 (cloud metadata) and the rest of the blocklist stay hard.
//   - 64:ff9b::/96 (RFC 6052) — NAT64 well-known prefix: an IPv6 literal
//     that TUNNELS an IPv4 destination (e.g. 64:ff9b::7f00:1 == 127.0.0.1).
//     Without this, an attacker writes the loopback address in IPv6 dress.
//   - 2002::/16 (RFC 4380) — Teredo: the same tunneling trick with an
//     embedded IPv4 address in bits 32-63.
//   - 240.0.0.0/4 — Class E (reserved) through 255.255.255.255 (limited
//     broadcast, which lands in this block). Never a valid destination.
//
// RFC1918 (10/8, 172.16/12, 192.168/16) and ULA (fc00::/7) are deliberately
// NOT here: the design allows them so a LAN relay works.
//
// blockedRange is one entry of the list. cgnat marks 100.64.0.0/10, the one
// entry an operator can opt out of (allowCGNAT / PULSEMON_ALLOW_CGNAT) —
// see the CGNAT note above.
type blockedRange struct {
	cidr  *net.IPNet
	cgnat bool
}

var blockedSubnets = []blockedRange{
	{cidr: mustCIDR("0.0.0.0/8")},
	{cidr: mustCIDR("198.18.0.0/15")},
	{cidr: mustCIDR("100.64.0.0/10"), cgnat: true},
	{cidr: mustCIDR("64:ff9b::/96")},
	{cidr: mustCIDR("2002::/16")},
	{cidr: mustCIDR("240.0.0.0/4")},
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("pulsemon: bad hardcoded CIDR " + s + ": " + err.Error())
	}
	return n
}

// allowCGNAT reports whether the operator opted out of the CGNAT
// (100.64.0.0/10) block via PULSEMON_ALLOW_CGNAT. It is read once at startup — an install-time setting like
// PULSEMON_ALLOWED_HOSTS — and the only other writer is tests. When set,
// checkWebhookIP skips the CGNAT entry so webhooks, SMTP relays, and
// sensor-redirect hops can reach a Tailscale/Headscale tailnet (every
// tailnet node lives in 100.64.0.0/10). The opt-out is CGNAT-ONLY:
// 169.254/16 (cloud metadata), loopback, and every other blocked range
// stay hard.
var allowCGNAT = parseCGNATOptOut()

// parseCGNATOptOut parses PULSEMON_ALLOW_CGNAT: 1/true/yes (any case)
// enables the opt-out; anything else (including unset) keeps the block.
func parseCGNATOptOut() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("PULSEMON_ALLOW_CGNAT")))
	return v == "1" || v == "true" || v == "yes"
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
	// Reserved-for-testing (198.18/15), carrier-NAT (100.64/10 — skipped
	// under the PULSEMON_ALLOW_CGNAT opt-out, where it is the tailnet),
	// NAT64 (64:ff9b::/96), Teredo (2002::/16) and Class E/broadcast
	// (240/4) ranges: never a valid destination (see blockedSubnets).
	for _, n := range blockedSubnets {
		if n.cgnat && allowCGNAT {
			continue
		}
		if n.cidr.Contains(ip) {
			return fmt.Errorf("host %q resolves to a reserved or carrier-NAT address (%s)", host, ip)
		}
	}
	// P1: IPv4-embedded IPv6 forms. net.ParseIP
	// normalizes the dotted-quad notation (::a.b.c.d, ::ffff:0:a.b.c.d)
	// into 16-byte addresses whose IPv6 range checks (above) see only the
	// zero/ffff prefix and never the real IPv4 destination in the trailing
	// 32 bits — so ::127.0.0.1 passed every check. Judge that trailing
	// IPv4 with the full IPv4 rules (recursive call; a 4-byte IP has no
	// embedded view, so it terminates).
	if v4 := embeddedIPv4(ip); v4 != nil {
		if err := checkWebhookIP(v4, host); err != nil {
			return err
		}
	}
	return nil
}

// embeddedIPv4 returns the trailing 32 bits as an IPv4 address when the
// 16-byte address is one of the IPv4-embedded forms the dotted-quad
// notation produces, and nil for a genuine IPv6 address. The two recognized
// layouts (P1):
//
//   - ::a.b.c.d            — leading 12 bytes zero (deprecated
//     IPv4-compatible form).
//   - ::ffff:0:a.b.c.d     — bytes 8-11 are ff ff 00 00 (an IPv4-mapped
//     form with an extra zero group; not recognized by net.IP.To4).
//
// A genuine IPv6 address (ULA, GUA, …) has non-zero leading bytes in other
// positions and is left alone — only these two layouts carry an IPv4
// destination that must be judged as IPv4.
func embeddedIPv4(ip net.IP) net.IP {
	if len(ip) != 16 {
		return nil
	}
	zero := true
	for i := 0; i < 12; i++ {
		if ip[i] != 0 {
			zero = false
			break
		}
	}
	if zero {
		return net.IPv4(ip[12], ip[13], ip[14], ip[15])
	}
	if ip[8] == 0xff && ip[9] == 0xff && ip[10] == 0x00 && ip[11] == 0x00 {
		return net.IPv4(ip[12], ip[13], ip[14], ip[15])
	}
	return nil
}

// validateSMTPHost validates the SMTP mail-server host with the same
// reserved-range rules the webhook path applies: a well-formed hostname or IP
// literal that does not land in a reserved range (loopback, link-local —
// including the 169.254.169.254 cloud-metadata address —, unspecified,
// multicast, or blockedSubnets). RFC1918/ULA are allowed, because a homelab
// mail server on the LAN is the point.
//
// Unlike validateWebhookURL there is no scheme gate (SMTP has no scheme) and
// no .local/.localhost suffix rejection: an mDNS-named LAN relay (mail.local)
// is a legitimate SMTP target, and the reserved-range check on the resolved
// answers is what keeps loopback/metadata out. Hostnames are resolved and
// every answer is checked, closing the save-time DNS-rebinding hole the
// webhook path closes.
// validateSMTPHostNoDNS is validateSMTPHost without the resolution pass
// see validateWebhookURLNoDNS for why the
// in-transaction save path must not run DNS under the write lock.
func validateSMTPHostNoDNS(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("smtp host is required")
	}
	if ip := net.ParseIP(host); ip != nil {
		return checkWebhookIP(ip, host)
	}
	if !validSMTPHostname(host) {
		return fmt.Errorf("smtp host %q is not a valid hostname", host)
	}
	return nil
}

func validateSMTPHost(host string) error {
	if err := validateSMTPHostNoDNS(host); err != nil {
		return err
	}
	if net.ParseIP(strings.TrimSpace(host)) != nil {
		return nil // IP literal: fully judged by the NoDNS pass.
	}
	// 5s deadline — context.Background() alone never times out.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("cannot resolve smtp host %q: %v", host, err)
	}
	for _, ip := range ips {
		if err := checkWebhookIP(ip, host); err != nil {
			return err
		}
	}
	return nil
}

// validSMTPHostname reports whether s is a syntactically valid RFC 1123
// hostname: labels of [a-zA-Z0-9-] separated by single dots, no leading or
// trailing hyphen, each label 1-63 chars, total 1-253. A single label (no
// dots) is allowed — a homelab mail server is often reached by a bare name on
// the LAN.
func validSMTPHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
	}
	return true
}
