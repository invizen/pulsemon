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
//     admin console would get zenmon's egress for free. Real webhook
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
// 192.168/16) is deliberately ALLOWED — a homelab may legitimately point at
// an internal relay (self-hosted ntfy, chat bridge), and an attacker on the
// same LAN can already reach those hosts directly, so blocking them buys
// nothing.
func validateWebhookURL(raw string) error {
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return errors.New("not a valid URL")
	}
	if u.Scheme != "https" {
		return errors.New("must be an https:// URL")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("must include a host")
	}
	if ip := net.ParseIP(host); ip != nil {
		return checkWebhookIP(ip, host)
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") || strings.HasSuffix(lower, ".local") {
		return fmt.Errorf("host %q cannot be used for alerts", host)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("cannot resolve host %q: %v", host, err)
	}
	for _, ip := range ips {
		if err := checkWebhookIP(ip, host); err != nil {
			return err
		}
	}
	return nil
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
	return nil
}
