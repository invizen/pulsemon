package main

import (
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

// webhookClient is the ONLY client used for alert delivery. Two deliberate
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
var webhookClient = &http.Client{
	Timeout: 10 * time.Second,
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
