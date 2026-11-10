package main

// Webhook SSRF guard: 0.0.0.0/8 is blocked wholesale (on Linux the whole block
// routes locally, not just 0.0.0.0), incl. IPv4-mapped IPv6 forms.

import (
	"net"
	"testing"
)

// TestCheckWebhookIPBlocksZeroEight locks the 0.0.0.0/8 addition: on Linux
// the whole block routes locally (not just 0.0.0.0), so IsUnspecified()
// alone left http://0.1.2.3 reaching local services.
func TestCheckWebhookIPBlocksZeroEight(t *testing.T) {
	for _, s := range []string{"0.0.0.0", "0.1.2.3", "0.255.255.255"} {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad test IP %q", s)
		}
		if err := checkWebhookIP(ip, s); err == nil {
			t.Errorf("checkWebhookIP(%q) = nil, want blocked (0.0.0.0/8 routes local on Linux)", s)
		}
	}
	// IPv4-mapped IPv6 form must be judged as IPv4 too.
	if err := checkWebhookIP(net.ParseIP("::ffff:0.1.2.3"), "::ffff:0.1.2.3"); err == nil {
		t.Error("IPv4-mapped ::ffff:0.1.2.3 not blocked")
	}
}

// TestRedirectTargetAllowed locks the probe redirect guard: same-host hops
// pass (router.local/ -> /login shape), cross-host pivots into loopback /
// link-local metadata are refused, and LAN cross-host hops stay allowed.
