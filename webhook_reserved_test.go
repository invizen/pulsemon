package main

import (
	"net"
	"strings"
	"testing"
)

// TestCheckWebhookIPReservedRanges pins the "add a CGNAT / benchmark blocklist"
// review finding. Go's net.IP.IsPrivate() covers ONLY RFC1918 + ULA, so
// IETF-reserved-for-testing (198.18.0.0/15) and Carrier-Grade NAT
// (100.64.0.0/10) were passing checkWebhookIP — a webhook pointed at them
// would silently never be delivered. This test locks those ranges as blocked
// AND locks the design boundary: RFC1918 (the homelab relay) stays ALLOWED.
func TestCheckWebhookIPReservedRanges(t *testing.T) {
	// Reserved-for-testing + CGNAT: must be blocked.
	blocked := []string{
		"198.18.0.1",      // 198.18.0.0/15 bottom
		"198.19.255.254",  // 198.18.0.0/15 top
		"100.64.0.1",      // CGNAT 100.64.0.0/10 bottom
		"100.127.255.254", // CGNAT 100.64.0.0/10 top
	}
	for _, s := range blocked {
		if err := checkWebhookIP(net.ParseIP(s), "rebind.example"); err == nil {
			t.Errorf("checkWebhookIP(%s) = nil, want refusal (reserved-for-testing / CGNAT must be blocked)", s)
		} else if !strings.Contains(err.Error(), "reserved or carrier-NAT") {
			t.Errorf("checkWebhookIP(%s) error = %q, want the reserved/CGNAT refusal", s, err.Error())
		}
	}

	// Just OUTSIDE the blocked ranges: must still be allowed (we don't over-
	// block the public space).
	for _, s := range []string{"198.17.255.254", "198.20.0.1", "100.63.255.254", "100.128.0.1"} {
		if err := checkWebhookIP(net.ParseIP(s), "public.example"); err != nil {
			t.Errorf("checkWebhookIP(%s) = %v, want allow (just outside the blocked ranges)", s, err)
		}
	}

	// The design boundary: RFC1918 is the homelab-relay category and stays
	// ALLOWED. (10.99.99.10 is also asserted in TestCheckWebhookIPDelta;
	// re-assert the full RFC1918 triad here so a future "tighten everything"
	// edit can't silently break the documented use case.)
	for _, s := range []string{"10.0.0.1", "172.16.0.1", "10.99.99.1"} {
		if err := checkWebhookIP(net.ParseIP(s), "ntfy.lan"); err != nil {
			t.Errorf("checkWebhookIP(%s) = %v, want allow (RFC1918 homelab relay must stay allowed)", s, err)
		}
	}
}
