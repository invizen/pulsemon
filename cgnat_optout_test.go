package main

import (
	"context"
	"net"
	"testing"
)

// setAllowCGNAT flips the CGNAT opt-out for the duration of a test and
// restores the startup value (the env var is install-time, so tests are
// the only other writer of allowCGNAT).
func setAllowCGNAT(t *testing.T, on bool) {
	t.Helper()
	old := allowCGNAT
	allowCGNAT = on
	t.Cleanup(func() { allowCGNAT = old })
}

// TestCGNATOptOutParsing pins the accepted env spellings: 1/true/yes
// (any case, surrounding whitespace) enable the opt-out; anything else —
// including unset — keeps the block.
func TestCGNATOptOutParsing(t *testing.T) {
	cases := map[string]bool{
		"":       false,
		"0":      false,
		"false":  false,
		"no":     false,
		"banana": false,
		"1":      true,
		"true":   true,
		"yes":    true,
		" TRUE ": true,
	}
	for v, want := range cases {
		t.Setenv("PULSEMON_ALLOW_CGNAT", v)
		if got := parseCGNATOptOut(); got != want {
			t.Errorf("parseCGNATOptOut() with PULSEMON_ALLOW_CGNAT=%q = %v, want %v", v, got, want)
		}
	}
}

// TestCGNATBlockedByDefault pins the default posture: CGNAT is refused on
// both boundaries of 100.64.0.0/10. (F6: this is exactly what broke
// Tailscale — the opt-out tests below are the fix, and it must not leak
// into the default.) webhook_reserved_test.go pins the same for the
// webhook path; the opt-out changed this code, so pin it here too.
func TestCGNATBlockedByDefault(t *testing.T) {
	setAllowCGNAT(t, false)
	for _, s := range []string{"100.64.0.1", "100.127.255.254"} {
		if err := checkWebhookIP(net.ParseIP(s), "tail.example"); err == nil {
			t.Errorf("checkWebhookIP(%s) by default = nil, want refusal", s)
		}
	}
}

// TestCGNATOptOutAllowsTailnet: with the opt-out the CGNAT range passes —
// a Tailscale/Headscale node is the operator's own extended LAN.
func TestCGNATOptOutAllowsTailnet(t *testing.T) {
	setAllowCGNAT(t, true)
	for _, s := range []string{"100.64.0.1", "100.100.1.5", "100.127.255.254"} {
		if err := checkWebhookIP(net.ParseIP(s), "tail.example"); err != nil {
			t.Errorf("checkWebhookIP(%s) with opt-out = %v, want allow", s, err)
		}
	}
}

// TestCGNATOptOutIsCGNATOnly: the opt-out widens NOTHING else. The
// 169.254/16 metadata block (the protection that actually matters here),
// loopback, 0/8, reserved-for-testing, and Class E stay refused; public
// space and the always-allowed LAN categories are untouched.
func TestCGNATOptOutIsCGNATOnly(t *testing.T) {
	setAllowCGNAT(t, true)
	for _, s := range []string{"169.254.169.254", "127.0.0.1", "0.0.0.1", "198.18.0.1", "240.0.0.1", "255.255.255.255"} {
		if err := checkWebhookIP(net.ParseIP(s), "meta.example"); err == nil {
			t.Errorf("checkWebhookIP(%s) with opt-out = nil, want refusal (opt-out is CGNAT-only)", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "192.168.1.1", "10.0.0.1", "172.16.0.1", "100.63.255.254", "100.128.0.1"} {
		if err := checkWebhookIP(net.ParseIP(s), "ok.example"); err != nil {
			t.Errorf("checkWebhookIP(%s) with opt-out = %v, want allow", s, err)
		}
	}
}

// TestCGNATOptOutEmbeddedIPv6: the dotted-quad / mapped forms go through
// the embedded-IPv4 recursion — the opt-out must apply to the CGNAT form
// (::6440:1 == 100.64.0.1) and NOT to the metadata form
// (::a9fe:a9fe == 169.254.169.254).
func TestCGNATOptOutEmbeddedIPv6(t *testing.T) {
	setAllowCGNAT(t, false)
	for _, s := range []string{"::6440:1", "::a9fe:a9fe"} {
		if err := checkWebhookIP(net.ParseIP(s), "v6.example"); err == nil {
			t.Errorf("checkWebhookIP(%s) by default = nil, want refusal", s)
		}
	}
	setAllowCGNAT(t, true)
	if err := checkWebhookIP(net.ParseIP("::6440:1"), "v6.example"); err != nil {
		t.Errorf("checkWebhookIP(::6440:1) with opt-out = %v, want allow", err)
	}
	if err := checkWebhookIP(net.ParseIP("::a9fe:a9fe"), "v6.example"); err == nil {
		t.Error("checkWebhookIP(::a9fe:a9fe) with opt-out = nil, want refusal (metadata block stays)")
	}
}

// TestRedirectTargetAllowedCGNAT: the HTTP-sensor redirect guard shares
// the canonical judge, so the opt-out covers it — a redirect to a tailnet
// host is refused by default and allowed under PULSEMON_ALLOW_CGNAT (F6's
// second breakage: http://nas → https://nas.tail1234.ts.net).
func TestRedirectTargetAllowedCGNAT(t *testing.T) {
	setAllowCGNAT(t, false)
	if err := redirectTargetAllowed(context.Background(), "100.64.7.7", "nas.example"); err == nil {
		t.Error("redirect to 100.64.7.7 by default = nil, want refusal")
	}
	setAllowCGNAT(t, true)
	if err := redirectTargetAllowed(context.Background(), "100.64.7.7", "nas.example"); err != nil {
		t.Errorf("redirect to 100.64.7.7 with opt-out = %v, want allow", err)
	}
}

// TestCGNATOptOutSMTPSavePath: the SMTP save path shares the canonical
// judge too — an SMTP relay on the tailnet is refused by default and
// allowed under the opt-out.
func TestCGNATOptOutSMTPSavePath(t *testing.T) {
	setAllowCGNAT(t, false)
	if err := validateSMTPHostNoDNS("100.64.9.9"); err == nil {
		t.Error("validateSMTPHostNoDNS(100.64.9.9) by default = nil, want refusal")
	}
	setAllowCGNAT(t, true)
	if err := validateSMTPHostNoDNS("100.64.9.9"); err != nil {
		t.Errorf("validateSMTPHostNoDNS(100.64.9.9) with opt-out = %v, want allow", err)
	}
}
