package main

// Review 2026-10-24 minor batch — cleartext webhook dial hardening.
// validateWebhookURL allows http:// when the host resolves into private
// RFC1918 space (homelab relays). The shared dialer (dialChecked) re-ran the
// BLOCKLIST per dialed IP but not the privacy requirement — so a host with
// MIXED A records (one private, one public), or DNS rebinding between the
// validation lookup and the dial, could deliver the alert body in cleartext
// to a PUBLIC address. http:// deliveries now go through
// webhookClientCleartext whose dialer requires every resolved address to be
// private; https keeps the existing client untouched.

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

type fakeIPResolver struct {
	m map[string][]net.IP
}

func (f fakeIPResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if ips, ok := f.m[host]; ok {
		return ips, nil
	}
	return nil, errors.New("no such host (fake): " + host)
}

func withFakeResolver(t *testing.T, m map[string][]net.IP) {
	t.Helper()
	orig := webhookResolver
	webhookResolver = fakeIPResolver{m: m}
	t.Cleanup(func() { webhookResolver = orig })
}

func TestDialCheckedCleartextRejectsPublic(t *testing.T) {
	withFakeResolver(t, map[string][]net.IP{
		"pub.example": {net.ParseIP("8.8.8.8")},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := dialCheckedCleartext(ctx, "tcp", "pub.example:80")
	if err == nil || !strings.Contains(err.Error(), "public") {
		t.Fatalf("pure public target: err = %v, want cleartext/public refusal", err)
	}
}

func TestDialCheckedCleartextRejectsMixedRecords(t *testing.T) {
	// The rebind/mixed-A shape: one private + one public address. The
	// private one would pass the old dialer; strict mode refuses the
	// ambiguous name outright — an operator-controlled name that answers
	// both ways cannot be trusted for cleartext.
	withFakeResolver(t, map[string][]net.IP{
		"mixed.example": {net.ParseIP("10.0.0.5"), net.ParseIP("93.184.216.34")},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := dialCheckedCleartext(ctx, "tcp", "mixed.example:80")
	if err == nil || !strings.Contains(err.Error(), "public") {
		t.Fatalf("mixed A records: err = %v, want cleartext/public refusal", err)
	}
}

func TestDialCheckedCleartextStillBlocksLoopback(t *testing.T) {
	withFakeResolver(t, map[string][]net.IP{
		"lb.example": {net.ParseIP("127.0.0.1")},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := dialCheckedCleartext(ctx, "tcp", "lb.example:80")
	if err == nil {
		t.Fatal("loopback target accepted by cleartext dialer")
	}
	// Blocklisted before dial: the error must be the policy error, not a
	// connection error.
	if strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "deadline") {
		t.Fatalf("loopback should be refused by policy pre-dial, got: %v", err)
	}
}

func TestDialCheckedCleartextPrivateDials(t *testing.T) {
	// All-private resolution passes the policy; the dial itself goes to an
	// unroutable TEST-NET address and fails on connectivity (NOT on a
	// policy error) — proving the guard allows legitimate LAN relays.
	withFakeResolver(t, map[string][]net.IP{
		"lan.example": {net.ParseIP("10.255.255.1")},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err := dialCheckedCleartext(ctx, "tcp", "lan.example:80")
	if err == nil {
		t.Skip("unexpectedly connected to TEST-NET address; environment oddity")
	}
	if strings.Contains(err.Error(), "public") || strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("private-only target refused by policy: %v", err)
	}
}

func TestWebhookClientForScheme(t *testing.T) {
	if c := webhookClientFor(&url.URL{Scheme: "http"}); c != webhookClientCleartext {
		t.Error("http:// must use the strict cleartext client")
	}
	if c := webhookClientFor(&url.URL{Scheme: "https"}); c != webhookClient {
		t.Error("https:// must use the standard webhook client")
	}
}
