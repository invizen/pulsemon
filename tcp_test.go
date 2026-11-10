package main

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestValidTCPTarget(t *testing.T) {
	cases := []struct {
		target string
		ok     bool
	}{
		{"10.0.0.5:5432", true},
		{"192.168.1.1:22", true},
		{"nas:5432", true},       // bare single-label LAN name
		{"example.com:80", true}, // dotted hostname
		{"127.0.0.1:1", true},
		{"127.0.0.1:65535", true},
		{"10.0.0.5", false},           // no port
		{"nas", false},                // no port
		{"10.0.0.5:0", false},         // port out of range
		{"10.0.0.5:65536", false},     // port out of range
		{"10.0.0.5:abc", false},       // non-numeric port
		{"10.0.0.5:-1", false},        // negative port
		{"999.999.999.999:80", false}, // out-of-range octets
		{"[::1]:80", false},           // IPv6 (product is IPv4-only)
		{"", false},
		{" 10.0.0.5:80", false}, // leading space is not trimmed (input hygiene)
	}
	for _, c := range cases {
		if got := validTCPTarget(c.target); got != c.ok {
			t.Errorf("validTCPTarget(%q) = %v, want %v", c.target, got, c.ok)
		}
	}
}

// listenTCP starts a throwaway TCP listener on loopback and returns its
// address plus a cleanup.
func listenTCP(t *testing.T) (addr string, cleanup func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return l.Addr().String(), func() { l.Close() }
}

func TestProbeTCPOpenPort(t *testing.T) {
	addr, cleanup := listenTCP(t)
	defer cleanup()

	r := probeTCP(context.Background(), addr, 2*time.Second)
	if r.Lost {
		t.Fatalf("probe to open port lost: %v", r.Err)
	}
	if r.Elapsed <= 0 {
		t.Errorf("elapsed = %v, want > 0", r.Elapsed)
	}
	if r.IP != "127.0.0.1" {
		t.Errorf("ip = %q, want 127.0.0.1", r.IP)
	}
	if r.DNS {
		t.Error("loopback IP literal misclassified as DNS")
	}
}

func TestProbeTCPClosedPort(t *testing.T) {
	// Grab a free port, then close the listener so the dial is refused.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	l.Close()

	r := probeTCP(context.Background(), addr, 2*time.Second)
	if !r.Lost {
		t.Fatal("probe to closed port not lost")
	}
	if r.DNS {
		t.Error("connection refusal misclassified as DNS failure")
	}
	if r.IP != "127.0.0.1" {
		t.Errorf("ip = %q, want 127.0.0.1", r.IP)
	}
}

func TestProbeTCPTimeout(t *testing.T) {
	// TEST-NET-1 (RFC 5737): documentation space, not routed on a LAN —
	// the connect runs out its budget. (An environment that answers with
	// an immediate no-route error is fine too: the assertion is Lost.)
	r := probeTCP(context.Background(), "192.0.2.1:80", 400*time.Millisecond)
	if !r.Lost {
		t.Fatal("probe to unroutable IP not lost")
	}
	if r.DNS {
		t.Error("IP literal misclassified as DNS failure")
	}
}

func TestProbeTCPDNSFailure(t *testing.T) {
	// RFC 2606 .invalid: guaranteed not to resolve (same pattern as
	// ping_test.go's resolver tests).
	r := probeTCP(context.Background(), "nonexistent-host-pulsemon-test.invalid:5432", 2*time.Second)
	if !r.Lost {
		t.Fatal("unresolvable host not lost")
	}
	if !r.DNS {
		t.Error("DNS failure not classified (the dns_error column would be empty)")
	}
	if r.IP != "" {
		t.Errorf("ip = %q, want empty (no target IP was known)", r.IP)
	}
}

func TestProbeTargetDispatchesTCP(t *testing.T) {
	addr, cleanup := listenTCP(t)
	defer cleanup()

	o := probeTarget(context.Background(), "tcp", addr, 2*time.Second)
	if o.lost {
		t.Fatalf("dispatched tcp probe lost: ip=%q", o.ip)
	}
	if o.rttMs <= 0 {
		t.Errorf("rttMs = %v, want > 0", o.rttMs)
	}
	if o.ip != "127.0.0.1" {
		t.Errorf("ip = %q, want 127.0.0.1", o.ip)
	}
	if o.httpCode != nil || o.certExpiry != nil {
		t.Error("tcp outcome carries http fields")
	}
	if o.dnsErr != "" {
		t.Errorf("dnsErr = %q, want empty", o.dnsErr)
	}
}

func TestNormalizeProbeTypeTCP(t *testing.T) {
	for _, in := range []string{"tcp", "TCP", " Tcp "} {
		if got := normalizeProbeType(in); got != "tcp" {
			t.Errorf("normalizeProbeType(%q) = %q, want tcp", in, got)
		}
	}
}

func TestSensorSpecValidateTCP(t *testing.T) {
	full := func(target string) sensorSpec {
		return sensorSpec{Name: "pg", Target: target, Type: "tcp", IntervalS: 60, TimeoutMS: 1000, LossWarn: 25, DownAfter: 2, SpikeMult: 5}
	}
	check := func(target string, wantErr bool) {
		t.Helper()
		s := full(target) // a func-call result is not addressable; materialize before the pointer-receiver validate
		err := s.validate()
		if (err != nil) != wantErr {
			t.Errorf("validate(%q) = %v, wantErr=%v", target, err, wantErr)
		}
	}
	check("10.0.0.5:5432", false)
	check("example.com:5432", false)
	check("nas:22", false)
	check("10.0.0.5", true)                   // portless
	check("10.0.0.5:70000", true)             // out of range
	check("https://example.com/health", true) // an http URL is not a tcp target
}
