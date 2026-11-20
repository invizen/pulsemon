package main

// Finding 23 (hostAllowed bracketed IPv6): the allowlist match used
// net.SplitHostPort on the entry, which REJECTS a bracketed no-port value,
// so a PULSEMON_ALLOWED_HOSTS entry stored as [::1] never matched a request
// to [::1]:9299 (only the bare ::1 form worked). These pins lock the
// bracket-agnostic match.

import "testing"

func TestHostAllowedBracketedIPv6(t *testing.T) {
	// Bracketed entry matches the bracketed request host (with and without port).
	s := &Server{allowedHosts: []string{"[::1]"}}
	if !s.hostAllowed("[::1]:9299") {
		t.Fatal("bracketed entry [::1] should match [::1]:9299")
	}
	if !s.hostAllowed("[::1]") {
		t.Fatal("bracketed entry [::1] should match [::1]")
	}
	// A different IPv6 must NOT match.
	if s.hostAllowed("[::2]:9299") {
		t.Fatal("[::2]:9299 must not match the [::1] entry")
	}

	// Bare entry form still works (the pre-existing behavior).
	s2 := &Server{allowedHosts: []string{"::1"}}
	if !s2.hostAllowed("[::1]:9299") {
		t.Fatal("bare entry ::1 should match [::1]:9299")
	}

	// Hostname entries are unaffected by the IPv6 change.
	s3 := &Server{allowedHosts: []string{"pulsemon.example.com"}}
	if !s3.hostAllowed("pulsemon.example.com:9299") {
		t.Fatal("hostname entry should match host:port")
	}
	if s3.hostAllowed("other.example.com") {
		t.Fatal("a different hostname must not match")
	}

	// A port-bearing entry must match exactly (the port is part of the match).
	s4 := &Server{allowedHosts: []string{"example.com:9299"}}
	if !s4.hostAllowed("example.com:9299") {
		t.Fatal("port-bearing entry should match the exact host:port")
	}
	if s4.hostAllowed("example.com:9300") {
		t.Fatal("a different port must not match a port-bearing entry")
	}
}

// TestSplitHostPortLenient pins the helper the bracketed-IPv6 fix depends on:
// it accepts a bracketed IPv6 with NO port ("[::1]") — which net.SplitHostPort
// rejects — and returns the bare host, port, and a hasPort flag.
func TestSplitHostPortLenient(t *testing.T) {
	cases := []struct {
		in          string
		wantHost    string
		wantPort    string
		wantHasPort bool
	}{
		{"[::1]", "::1", "", false},
		{"[::1]:9299", "::1", "9299", true},
		{"[2001:db8::1]:80", "2001:db8::1", "80", true},
		{"example.com", "example.com", "", false},
		{"example.com:9299", "example.com", "9299", true},
		{"10.0.0.5:8080", "10.0.0.5", "8080", true},
		{"127.0.0.1", "127.0.0.1", "", false},
		{"[::1", "[::1", "", false}, // unbalanced bracket: returned as-is (garbage in, no crash)
	}
	for _, c := range cases {
		host, port, hasPort := splitHostPortLenient(c.in)
		if host != c.wantHost || port != c.wantPort || hasPort != c.wantHasPort {
			t.Errorf("splitHostPortLenient(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.in, host, port, hasPort, c.wantHost, c.wantPort, c.wantHasPort)
		}
	}
}
