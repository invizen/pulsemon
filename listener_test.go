package main

import (
	"net"
	"testing"
)

// TestHTTPSAddrFor pins the PULSEMON_ADDR → TLS-address derivation,
// including the IPv6 forms: the result must be a valid host:port with
// exactly one pair of brackets. The old LastIndex split kept the brackets
// in the host and JoinHostPort double-wrapped them — "[[::1]]:443" is an
// invalid address, so a TLS install with an IPv6 PULSEMON_ADDR could not
// bind.
func TestHTTPSAddrFor(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{"", ":443"}, // unset → the binary's own ":9299" default
		{":8080", ":443"},
		{"127.0.0.1:8080", "127.0.0.1:443"},
		{"10.0.0.5:8443", "10.0.0.5:443"},
		{"[::1]:8080", "[::1]:443"},
		{"::1:8080", "[::1]:443"}, // unbracketed form
		{"8080", ":443"},          // bare port
	}
	for _, c := range cases {
		t.Setenv("PULSEMON_ADDR", c.addr)
		got := httpsAddrFor(443)
		if got != c.want {
			t.Errorf("httpsAddrFor(443) with PULSEMON_ADDR=%q = %q, want %q", c.addr, got, c.want)
		}
		// Every result must round-trip through SplitHostPort — an invalid
		// address (e.g. double brackets) fails here.
		if _, _, err := net.SplitHostPort(got); err != nil {
			t.Errorf("httpsAddrFor(443) with PULSEMON_ADDR=%q = %q is not a valid host:port: %v", c.addr, got, err)
		}
	}
}
