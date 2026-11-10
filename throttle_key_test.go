package main

// Login-throttle bucketing: CGNAT/overlay (100.64.0.0/10) is per-IP, like
// RFC1918; public and the rest of overlay space stay /24.

import (
	"testing"
)

func TestThrottleKeyBuckets(t *testing.T) {
	cases := []struct {
		in, want string
		why      string
	}{
		{"100.64.5.6", "100.64.5.6", "CGNAT/overlay is per-IP, not /24"},
		{"100.127.255.9", "100.127.255.9", "top of 100.64.0.0/10 still per-IP"},
		{"100.128.0.1", "100.128.0.0", "just above /10 returns to /24 bucketing"},
		{"192.168.1.5", "192.168.1.5", "RFC1918 per-IP (unchanged)"},
		{"8.8.8.8", "8.8.8.0", "public /24 (unchanged)"},
		{"203.0.113.77", "203.0.113.0", "public /24 (unchanged)"},
	}
	for _, c := range cases {
		if got := throttleKey(c.in); got != c.want {
			t.Errorf("throttleKey(%s) = %s, want %s (%s)", c.in, got, c.want, c.why)
		}
	}
}
