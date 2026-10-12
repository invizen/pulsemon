package main

import "testing"

// TestValidateSMTPHostIP locks the M1 fix: an SMTP mail-server host that is an
// IP literal must be judged against the same reserved-range blocklist the
// webhook path uses. Loopback, link-local (incl. the 169.254.169.254
// cloud-metadata address), unspecified, multicast, carrier-NAT, and
// reserved-for-testing are all refused; RFC1918 and public addresses are
// allowed (a homelab mail server on the LAN is the point).
func TestValidateSMTPHostIP(t *testing.T) {
	cases := []struct {
		host string
		ok   bool
	}{
		{"10.0.0.5", true},         // RFC1918 LAN relay — allowed
		{"192.168.1.10", true},     // RFC1918 — allowed
		{"172.16.0.3", true},       // RFC1918 — allowed
		{"8.8.8.8", true},          // public — allowed
		{"127.0.0.1", false},       // loopback
		{"169.254.169.254", false}, // link-local / cloud metadata
		{"169.254.1.1", false},     // link-local
		{"0.0.0.0", false},         // unspecified
		{"224.0.0.1", false},       // multicast
		{"100.64.0.1", false},      // carrier-grade NAT (blockedSubnets)
		{"198.18.0.1", false},      // reserved-for-testing (blockedSubnets)
		{"", false},                // empty
	}
	for _, c := range cases {
		err := validateSMTPHost(c.host)
		if c.ok && err != nil {
			t.Errorf("validateSMTPHost(%q) = %v, want nil", c.host, err)
		}
		if !c.ok && err == nil {
			t.Errorf("validateSMTPHost(%q) = nil, want an error", c.host)
		}
	}
}

// TestValidateSMTPHostFormat locks the hostname-format gate (no DNS involved):
// syntactically invalid hostnames are refused before any resolution attempt,
// and "localhost" is refused because it resolves to loopback.
func TestValidateSMTPHostFormat(t *testing.T) {
	// Malformed hostnames: refused on format, before resolution.
	for _, bad := range []string{"bad host", "exa mple.com", "-leading.com", "trailing-.com", "a..com", longLabel + ".com"} {
		if err := validateSMTPHost(bad); err == nil {
			t.Errorf("validateSMTPHost(%q) = nil, want a format error", bad)
		}
	}
	// localhost resolves to 127.0.0.1 (loopback) on every platform we care
	// about, so it must be refused by the resolved-answer check.
	if err := validateSMTPHost("localhost"); err == nil {
		t.Error("validateSMTPHost(\"localhost\") = nil, want a loopback error")
	}
}

// longLabel is a 64-char label (one over the 63-char RFC 1123 max).
const longLabel = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// TestValidSMTPHostname locks the pure RFC 1123 hostname validator.
func TestValidSMTPHostname(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"mail", true},                    // single label (bare LAN name)
		{"mail.local", true},              // mDNS-style LAN name
		{"smtp.gmail.com", true},          // public
		{"my-mail-server", true},          // hyphen mid-label
		{"a-b-c.d-e.f", true},             // multi-label
		{"", false},                       // empty
		{"-leading.com", false},           // leading hyphen
		{"trailing-.com", false},          // trailing hyphen
		{"a..com", false},                 // empty label (double dot)
		{"x" + longLabel + ".com", false}, // label > 63 chars
	}
	for _, c := range cases {
		if got := validSMTPHostname(c.name); got != c.ok {
			t.Errorf("validSMTPHostname(%q) = %v, want %v", c.name, got, c.ok)
		}
	}
}
