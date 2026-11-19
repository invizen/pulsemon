package main

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// --- Finding #13: webhook/SMTP SSRF & dialer flaws ---
//
// Four defects: (1) dialChecked returned (nil, nil) on an empty-but-
// successful resolver result — a nil-conn panic in smtp.go's
// conn.SetDeadline and inside net/http; (2) the .local/.localhost suffix
// checks did not strip trailing dots, so "printer.local." / "localhost."
// bypassed the only thing keeping mDNS names out of the http-relay path;
// (3) the save-time http gate accepted ANY-private resolution while the
// dial-time rule (dialCheckedCleartext) requires ALL-private — a host with
// mixed A records saved clean and then failed EVERY delivery; (4)
// embeddedIPv4 matched ff ff 00 00 in bytes 8-11 without requiring the
// first 8 bytes to be zero, misclassifying genuine IPv6 addresses (and
// false-blocking a literal whose trailing quad sat in a blocked IPv4
// range).

// TestDialCheckedEmptyResolverResult: a resolver that SUCCEEDS with an
// empty answer must yield a dial ERROR, not (nil, nil) — the old shape
// panicked at the first dereference of the conn (smtp.go's
// conn.SetDeadline, net/http inside the transport).
func TestDialCheckedEmptyResolverResult(t *testing.T) {
	withFakeResolver(t, map[string][]net.IP{
		"empty.example": {}, // present key, empty answer: ([]net.IP)(nil-free) + nil error
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dialChecked(ctx, "tcp", "empty.example:80")
	if err == nil {
		t.Fatal("empty resolver result: err = nil, want an explicit no-IP error (the old (nil, nil) panics the caller)")
	}
	if conn != nil {
		t.Errorf("empty resolver result: conn = %v, want nil", conn)
	}
	if !strings.Contains(err.Error(), "no IP address") {
		t.Errorf("empty resolver result: err = %v, want the no-IP diagnostic", err)
	}
}

// TestValidateWebhookURLTrailingDot: the FQDN form (trailing dot) must not
// bypass the .local/.localhost suffix rejection — DNS treats the dotted
// name as the same name, so the bypass is a pure save-time filter hole.
func TestValidateWebhookURLTrailingDot(t *testing.T) {
	cases := []struct {
		raw  string
		want bool // true = must be rejected
	}{
		{"http://printer.local.", true},               // the reported bypass: mDNS + cleartext
		{"https://localhost.", true},                  // the reported bypass: loopback
		{"http://localhost.", true},                   // cleartext loopback, dotted
		{"https://printer.local", true},               // control: undotted .local still blocked
		{"http://printer.local", true},                // control: undotted .local still blocked
		{"https://printer.local..", true},             // multiple trailing dots
		{"https://relay.example.com", false},          // positive control: normal host
		{"https://my.local.relay.example.com", false}, // ".local" inside the name is fine
	}
	for _, c := range cases {
		_, _, err := validateWebhookURLNoDNS(c.raw)
		if c.want && err == nil {
			t.Errorf("%s: accepted, want the mDNS/localhost suffix rejection (trailing-dot bypass)", c.raw)
		}
		if !c.want && err != nil {
			t.Errorf("%s: rejected (%v), want accepted", c.raw, err)
		}
	}
}

// TestValidateWebhookURLCleartextAllPrivate: the save-time http gate must
// be at least as strict as the dial-time rule (dialCheckedCleartext
// requires EVERY answer private). A host with mixed A records (one
// private, one public) used to save clean and then fail EVERY delivery
// with "resolved to a public address" — a URL that can never deliver.
func TestValidateWebhookURLCleartextAllPrivate(t *testing.T) {
	withFakeResolver(t, map[string][]net.IP{
		"mixed.example": {net.ParseIP("10.0.0.5"), net.ParseIP("93.184.216.34")},
		"lan.example":   {net.ParseIP("10.0.0.5"), net.ParseIP("192.168.1.10")},
	})
	// Mixed records over http: the dial rule would refuse this on every
	// delivery, so save must refuse it too.
	if err := validateWebhookURL("http://mixed.example/hook"); err == nil {
		t.Error("mixed A records over http://: accepted at save, but dialCheckedCleartext refuses it on every delivery")
	} else if !strings.Contains(err.Error(), "https://") {
		t.Errorf("mixed A records over http://: err = %v, want the https-required message", err)
	}
	// All-private over http: a legitimate LAN relay — must save.
	if err := validateWebhookURL("http://lan.example/hook"); err != nil {
		t.Errorf("all-private over http://: rejected (%v), want accepted (LAN relay)", err)
	}
	// The gate is scheme-scoped: the same mixed name over https is fine
	// (TLS to a public address is the normal case).
	if err := validateWebhookURL("https://mixed.example/hook"); err != nil {
		t.Errorf("mixed A records over https://: rejected (%v), want accepted", err)
	}
}

// TestEmbeddedIPv4ZeroPrefixRequired: the ff ff 00 00 layout is an
// embedded form ONLY with a zero leading 8 bytes (what the :: in
// ::ffff:0:a.b.c.d expands to). A genuine ULA/GUA with ffff:0000 in
// bytes 8-11 must not have its trailing 32 bits judged as IPv4 —
// pre-fix, fd12:3456::ffff:0:a9fe:1 (a perfectly legitimate ULA) was
// false-blocked as 169.254.0.1.
func TestEmbeddedIPv4ZeroPrefixRequired(t *testing.T) {
	// The recognized layout is still recognized (zero prefix + ff ff 00 00).
	if v4 := embeddedIPv4(net.ParseIP("::ffff:0:127.0.0.1")); v4 == nil || v4.String() != "127.0.0.1" {
		t.Errorf("embeddedIPv4(::ffff:0:127.0.0.1) = %v, want 127.0.0.1", v4)
	}
	// The all-zeros-12 layout is still recognized.
	if v4 := embeddedIPv4(net.ParseIP("::127.0.0.1")); v4 == nil || v4.String() != "127.0.0.1" {
		t.Errorf("embeddedIPv4(::127.0.0.1) = %v, want 127.0.0.1", v4)
	}
	// A genuine ULA with ffff:0000 in bytes 8-11 and a NON-ZERO prefix is
	// not an embedded form — no IPv4 view at all.
	ula := net.ParseIP("fd12:3456::ffff:0:a9fe:1")
	if v4 := embeddedIPv4(ula); v4 != nil {
		t.Errorf("embeddedIPv4(fd12:3456::ffff:0:a9fe:1) = %v, want nil (genuine IPv6)", v4)
	}
	// End-to-end: the ULA above carries a trailing quad in 169.254/16, so
	// pre-fix checkWebhookIP false-blocked it. Now it passes.
	if err := checkWebhookIP(ula, "ula.example"); err != nil {
		t.Errorf("checkWebhookIP(fd12:3456::ffff:0:a9fe:1) = %v, want nil (the embedded view was a false positive)", err)
	}
	// Same shape, a GUA (non-ULA) prefix: also legitimate.
	gua := net.ParseIP("2606:4700::ffff:0:a9fe:1")
	if err := checkWebhookIP(gua, "gua.example"); err != nil {
		t.Errorf("checkWebhookIP(2606:4700::ffff:0:a9fe:1) = %v, want nil", err)
	}
	// Controls: the embedded forms with a BLOCKED trailing quad are still
	// blocked (the fix must not weaken the real detections).
	if err := checkWebhookIP(net.ParseIP("::ffff:0:169.254.0.1"), "meta.example"); err == nil {
		t.Error("::ffff:0:169.254.0.1 accepted, want blocked (embedded metadata address)")
	}
	if err := checkWebhookIP(net.ParseIP("::169.254.0.1"), "meta2.example"); err == nil {
		t.Error("::169.254.0.1 accepted, want blocked (IPv4-compatible metadata address)")
	}
	if err := checkWebhookIP(net.ParseIP("::ffff:0:127.0.0.1"), "lb.example"); err == nil {
		t.Error("::ffff:0:127.0.0.1 accepted, want blocked (embedded loopback)")
	}
}
