package main

import (
	"net/http"
	"strings"
	"testing"
)

// NITS batch (2026-11-20): small findings — the webhook transport's unbounded
// idle lifetime, and the PATCH target-error message leaking the ICMP text for
// TCP targets. (The SQL/EXISTS query optimizations in this batch are
// behavior-identical and pinned by their existing store/bootstrap suites; the
// UI polish is pinned by the Node harness.)

// TestWebhookTransportHasBoundedIdleLifetime pins the transport clone: a bare
// &http.Transport{} leaves IdleConnTimeout and MaxIdleConns at 0 (unbounded
// idle conns, no handshake timeout). The transport must now inherit
// http.DefaultTransport's sane limits while keeping the no-proxy + dialChecked
// security contract.
func TestWebhookTransportHasBoundedIdleLifetime(t *testing.T) {
	tt := webhookTransport
	if tt.IdleConnTimeout == 0 {
		t.Fatal("webhookTransport.IdleConnTimeout is 0 (unbounded idle conns) — it must inherit http.DefaultTransport's 90s limit")
	}
	if tt.MaxIdleConns == 0 {
		t.Fatal("webhookTransport.MaxIdleConns is 0 (unbounded) — it must inherit http.DefaultTransport's 100")
	}
	if tt.Proxy != nil {
		t.Fatal("webhookTransport.Proxy is not nil — webhook egress must never route through an ambient proxy")
	}
	if tt.DialContext == nil {
		t.Fatal("webhookTransport.DialContext is nil — the dial-time blocklist check is gone")
	}
}

// TestPatchTCPInvalidTargetGetsTCPMessage pins the PATCH error-message fix:
// a TCP sensor with an invalid target must get the TCP "host:port" message,
// not the ICMP "IPv4 address or hostname" text (the old hardcoded case returned
// the ICMP text for BOTH types). The ICMP path is the positive control — it
// still gets its own message.
func TestPatchTCPInvalidTargetGetsTCPMessage(t *testing.T) {
	_, do := newM10bServer(t)

	code, out := do(http.MethodPost, "/api/sensors", `{"name":"tcp1","target":"192.0.2.1:80","type":"tcp"}`)
	if code != http.StatusCreated {
		t.Fatalf("seed TCP sensor: %d %v", code, out)
	}
	id, _ := out["id"].(string)

	// PATCH the TCP target to a bare IP (no port) — invalid for TCP.
	code, out = do(http.MethodPatch, "/api/sensors/"+id, `{"target":"192.0.2.1"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("PATCH TCP target without port = %d, want 400: %v", code, out)
	}
	msg, _ := out["error"].(string)
	if !strings.Contains(msg, "host:port") {
		t.Fatalf("TCP target error = %q, want the TCP 'host:port' message", msg)
	}
	if strings.Contains(msg, "IPv4 address or hostname") {
		t.Fatalf("TCP target error = %q leaked the ICMP 'IPv4 address or hostname' text", msg)
	}

	// Positive control: an ICMP sensor with an IPv6 literal (neither an IPv4
	// address nor a hostname) still gets the ICMP message.
	code, out = do(http.MethodPost, "/api/sensors", `{"name":"icmp1","target":"2001:db8::1"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("POST ICMP sensor with an IPv6 target = %d, want 400: %v", code, out)
	}
	if msg, _ := out["error"].(string); msg != "target must be an IPv4 address or hostname" {
		t.Fatalf("ICMP target error = %q, want the ICMP 'IPv4 address or hostname' message", msg)
	}
}
