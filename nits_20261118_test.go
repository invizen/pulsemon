package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// NITS batch (2026-11-18): four small findings — the copy-pasted 429 block,
// the ICMP timeout not including DNS, probeTCP's missing nil-IP guard, and
// the JSON decoders not rejecting unknown fields. Each test pins one.

// TestRespondThrottledSetsRetryAfter pins the 429 helper: it derives
// Retry-After by ceiling to whole seconds (minimum 1) and answers 429 with
// the caller's message. The five throttle/lockout sites now share this.
func TestRespondThrottledSetsRetryAfter(t *testing.T) {
	cases := []struct {
		name string
		wait time.Duration
		want string
	}{
		{"sub-second rounds up to 1", 200 * time.Millisecond, "1"},
		{"exact second", 5 * time.Second, "5"},
		{"ceiling to next second", 5*time.Second + time.Millisecond, "6"},
		{"zero floors to 1", 0, "1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			respondThrottled(rr, c.wait, "too many")
			if rr.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want 429", rr.Code)
			}
			if got := rr.Header().Get("Retry-After"); got != c.want {
				t.Fatalf("Retry-After = %q, want %q", got, c.want)
			}
		})
	}
}

// TestPingHostBoundsDNSToTimeout pins the ICMP fix: the DNS lookup and the
// reply wait are bounded TOGETHER by the probe timeout (mirror of probeTCP /
// probeHTTP). Before the fix the DNS ran its own latency ON TOP of the
// timeout, so a slow resolver + a 30s Pulse Now could outlast the server's
// 30s WriteTimeout and the client got nothing. A resolver that takes 1s must
// not make a 200ms probe take 1s.
func TestPingHostBoundsDNSToTimeout(t *testing.T) {
	const target = "slowdns.example"
	stubResolver(t, func(ctx context.Context, host string, timeout time.Duration) (*net.IPAddr, error) {
		// Simulate a slow/hung resolver (far longer than the probe timeout).
		<-time.After(1 * time.Second)
		return &net.IPAddr{IP: net.ParseIP("192.0.2.1")}, nil
	})
	clearDNSCache(t, target)

	start := time.Now()
	res := pingHost(context.Background(), target, 200*time.Millisecond)
	elapsed := time.Since(start)
	if !res.Lost || !res.DNS {
		t.Fatalf("1s-slow DNS on a 200ms timeout: want a DNS loss, got %+v", res)
	}
	if elapsed > 800*time.Millisecond {
		t.Fatalf("pingHost took %v; the DNS phase must be bounded by the 200ms probe timeout, not added on top of it", elapsed)
	}
	// Drain the background singleflight call so the stub-swap cleanup in
	// t.Cleanup doesn't race the still-running shared-call goroutine: a
	// second dnsLookup on the same target JOINS the in-flight call and
	// blocks until it completes — the channel receive is the happens-before
	// edge that orders the cleanup's write after the shared call's read.
	// (pingHost returned early via ctx.Done() without joining, so without
	// this the -race run flags the stub swap.)
	_, _ = dnsLookup(context.Background(), target)
}

// TestProbeTCPIPv6LiteralIsCleanLoss pins the probeTCP nil-IP guard: an IPv6
// literal (a hand-edited row; save-time validation rejects these) resolves to
// no IPv4 (resolveICMPTarget returns nil, nil). Before the fix probeTCP dialed
// ":port" (an empty host is localhost); now it is a clean loss.
func TestProbeTCPIPv6LiteralIsCleanLoss(t *testing.T) {
	res := probeTCP(context.Background(), "[2001:db8::1]:80", time.Second)
	if !res.Lost {
		t.Fatalf("probeTCP on an IPv6 literal: want Lost, got %+v", res)
	}
	if res.IP != "" {
		t.Fatalf("probeTCP on an IPv6 literal: want empty IP, got %q", res.IP)
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "no IPv4 address") {
		t.Fatalf("probeTCP on an IPv6 literal: want a 'no IPv4 address' error, got %v", res.Err)
	}
}

// TestPatchSensorRejectsUnknownField pins the strict-decode fix: a misspelled
// field alongside a valid one is now a 400 (before the fix the misspelled
// field was silently ignored and the valid one applied). Well-formed payloads
// are unaffected.
func TestPatchSensorRejectsUnknownField(t *testing.T) {
	_, do := newM10bServer(t)
	code, out := do(http.MethodPost, "/api/sensors", `{"name":"uf","target":"192.0.2.1"}`)
	if code != http.StatusCreated {
		t.Fatalf("seed sensor: %d %v", code, out)
	}
	id, _ := out["id"].(string)

	// "timout_ms" is a typo for "timeout_ms" — with a valid "name" present.
	code, out = do(http.MethodPatch, "/api/sensors/"+id, `{"name":"renamed","timout_ms":5000}`)
	if code != http.StatusBadRequest {
		t.Fatalf("PATCH with a misspelled field = %d, want 400: %v", code, out)
	}
	// The valid-only request still works (strict decode must not reject
	// well-formed payloads).
	code, out = do(http.MethodPatch, "/api/sensors/"+id, `{"name":"renamed"}`)
	if code != http.StatusOK {
		t.Fatalf("PATCH with a valid field = %d, want 200: %v", code, out)
	}
}
