package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// xffReq builds a login request with the given TCP peer and (optional)
// X-Forwarded-For header.
func xffReq(remote, xff string) *http.Request {
	r := httptest.NewRequest("POST", "/api/auth/login", nil)
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

// captureLog redirects the service log to a buffer for the test's
// duration (same pattern as TestFix_ScanErrorsLoggedNotSilent).
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf
}

// TestClientIPUntrustedPeerXFFWarnsOnce (2026-10-23 external review F8):
// a request from an UNTRUSTED peer carrying X-Forwarded-For is the
// signature of a reverse proxy missing from PULSEMON_TRUSTED_PROXIES —
// every client behind it shares the proxy's throttle bucket, so 7 bad
// guesses from anyone lock everyone out for 5 minutes. The warning must
// fire exactly once per process, name the peer (the value the operator
// needs for PULSEMON_TRUSTED_PROXIES), and the header must STAY ignored
// — the diagnostic must not loosen the security behavior.
func TestClientIPUntrustedPeerXFFWarnsOnce(t *testing.T) {
	xffMisconfigWarned.Store(false)
	buf := captureLog(t)

	a := NewAuthState(nil) // no trusted proxies
	for i := 0; i < 3; i++ {
		if got := a.ClientIP(xffReq("203.0.113.5:1234", "10.0.0.9")); got != "203.0.113.5" {
			t.Fatalf("ClientIP call %d = %q, want peer 203.0.113.5 (XFF from an untrusted peer must stay ignored)", i, got)
		}
	}
	out := buf.String()
	if n := strings.Count(out, "PULSEMON_TRUSTED_PROXIES"); n != 1 {
		t.Errorf("misconfiguration warning logged %d times, want exactly 1\nlog:\n%s", n, out)
	}
	if !strings.Contains(out, "203.0.113.5") {
		t.Errorf("warning does not name the peer (the value to put in PULSEMON_TRUSTED_PROXIES):\n%s", out)
	}
}

// TestClientIPTrustedPeerXFFNoWarn: the happy path — proxy listed in
// PULSEMON_TRUSTED_PROXIES, XFF honored — must not trigger the
// misconfiguration warning.
func TestClientIPTrustedPeerXFFNoWarn(t *testing.T) {
	xffMisconfigWarned.Store(false)
	buf := captureLog(t)

	t.Setenv("PULSEMON_TRUSTED_PROXIES", "127.0.0.1")
	a := NewAuthState(nil)
	if got := a.ClientIP(xffReq("127.0.0.1:999", "203.0.113.7, 10.0.0.1")); got != "10.0.0.1" {
		t.Fatalf("ClientIP = %q, want 10.0.0.1 (trusted-proxy XFF honored)", got)
	}
	if buf.Len() != 0 {
		t.Errorf("trusted-proxy path logged a warning:\n%s", buf.String())
	}
}

// TestClientIPUntrustedPeerNoXFFNoWarn: a plain direct connection (no
// XFF header at all) must not warn.
func TestClientIPUntrustedPeerNoXFFNoWarn(t *testing.T) {
	xffMisconfigWarned.Store(false)
	buf := captureLog(t)

	a := NewAuthState(nil)
	if got := a.ClientIP(xffReq("10.0.0.5:1234", "")); got != "10.0.0.5" {
		t.Fatalf("ClientIP = %q, want 10.0.0.5", got)
	}
	if buf.Len() != 0 {
		t.Errorf("no-XFF path logged a warning:\n%s", buf.String())
	}
}
