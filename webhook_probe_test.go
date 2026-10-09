package main

import (
	"net"
	"net/url"
	"strconv"
	"testing"
)

// Diagnostic probe (temporary): for a battery of IPv6/localhost spellings,
// print Hostname(), ParseIP result, and the real validateWebhookURL verdict.
// Deleted after inspection.
func TestProbeIPv6EdgeCases(t *testing.T) {
	cases := []string{
		"http://[::1]:8080/hook",
		"https://[::1]:8080/hook",
		"http://[::1%eth0]:8080/hook",
		"https://[::1%eth0]:8080/hook",
		"http://[fe80::1]:8080/hook",
		"https://[fe80::1]:8080/hook",
		"http://[fe80::1%eth0]:8080/hook",
		"https://[fe80::1%eth0]:8080/hook",
		"http://[::ffff:127.0.0.1]:8080/hook",
		"https://[::ffff:127.0.0.1]:8080/hook",
		"http://[2001:db8::1]:8080/hook",
		"https://[2001:db8::1]:8080/hook",
		"http://[fc00::1]:8080/hook",
		"https://[fc00::1]:8080/hook",
		"http://localhost/hook",
		"https://localhost/hook",
		"http://myhost.localhost/hook",
		"http://myhost.local/hook",
		"http://::1/hook", // no brackets, no port
	}
	for _, raw := range cases {
		u, perr := url.ParseRequestURI(raw)
		host := ""
		if perr == nil {
			host = u.Hostname()
		}
		ip := net.ParseIP(host)
		ipStr := "<nil>"
		if ip != nil {
			ipStr = ip.String() + " loop=" + strconv.FormatBool(ip.IsLoopback()) + " linkloc=" + strconv.FormatBool(ip.IsLinkLocalUnicast()) + " priv=" + strconv.FormatBool(ip.IsPrivate())
		}
		err := validateWebhookURL(raw)
		verdict := "ALLOWED"
		if err != nil {
			verdict = "REFUSED: " + err.Error()
		}
		t.Logf("raw=%-34s host=%-16s parseIP=%-40s => %s", raw, host, ipStr, verdict)
	}
}
