package main

import "testing"

// TestAlertTargetQueryRedaction is the repro for the 2026-11-20 finding:
// query-string tokens (?token=…) in sensor targets were never redacted —
// only user:pass@ was — so a ?token=… in an http target went VERBATIM
// into every alert card (Discord/Telegram/Chat/SMTP) and to viewer
// sessions (viewerTarget reuses alertTarget). The query/fragment is now
// cut on the same raw-string path as the userinfo.
func TestAlertTargetQueryRedaction(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// The finding's shape: a token in the query.
		{"https://host/health?token=abc123", "https://host/health"},
		// Token-only target (no path).
		{"https://host?token=abc", "https://host"},
		// Userinfo AND query: both cut.
		{"https://user:pass@host/health?token=abc", "https://host/health"},
		// Fragment (carries tokens too, and never reaches the server).
		{"https://host/path#frag", "https://host/path"},
		// Query before fragment.
		{"https://host/p?a=1#f", "https://host/p"},
		// No query: unchanged (the common case must not churn).
		{"https://host/path", "https://host/path"},
		{"https://user:pass@host/health", "https://host/health"},
		// '@' in the PATH survives (only the query is cut).
		{"https://host/path@with@at?x=1", "https://host/path@with@at"},
		// A '?' starts the QUERY under net/url (userinfo cannot contain
		// one, RFC 3986) — host "user" stands, the query is cut.
		{"https://user?x:pass@host/", "https://user"},
		// Bare IP / host:port: no authority, untouched.
		{"192.0.2.10", "192.0.2.10"},
		{"192.0.2.11:5432", "192.0.2.11:5432"},
	} {
		if got := alertTarget(tc.in); got != tc.want {
			t.Errorf("alertTarget(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
