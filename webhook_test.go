package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// TestWebhookMasked locks the credential-masking contract. Google Chat keeps
// its key in a query string (mask the query); Discord embeds its token in the
// path (mask the last path segment). A regression here means the settings
// API echoes a live secret — a real leak, not a cosmetic bug.
func TestWebhookMasked(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"google chat query key",
			"https://chat.googleapis.com/v1/spaces/abc/messages?key=SECRET&token=TOK",
			"https://chat.googleapis.com/v1/spaces/abc/messages?***"},
		{"discord path token",
			"https://discord.com/api/webhooks/12345/abcdef-ghijkl-mnopq",
			"https://discord.com/api/webhooks/12345/***"},
		{"plain no secret", "https://example.com/hook", "https://example.com/***"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := webhookMasked(c.in); got != c.want {
				t.Errorf("webhookMasked(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
	// The mask must never expose the original secret substring.
	for _, secret := range []string{"SECRET", "TOK", "abcdef-ghijkl-mnopq"} {
		m := webhookMasked("https://chat.googleapis.com/v1/spaces/a/messages?key=SECRET&token=TOK")
		if contains(m, secret) {
			t.Errorf("masked URL still contains secret %q: %q", secret, m)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (index(s, sub) >= 0)
}

func index(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// TestChatEnabledLegacyDefault locks the upgrade path for the legacy
// google_chat provider: with no explicit flag, a present URL keeps it active
// (existing installs keep alerting with zero config); no URL → off (fresh
// installs stay clean). An explicit flag always wins.
func TestChatEnabledLegacyDefault(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "prov.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// No URL, no flag → off (fresh install).
	if chatEnabled(db) {
		t.Error("no URL, no flag: chatEnabled should be false (fresh install)")
	}
	// URL present, no flag → on (legacy default).
	if err := db.SetSetting("google_chat_url", "https://chat.googleapis.com/v1/spaces/a/messages?key=x"); err != nil {
		t.Fatal(err)
	}
	if !chatEnabled(db) {
		t.Error("URL present, no flag: chatEnabled should be true (legacy default)")
	}
	// Explicit off beats a present URL.
	if err := db.SetSetting("google_chat_enabled", "0"); err != nil {
		t.Fatal(err)
	}
	if chatEnabled(db) {
		t.Error("explicit off should win over a present URL")
	}
	// Explicit on with no URL still reports enabled (but activeProviders
	// separately requires a URL to actually send).
	if err := db.SetSetting("google_chat_enabled", "1"); err != nil {
		t.Fatal(err)
	}
	if !chatEnabled(db) {
		t.Error("explicit on should win regardless of URL")
	}
}

// TestFlagEnabledGeneric locks the generic provider (discord): it needs an
// explicit "1" flag AND a URL to be active; no legacy default.
func TestFlagEnabledGeneric(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "prov2.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	// discord: no flag → off even if a URL exists (must be explicitly enabled).
	if err := db.SetSetting("discord_url", "https://discord.com/api/webhooks/1/tok"); err != nil {
		t.Fatal(err)
	}
	if flagEnabled("discord")(db) {
		t.Error("discord with URL but no flag should be off (no legacy default)")
	}
	if err := db.SetSetting("discord_enabled", "1"); err != nil {
		t.Fatal(err)
	}
	if !flagEnabled("discord")(db) {
		t.Error("discord with URL + flag should be on")
	}
	// flagHasURL: non-empty URL.
	if !flagHasURL("discord")(db) {
		t.Error("discord has a URL — flagHasURL should be true")
	}
}

// TestLegacyWebhookMigration locks the v0.1.14 upgrade migration: a pre-
// multi-provider install stores its Google Chat URL in settings.webhook_url.
// After InitSchema, that must land in google_chat_url (idempotent — running
// InitSchema twice must not duplicate or clobber), and a fresh install with
// no legacy row must have neither key.
func TestLegacyWebhookMigration(t *testing.T) {
	// Case A: fresh install — no legacy row → no google_chat_url, no flag.
	fresh, err := NewDB(filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatalf("NewDB fresh: %v", err)
	}
	if err := fresh.InitSchema(); err != nil {
		t.Fatalf("InitSchema fresh: %v", err)
	}
	if v := fresh.GetSetting("google_chat_url"); v != "" {
		t.Errorf("fresh install should have no google_chat_url, got %q", v)
	}
	if v := fresh.GetSetting("google_chat_enabled"); v != "" {
		t.Errorf("fresh install should have no google_chat_enabled, got %q", v)
	}
	fresh.Close()

	// Case B: legacy install — pre-seed webhook_url, then InitSchema migrates.
	// We open the DB and write the legacy key directly (simulating a pre-
	// v0.1.14 database file), then re-run InitSchema.
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := NewDB(path)
	if err != nil {
		t.Fatalf("NewDB legacy: %v", err)
	}
	if err := legacy.InitSchema(); err != nil {
		t.Fatalf("InitSchema legacy: %v", err)
	}
	// Simulate the old schema's stored webhook.
	if _, err := legacy.Exec(`INSERT INTO settings (setting_key, value) VALUES ('webhook_url', 'https://chat.googleapis.com/v1/spaces/a/messages?key=SECRET')`); err != nil {
		t.Fatalf("seed legacy webhook_url: %v", err)
	}
	legacy.Close()

	// Re-open and re-run InitSchema — the migration should fire.
	db2, err := NewDB(path)
	if err != nil {
		t.Fatalf("reopen legacy: %v", err)
	}
	defer db2.Close()
	if err := db2.InitSchema(); err != nil {
		t.Fatalf("re-InitSchema: %v", err)
	}
	if v := db2.GetSetting("google_chat_url"); v != "https://chat.googleapis.com/v1/spaces/a/messages?key=SECRET" {
		t.Errorf("migration did not copy webhook_url → google_chat_url, got %q", v)
	}
	if v := db2.GetSetting("google_chat_enabled"); v != "1" {
		t.Errorf("migrated install should have google_chat_enabled=1, got %q", v)
	}
	// Idempotency: a second InitSchema must not duplicate the setting row.
	if err := db2.InitSchema(); err != nil {
		t.Fatalf("third InitSchema: %v", err)
	}
	var n int
	if err := db2.QueryRow(`SELECT COUNT(*) FROM settings WHERE setting_key = 'google_chat_url'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("google_chat_url row count after repeated InitSchema = %d, want 1", n)
	}
}

// TestCheckWebhookIPDelta pins the exact property a DNS-rebinding attack
// exploits: a public IP is ALLOWED at save time, while the forbidden
// loopback / cloud-metadata address is BLOCKED. If checkWebhookIP ever
// starts passing a blocked address (or rejecting a public one), the
// rebinding defense below loses its meaning.
func TestCheckWebhookIPDelta(t *testing.T) {
	if err := checkWebhookIP(net.ParseIP("8.8.8.8"), "public.example"); err != nil {
		t.Errorf("public IP 8.8.8.8 must be allowed, got: %v", err)
	}
	if err := checkWebhookIP(net.ParseIP("10.99.99.10"), "ntfy.lan"); err != nil {
		t.Errorf("RFC1918 10.99.99.10 must be allowed (homelab relay), got: %v", err)
	}
	for _, blocked := range []string{"127.0.0.1", "169.254.169.254", "0.0.0.0", "::1"} {
		if err := checkWebhookIP(net.ParseIP(blocked), "rebind.example"); err == nil {
			t.Errorf("blocked address %s must be rejected", blocked)
		}
	}
	// IPv4-mapped IPv6 forms must not slip past the IPv6 checks.
	if err := checkWebhookIP(net.ParseIP("::ffff:127.0.0.1"), "rebind.example"); err == nil {
		t.Error("IPv4-mapped ::ffff:127.0.0.1 must be rejected")
	}
}

// TestDialCheckedBlocksLiteralIP proves the blocklist is enforced on the
// exact address at dial time, not just on a stale save-time lookup. A URL
// whose host is a literal loopback / metadata IP must be refused before any
// connection is made.
func TestDialCheckedBlocksLiteralIP(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1:8443":          "loopback",
		"169.254.169.254:8443":    "link-local",
		"0.0.0.0:8443":            "unspecified",
		"[::1]:8443":              "loopback",
		"[::ffff:127.0.0.1]:8443": "loopback (IPv4-mapped)",
	}
	for addr, why := range cases {
		_, err := dialChecked(context.Background(), "tcp", addr)
		if err == nil {
			t.Errorf("dialChecked(%q) connected to a %s address, want refusal", addr, why)
			continue
		}
		if !strings.Contains(err.Error(), "blocked address") {
			t.Errorf("dialChecked(%q) error = %q, want a 'blocked address' refusal", addr, err.Error())
		}
	}
}

// TestDialCheckedRebinding pins the actual TOCTOU fix: a hostname that a
// save-time check would accept (public IP) but that the resolver returns as
// a forbidden IP at dial time must be refused by dialChecked. We stand up a
// tiny UDP DNS responder that answers every A query with 127.0.0.1 and point
// net.DefaultResolver at it for the duration of the test — simulating a
// rebinding domain that flips from a public IP to loopback between save and
// dial.
func TestDialCheckedRebinding(t *testing.T) {
	// Minimal DNS-over-UDP responder: echo the query id + name, answer the
	// A question with 127.0.0.1.
	udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind UDP for DNS responder: %v", err)
	}
	defer udpConn.Close()
	addr := udpConn.LocalAddr().(*net.UDPAddr)
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := udpConn.ReadFrom(buf)
			if err != nil {
				return // listener closed
			}
			// Walk the question's name labels (each: 1 length byte + label,
			// terminated by a 0 byte) to find where the question section ends
			// (name + 2-byte qtype + 2-byte qclass).
			i := 12
			questionEnd := -1
			for i+3 < n && buf[i] != 0 {
				l := int(buf[i])
				if i+l+1 > n {
					break // malformed: no root terminator in packet
				}
				i += l + 1
			}
			// Normal termination means buf[i] == 0 (the root label) and the
			// qtype/qclass (4 bytes) still fit.
			if i < n && buf[i] == 0 && i+5 <= n {
				questionEnd = i + 1 + 4 // root label + qtype + qclass
			}
			if questionEnd < 0 {
				continue
			}
			// Response: header (response, RD|RA, 1 question, 1 answer) +
			// the original question bytes + an A answer naming the root.
			resp := append([]byte(nil), buf[0:2]...)
			resp = append(resp, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
			resp = append(resp, buf[12:questionEnd]...)
			resp = append(resp,
				0x00,                   // answer name = root
				0x00, 0x01, 0x00, 0x01, // type A, class IN
				0x00, 0x00, 0x00, 0x00, // ttl 0
				0x00, 0x04, // rdlength 4
				127, 0, 0, 1, // 127.0.0.1
			)
			udpConn.WriteTo(resp, from)
		}
	}()

	oldResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if network == "tcp" {
				return nil, fmt.Errorf("resolver: no TCP DNS in this test")
			}
			d := &net.Dialer{}
			c, err := d.DialContext(ctx, "udp4", addr.String())
			if err != nil {
				return nil, err
			}
			// Wrap so the resolver's read/write sizes stay valid.
			return c, nil
		},
	}
	defer func() { net.DefaultResolver = oldResolver }()

	// Sanity: the fake resolver actually hands back 127.0.0.1 for our host.
	ips, err := net.LookupIP("rebind.zm")
	if err != nil {
		t.Fatalf("fake resolver did not answer: %v", err)
	}
	if len(ips) == 0 || !ips[0].IsLoopback() {
		t.Fatalf("fake resolver returned %v, want 127.0.0.1", ips)
	}

	// The rebinding attack: at dial time the host resolves to loopback.
	// dialChecked must refuse to connect to it.
	_, err = dialChecked(context.Background(), "tcp", "rebind.zm:8443")
	if err == nil {
		t.Fatalf("dialChecked connected to a rebound loopback address — TOCTOU not closed")
	}
	if !strings.Contains(err.Error(), "blocked address") {
		t.Errorf("dialChecked error = %q, want a 'blocked address' refusal", err.Error())
	}
}

// TestWebhookClientRefusesLoopbackEndToEnd proves the hardened client (not
// just dialChecked in isolation) will not deliver an alert to a loopback or
// metadata endpoint, even though the default http.Client happily would. A
// plain client POST to the same address succeeds; webhookClient's POST must
// fail with a blocked-address refusal.
func TestWebhookClientRefusesLoopbackEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	// srv.URL is http://127.0.0.1:PORT — a loopback literal IP host: a
	// destination the save-time check would reject, and one the stock
	// client would happily reach if pointed at directly.
	u := "http://" + srv.Listener.Addr().String()

	if _, err := webhookClient.Post(u, "application/json", strings.NewReader("{}")); err == nil {
		t.Fatalf("webhookClient delivered to loopback %s, want a blocked-address refusal", u)
	} else if !strings.Contains(err.Error(), "blocked address") {
		t.Errorf("webhookClient error = %q, want a 'blocked address' refusal", err.Error())
	}
	// Control: the stock default client has no such guard and WOULD reach it.
	if _, err := http.DefaultClient.Post(u, "application/json", strings.NewReader("{}")); err != nil {
		t.Logf("default client unexpectedly failed (expected it to connect): %v", err)
	}
}

// TestValidateWebhookURLIPv6 pins the bracketed-IPv6 host handling.
// u.Hostname() already strips brackets and the port, so these all land in
// validateWebhookURL as bare addresses that net.ParseIP handles directly —
// the regression risk is in the verdicts and the reported reason, not in
// parsing. The two security-relevant pins: a BLOCKED literal (loopback,
// link-local, IPv4-mapped) must be refused with an accurate "blocked
// address" reason for EVERY scheme (pre-fix, http://[::1] was misreported as
// "not RFC1918"), and a public IPv6 literal over http must still require
// https.
func TestValidateWebhookURLIPv6(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		ok      bool
		wantErr string // non-empty: error must contain this
	}{
		{"loopback bracketed http", "http://[::1]:8080/hook", false, "blocked address"},
		{"loopback bracketed https", "https://[::1]:8080/hook", false, "blocked address"},
		{"link-local bracketed http", "http://[fe80::1]:8080/hook", false, "blocked address"},
		{"link-local bracketed https", "https://[fe80::1]:8080/hook", false, "blocked address"},
		{"IPv4-mapped loopback http", "http://[::ffff:127.0.0.1]:8080/hook", false, "blocked address"},
		{"IPv4-mapped loopback https", "https://[::ffff:127.0.0.1]:8080/hook", false, "blocked address"},
		{"public IPv6 http requires https", "http://[2001:db8::1]:8080/hook", false, "private RFC1918"},
		{"public IPv6 https allowed", "https://[2001:db8::1]:8080/hook", true, ""},
		{"ULA http allowed", "http://[fc00::1]:8080/hook", true, ""},
		{"ULA https allowed", "https://[fc00::1]:8080/hook", true, ""},
		// Zone identifiers are rejected at URL-parse: safe direction.
		{"zone id http", "http://[::1%eth0]:8080/hook", false, "not a valid URL"},
		{"zone id https", "https://[::1%eth0]:8080/hook", false, "not a valid URL"},
		// Unbracketed bare IPv6 host is not a valid URI to begin with.
		{"unbracketed loopback", "http://::1/hook", false, "not a valid URL"},
		// mDNS / dev domains are rejected regardless of scheme (the suffix
		// check is NOT redundant with the blocklist: a .local name that
		// resolves to RFC1918 passes checkWebhookIP).
		{"localhost http", "http://localhost/hook", false, "cannot be used for alerts"},
		{"localhost https", "https://localhost/hook", false, "cannot be used for alerts"},
		{".local http", "http://myhost.local/hook", false, "cannot be used for alerts"},
		{".local https", "https://myhost.local/hook", false, "cannot be used for alerts"},
		{".localhost http", "http://myhost.localhost/hook", false, "cannot be used for alerts"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateWebhookURL(c.url)
			if c.ok {
				if err != nil {
					t.Errorf("validateWebhookURL(%q) = %v, want nil", c.url, err)
				}
				return
			}
			if err == nil {
				t.Errorf("validateWebhookURL(%q) = nil, want refusal", c.url)
				return
			}
			if c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("validateWebhookURL(%q) error = %q, want it to contain %q", c.url, err.Error(), c.wantErr)
			}
		})
	}
}

// startFakeDNS stands up a UDP DNS responder that answers every A query with
// the given IPv4 address and points net.DefaultResolver at it. The original
// resolver is restored and the listener closed when the test ends.
func startFakeDNS(t *testing.T, respondIP string) {
	t.Helper()
	udpConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind UDP for DNS responder: %v", err)
	}
	addr := udpConn.LocalAddr().(*net.UDPAddr)
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := udpConn.ReadFrom(buf)
			if err != nil {
				return // listener closed
			}
			// Walk the question's name labels to find where the question
			// section ends (name + 2-byte qtype + 2-byte qclass).
			i := 12
			questionEnd := -1
			for i+3 < n && buf[i] != 0 {
				l := int(buf[i])
				if i+l+1 > n {
					break // malformed: no root terminator in packet
				}
				i += l + 1
			}
			if i < n && buf[i] == 0 && i+5 <= n {
				questionEnd = i + 1 + 4 // root label + qtype + qclass
			}
			if questionEnd < 0 {
				continue
			}
			resp := append([]byte(nil), buf[0:2]...)
			resp = append(resp, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
			resp = append(resp, buf[12:questionEnd]...)
			resp = append(resp,
				0x00,                   // answer name = root
				0x00, 0x01, 0x00, 0x01, // type A, class IN
				0x00, 0x00, 0x00, 0x00, // ttl 0
				0x00, 0x04, // rdlength 4
			)
			resp = append(resp, net.ParseIP(respondIP).To4()...)
			udpConn.WriteTo(resp, from)
		}
	}()
	oldResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if network == "tcp" {
				return nil, fmt.Errorf("resolver: no TCP DNS in this test")
			}
			d := &net.Dialer{}
			c, err := d.DialContext(ctx, "udp4", addr.String())
			if err != nil {
				return nil, err
			}
			return c, nil
		},
	}
	t.Cleanup(func() {
		net.DefaultResolver = oldResolver
		udpConn.Close()
	})
}

// TestValidateWebhookURLScheme pins the scheme policy: https:// anywhere,
// http:// only when the host is a private RFC1918 / ULA address (the homelab
// relay case). Public destinations over http are rejected, and the IP
// blocklist (loopback, link-local, ...) still applies regardless of scheme.
func TestValidateWebhookURLScheme(t *testing.T) {
	cases := []struct {
		name string
		url  string
		ok   bool
	}{
		// https is always fine (these are clean addresses).
		{"https public IP", "https://8.8.8.8/hook", true},
		{"https private IP", "https://10.99.99.50:8080/hook", true},
		// http to a private RFC1918 IP is allowed (the internal-relay case).
		{"http 192.168/16", "http://10.99.99.50:8080/hook", true},
		{"http 10/8", "http://10.0.0.5/hook", true},
		{"http 172.16/12 low", "http://172.16.0.5/hook", true},
		{"http 172.16/12 high", "http://172.31.255.255/hook", true},
		// http to a public IP is rejected.
		{"http public IP", "http://8.8.8.8:8080/hook", false},
		// 172.32/8 is NOT in 172.16/12, so it is not private: rejected.
		{"http 172.32 not private", "http://172.32.0.1/hook", false},
		// The blocklist still applies regardless of scheme.
		{"http loopback", "http://127.0.0.1:8080/hook", false},
		{"http link-local metadata", "http://169.254.169.254/hook", false},
		{"http unspecified", "http://0.0.0.0/hook", false},
		{"http loopback v6", "http://[::1]:8080/hook", false},
		// Non-http/https schemes are rejected outright.
		{"ftp scheme", "ftp://10.99.99.50/hook", false},
		{"no host", "http://", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateWebhookURL(c.url)
			if c.ok {
				if err != nil {
					t.Errorf("validateWebhookURL(%q) = %v, want nil", c.url, err)
				}
			} else {
				if err == nil {
					t.Errorf("validateWebhookURL(%q) = nil, want refusal", c.url)
				}
			}
		})
	}
}

// TestValidateWebhookURLHTTPPrivateHostname pins the hostname branch of the
// http relaxation: a host that is not a literal IP but RESOLVES to a private
// RFC1918 address is allowed over http (the user's http://bridge.lan/hook
// case). The fake DNS responder answers every A query with 10.99.99.50 (a neutral RFC1918 placeholder).
func TestValidateWebhookURLHTTPPrivateHostname(t *testing.T) {
	startFakeDNS(t, "10.99.99.50")
	ips, err := net.LookupIP("bridge.lan")
	if err != nil {
		t.Fatalf("fake resolver did not answer: %v", err)
	}
	if len(ips) == 0 || !ips[0].IsPrivate() {
		t.Fatalf("fake resolver returned %v, want a private IP", ips)
	}
	if err := validateWebhookURL("http://bridge.lan/hook"); err != nil {
		t.Errorf("validateWebhookURL(http://bridge.lan/hook) = %v, want nil (private RFC1918 host)", err)
	}
	if err := validateWebhookURL("https://bridge.lan/hook"); err != nil {
		t.Errorf("validateWebhookURL(https://bridge.lan/hook) = %v, want nil", err)
	}
}

// TestValidateWebhookURLHTTPPublicHostname is the security-critical mirror: a
// hostname that resolves to a PUBLIC address must NOT be allowed over http.
// The fake DNS responder answers every A query with 8.8.8.8.
func TestValidateWebhookURLHTTPPublicHostname(t *testing.T) {
	startFakeDNS(t, "8.8.8.8")
	ips, err := net.LookupIP("public.example")
	if err != nil {
		t.Fatalf("fake resolver did not answer: %v", err)
	}
	if len(ips) == 0 || ips[0].IsPrivate() {
		t.Fatalf("fake resolver returned %v, want a public IP", ips)
	}
	if err := validateWebhookURL("http://public.example/hook"); err == nil {
		t.Error("validateWebhookURL(http://public.example/hook) = nil, want refusal (public host over http)")
	}
	if err := validateWebhookURL("https://public.example/hook"); err != nil {
		t.Errorf("validateWebhookURL(https://public.example/hook) = %v, want nil", err)
	}
}
