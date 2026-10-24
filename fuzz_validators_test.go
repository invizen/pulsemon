package main

// 2026-10-24 review (m4): the input validators are pure functions that
// feed security decisions (string-escape gate, SSRF blocklist, PEM/key
// parsing, SMTP address handling, version pins). Fuzz them for panics and
// invariant violations: `go test -fuzz=Fuzz... -run=XXX` for a real
// session; the baselines below run in every `go test` (fuzz targets run
// their seed corpus as normal tests).

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func FuzzValidSensorName(f *testing.F) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"router", true},
		{"nas-01", true},
		{"x');alert(1);//", false},
		{"a\"b", false},
		{"line1\nline2", false},
		{"", false},
	} {
		if got := validSensorName(tc.name); got != tc.want {
			f.Errorf("validSensorName(%q) = %v, want %v", tc.name, got, tc.want)
		}
		f.Add(tc.name)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = validSensorName(s) // must not panic
	})
}

func FuzzCleanTags(f *testing.F) {
	out := cleanTags([]string{" a ", "a", "b", ""})
	if len(out) != 2 || out[0] != "a" || out[1] != "b" {
		f.Fatalf("cleanTags dedupe/trim: %v", out)
	}
	f.Add(" a \na\nb\n")
	f.Add("x');alert(1);//\nline\nbreak\ntab	sep")
	f.Fuzz(func(t *testing.T, s string) {
		// Fuzz args can't be []string, so encode the tag list as
		// newline-separated text.
		var tags []string
		for _, part := range strings.Split(s, "\n") {
			tags = append(tags, part)
		}
		out := cleanTags(tags)
		if len(out) > 8 {
			t.Fatalf("cleanTags returned %d tags, want <= 8: %v", len(out), out)
		}
		for _, tag := range out {
			if !validSensorName(tag) {
				t.Fatalf("cleanTags emitted an invalid tag %q", tag)
			}
		}
	})
}

func FuzzValidateWebhookURLNoDNS(f *testing.F) {
	if _, _, err := validateWebhookURLNoDNS("https://169.254.169.254/latest"); err == nil {
		f.Error("metadata IP literal accepted, want blocked")
	}
	if _, _, err := validateWebhookURLNoDNS("http://192.168.1.10/hook"); err != nil {
		f.Errorf("private http relay rejected: %v", err)
	}
	if _, _, err := validateWebhookURLNoDNS("ftp://example.com"); err == nil {
		f.Error("non-http(s) scheme accepted")
	}
	for _, seed := range []string{
		"https://169.254.169.254/latest",
		"http://192.168.1.10/hook",
		"ftp://example.com",
		"https://[::1]/hook",
		"169.254.169.254",
		"not a url at all",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _, _ = validateWebhookURLNoDNS(s) // must not panic
	})
}

func FuzzPemBlockFromUpload(f *testing.F) {
	if _, err := pemBlockFromUpload("", "CERTIFICATE"); err == nil {
		f.Error("empty input accepted, want error")
	}
	for _, seed := range []string{
		"",
		"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		"junk before\n-----BEGIN PRIVATE KEY-----\nAAA=\n-----END PRIVATE KEY-----",
		"-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = pemBlockFromUpload(s, "CERTIFICATE") // must not panic
		_, _ = pemBlockFromUpload(s, "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY")
	})
}

func FuzzSmtpAddr(f *testing.F) {
	if _, err := smtpAddr("a@b.c"); err != nil {
		f.Errorf("bare address rejected: %v", err)
	}
	if _, err := smtpAddr("a@b.c\r\nBcc: x@y.z"); err == nil {
		f.Error("CRLF address accepted, want header-injection refused")
	}
	if _, err := smtpAddr(""); err == nil {
		f.Error("empty address accepted")
	}
	for _, seed := range []string{
		"a@b.c",
		"\"quoted\"@b.c",
		"a@b.c\r\nBcc: x@y.z",
		"@@@",
		"a@b.c\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = smtpAddr(s) // must not panic
	})
}

func FuzzValidVersionToken(f *testing.F) {
	// The token is interpolated into a GitHub releases URL, so the
	// invariant is that an accepted token matches the shape the fetcher
	// expects — no slashes, whitespace, or dot-traversal.
	pattern := regexp.MustCompile(`^v[0-9a-zA-Z.+-]{1,39}$`)
	if !validVersionToken("v0.3.27") {
		f.Error("v0.3.27 rejected")
	}
	if validVersionToken("../evil") {
		f.Error("../evil accepted")
	}
	for _, seed := range []string{"v0.3.27", "../evil", "v0.3.27\n", "v a b", "latest"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got := validVersionToken(s); got {
			if !pattern.MatchString(s) {
				t.Fatalf("validVersionToken accepted %q, which does not match the releases-URL shape", s)
			}
		}
	})
}

func FuzzWebhookMasked(f *testing.F) {
	if got := webhookMasked("https://api.telegram.org/bot123:TOKEN/sendMessage"); got != "https://api.telegram.org/***" {
		f.Errorf("webhookMasked: %q", got)
	}
	for _, seed := range []string{
		"https://api.telegram.org/bot123:TOKEN/sendMessage",
		"http://192.168.1.10/hook?token=xyz",
		"nohost",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := webhookMasked(s)
		// A mask must never return the input verbatim when it has a
		// host (the path/query carries the credential).
		if got == s {
			if u, err := url.Parse(s); err == nil && u.Host != "" {
				t.Fatalf("webhookMasked returned the URL verbatim: %q", s)
			}
		}
	})
}

func FuzzAlertTarget(f *testing.F) {
	if got := alertTarget("https://admin:secret@nas.lan/health"); got != "https://nas.lan/health" {
		f.Errorf("alertTarget: %q", got)
	}
	if got := alertTarget("192.168.1.10"); got != "192.168.1.10" {
		f.Errorf("alertTarget on a bare IP: %q", got)
	}
	for _, seed := range []string{
		"https://admin:secret@nas.lan/health",
		"192.168.1.10",
		"https://user@host:8443/path?q=1#frag",
		"not a url",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = alertTarget(s) // must not panic
	})
}

func FuzzSmtpEnvelopeAddr(f *testing.F) {
	if _, err := smtpEnvelopeAddr("a@b.c\r\nX: y"); err == nil {
		f.Error("CRLF envelope address accepted, want refusal")
	}
	for _, seed := range []string{"a@b.c", "a@b.c\r\nX: y", "plainaddr", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = smtpEnvelopeAddr(s) // must not panic
	})
}

func FuzzParseRetryAfter(f *testing.F) {
	now := time.Now()
	if d := parseRetryAfter("45", now); d != 45*time.Second {
		f.Errorf("parseRetryAfter(45) = %v", d)
	}
	if d := parseRetryAfter("999999", now); d != maxAlertRetryAfter {
		f.Errorf("parseRetryAfter(999999) not capped: %v", d)
	}
	if d := parseRetryAfter("garbage", now); d != 0 {
		f.Errorf("parseRetryAfter(garbage) = %v, want 0", d)
	}
	for _, seed := range []string{"45", "999999", "garbage", "-3", "12.5", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if d := parseRetryAfter(s, now); d < 0 || d > maxAlertRetryAfter {
			t.Fatalf("parseRetryAfter(%q) = %v outside [0, cap]", s, d)
		}
	})
}

func FuzzEtagMatches(f *testing.F) {
	const tag = `"abc123"`
	if !etagMatches(tag, tag) {
		f.Error("exact match failed")
	}
	if !etagMatches(`W/`+tag, tag) {
		f.Error("weak-prefix match failed")
	}
	if etagMatches(`"other"`, tag) {
		f.Error("non-matching etag matched")
	}
	for _, seed := range []string{tag, `W/` + tag, `"other"`, "", `W/"abc123" "x"`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, header string) {
		_ = etagMatches(header, tag) // must not panic
	})
}
