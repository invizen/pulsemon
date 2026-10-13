package main

import (
	"strings"
	"testing"
)

// Telegram uses HTML parse mode (<b>bold</b>). The card carries the same
// information as the Discord/Google Chat cards, HTML-flavored.
func TestTelegramCard(t *testing.T) {
	c := telegramCard("up", "error", "zenkub1", "192.168.1.10", 0)
	for _, want := range []string{
		"❌", "<b>pulsemon: error</b>",
		"<b>Sensor:</b> zenkub1", "<b>Target:</b> 192.168.1.10",
		"<b>State:</b> error",
	} {
		if !strings.Contains(c, want) {
			t.Fatalf("telegramCard missing %q in:\n%s", want, c)
		}
	}
	// No RTT for a down ICMP sensor: no <b>Ping:</b> line.
	if strings.Contains(c, "<b>Ping:</b>") {
		t.Fatalf("unexpected Ping line in down card:\n%s", c)
	}
}

func TestTelegramCardWithRTT(t *testing.T) {
	c := telegramCard("up", "warning", "nas", "10.0.0.5", 120.4)
	if !strings.Contains(c, "<b>Ping:</b> 120 ms") {
		t.Fatalf("expected Ping line, got:\n%s", c)
	}
}

func TestTelegramCardRe(t *testing.T) {
	c := telegramCardRe("error", "zenkub1", "192.168.1.10", 0)
	for _, want := range []string{
		"❌", "re-alert", "<b>State:</b> error",
	} {
		if !strings.Contains(c, want) {
			t.Fatalf("telegramCardRe missing %q in:\n%s", want, c)
		}
	}
}

func TestTelegramCardIcons(t *testing.T) {
	cases := map[string]string{
		"up":      "✅",
		"warning": "⚠️",
		"error":   "❌",
	}
	for state, icon := range cases {
		c := telegramCard("up", state, "s", "t", 0)
		if !strings.Contains(c, icon) {
			t.Fatalf("state %s: expected icon %s in:\n%s", state, icon, c)
		}
	}
}

// TestTelegramCardEscapesAmpersandInTarget locks the finding-9 fix: a URL
// query string with a raw & (validURL accepts it) must reach the card as
// &amp; — an unescaped & in Telegram HTML parse mode can make the API
// reject the message with 400 "can't parse entities", silently dropping
// the alert. Both card variants are checked.
func TestTelegramCardEscapesAmpersandInTarget(t *testing.T) {
	target := "https://host.lan/health?service=a&check=1"
	for _, c := range []string{
		telegramCard("up", "error", "zenkub1", target, 0),
		telegramCardRe("error", "zenkub1", target, 0),
	} {
		if !strings.Contains(c, "&amp;check=1") {
			t.Fatalf("expected escaped &amp;check=1 in:\n%s", c)
		}
		if strings.Contains(c, "a&check") {
			t.Fatalf("unescaped & reached the card:\n%s", c)
		}
	}
}

// TestTelegramCardEscapesMarkupInTarget locks the other half: url.Parse
// (and thus validURL) accepts raw markup in the URL path (verified on
// Go 1.26: https://host.lan/<b>bold</b> parses fine), so an unescaped
// target would inject live <b> markup into the Telegram card. It must be
// escaped to &lt;b&gt; instead.
func TestTelegramCardEscapesMarkupInTarget(t *testing.T) {
	target := "https://host.lan/<b>bold</b>"
	for _, c := range []string{
		telegramCard("up", "error", "zenkub1", target, 0),
		telegramCardRe("error", "zenkub1", target, 0),
	} {
		if !strings.Contains(c, "&lt;b&gt;bold&lt;/b&gt;") {
			t.Fatalf("expected escaped markup in:\n%s", c)
		}
		if strings.Contains(c, "<b>bold</b>") {
			t.Fatalf("unescaped markup injected into the card:\n%s", c)
		}
		// The card's own intentional tags must survive escaping.
		if !strings.Contains(c, "<b>Sensor:</b> zenkub1") {
			t.Fatalf("intentional card tags were damaged:\n%s", c)
		}
	}
}
