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
		"🔴", "<b>pulsemon: error</b>",
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
		"🔴", "re-alert", "<b>State:</b> error",
	} {
		if !strings.Contains(c, want) {
			t.Fatalf("telegramCardRe missing %q in:\n%s", want, c)
		}
	}
}

func TestTelegramCardIcons(t *testing.T) {
	cases := map[string]string{
		"up":      "🟢",
		"warning": "🟡",
		"error":   "🔴",
	}
	for state, icon := range cases {
		c := telegramCard("up", state, "s", "t", 0)
		if !strings.Contains(c, icon) {
			t.Fatalf("state %s: expected icon %s in:\n%s", state, icon, c)
		}
	}
}
