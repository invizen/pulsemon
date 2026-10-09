package main

import "testing"

// TestListenAddr pins the listen-address resolution: the env override must win
// when set (any "host:port" value is passed through verbatim), and the default
// must be ":9299" (8080 was retired in v0.1.20 — it's heavily claimed by
// homelab dashboards and proxies).
func TestListenAddr(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		t.Setenv("PULSEMON_ADDR", "")
		if got := listenAddr(); got != ":9299" {
			t.Fatalf("default addr = %q, want :9299", got)
		}
	})
	t.Run("port-only override", func(t *testing.T) {
		t.Setenv("PULSEMON_ADDR", ":7777")
		if got := listenAddr(); got != ":7777" {
			t.Fatalf("addr = %q, want :7777", got)
		}
	})
	t.Run("host+port override", func(t *testing.T) {
		t.Setenv("PULSEMON_ADDR", "127.0.0.1:9999")
		if got := listenAddr(); got != "127.0.0.1:9999" {
			t.Fatalf("addr = %q, want 127.0.0.1:9999", got)
		}
	})
}
