package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFix_C1_NoProviderSecretSurvivesMasking(t *testing.T) {
	// 1. Pure function test
	t.Run("PureFunction", func(t *testing.T) {
		cases := []struct {
			input    string
			expected string
		}{
			{"https://api.telegram.org/bot123456789:AAEhBP0av28yC9tG_exampleTOKEN/sendMessage", "https://api.telegram.org/***"},
			{"https://discord.com/api/webhooks/111111/SECRETTOKEN", "https://discord.com/***"},
			{"https://chat.googleapis.com/v1/spaces/AAA/messages?key=K&token=T", "https://chat.googleapis.com/***"},
			{"invalid-url", "***"},
			{"", ""},
		}

		for _, c := range cases {
			got := webhookMasked(c.input)
			if got != c.expected {
				t.Errorf("webhookMasked(%q) = %q, want %q", c.input, got, c.expected)
			}
		}
	})

	// 2. API integration test
	t.Run("APIIntegration", func(t *testing.T) {
		d := newTestDB(t)
		srv := NewServer(d, NewProbeWorker(d))
		httpSrv := httptest.NewServer(srv.authGate())
		defer httpSrv.Close()

		d.SetSetting("auth_bootstrapped", "1")

		// Set secrets
		telegramURL := "https://api.telegram.org/bot123456789:AAEhBP0av28yC9tG_exampleTOKEN/sendMessage"
		discordURL := "https://discord.com/api/webhooks/111111/SECRETTOKEN"
		googleChatURL := "https://chat.googleapis.com/v1/spaces/AAA/messages?key=K&token=T"

		_ = d.SetSetting("telegram_url", telegramURL)
		_ = d.SetSetting("discord_url", discordURL)
		_ = d.SetSetting("google_chat_url", googleChatURL)

		resp, err := http.Get(httpSrv.URL + "/api/settings")
		if err != nil {
			t.Fatalf("failed GET /api/settings: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("got status %d, want 200", resp.StatusCode)
		}

		var settings struct {
			Providers []struct {
				Kind string `json:"kind"`
				URL  string `json:"url"`
			} `json:"providers"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&settings); err != nil {
			t.Fatalf("failed decode: %v", err)
		}

		for _, p := range settings.Providers {
			// Check for known secrets in the masked URL
			if p.Kind == "telegram" {
				if strings.Contains(p.URL, "AAEhBP0av28yC9tG_exampleTOKEN") {
					t.Errorf("telegram URL still contains secret: %q", p.URL)
				}
			}
			if p.Kind == "discord" {
				if strings.Contains(p.URL, "SECRETTOKEN") {
					t.Errorf("discord URL still contains secret: %q", p.URL)
				}
			}
			if p.Kind == "google_chat" {
				if strings.Contains(p.URL, "token=T") || strings.Contains(p.URL, "key=K") {
					t.Errorf("google_chat URL still contains secret: %q", p.URL)
				}
			}

			// Verify masking shape (Scheme://Host/*** or ***)
			if p.URL != "" && !strings.HasSuffix(p.URL, "/***") && p.URL != "***" {
				t.Errorf("unexpected URL format for %s: %q", p.Kind, p.URL)
			}
		}
	})
}
