package main

import (
	"path/filepath"
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
