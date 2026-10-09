package main

import "testing"

// The Telegram provider persists its non-URL field (chat_id) through the
// shared applyProviderUpdate path, and rejects unknown extra keys so a
// client can't write arbitrary settings keys.
func TestApplyProviderUpdateTelegramChatID(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))

	cid := "123456789"
	if err := srv.applyProviderUpdate("telegram", strPtr("https://api.telegram.org/botT/sendMessage"), boolPtr(true), map[string]string{"chat_id": cid}); err != nil {
		t.Fatalf("applyProviderUpdate telegram: %v", err)
	}
	if got := db.GetSetting("telegram_chat_id"); got != cid {
		t.Fatalf("telegram_chat_id = %q, want %q", got, cid)
	}
	if got := db.GetSetting("telegram_url"); got == "" {
		t.Fatal("telegram_url not saved")
	}
	if got := db.GetSetting("telegram_enabled"); got != "1" {
		t.Fatalf("telegram_enabled = %q, want 1", got)
	}
}

func TestApplyProviderUpdateRejectsUnknownExtra(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))

	// "chat_id" is valid for telegram; "evil" is not.
	if err := srv.applyProviderUpdate("telegram", strPtr("https://api.telegram.org/botT/sendMessage"), nil, map[string]string{"evil": "x"}); err == nil {
		t.Fatal("expected unknown extra key to be rejected, got nil")
	}
	if got := db.GetSetting("telegram_evil"); got != "" {
		t.Fatalf("telegram_evil should not be written, got %q", got)
	}
}

func TestTelegramHasURL(t *testing.T) {
	db := newTestDB(t)
	// No url, no chat_id → false.
	if telegramHasURL(db) {
		t.Fatal("expected false with no config")
	}
	// URL only (no chat_id) → false: a URL alone can't deliver.
	db.SetSetting("telegram_url", "https://api.telegram.org/botT/sendMessage")
	if telegramHasURL(db) {
		t.Fatal("expected false with URL but no chat_id")
	}
	// Both → true.
	db.SetSetting("telegram_chat_id", "123")
	if !telegramHasURL(db) {
		t.Fatal("expected true with URL and chat_id")
	}
}

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }
