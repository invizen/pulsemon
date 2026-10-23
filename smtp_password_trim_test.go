package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// F10 (2026-10-23 external review): the settings-save loop trimmed EVERY
// extra field, including the SMTP password, so a password with a leading
// or trailing space was silently changed before storage. Credentials are
// now stored raw; every other extra field keeps the trim.

func f10putSettings(t *testing.T, mux *http.ServeMux, body string) int {
	t.Helper()
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(body)))
	return rr.Code
}

// TestSMTPCredentialsStoredUntrimmed pins the core fix: leading/trailing
// whitespace in username and password is part of the credential and must
// reach SQLite byte-for-byte.
func TestSMTPCredentialsStoredUntrimmed(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	mux := srv.Mux()

	body := `{"providers":[{"kind":"smtp","url":"10.0.0.25","extra":{"port":"587","from":"pulsemon@home.lan","to":"ops@home.lan","username":"ops ","password":" secret  ","tls_mode":"starttls"}}]}`
	if code := f10putSettings(t, mux, body); code != http.StatusOK {
		t.Fatalf("PUT with whitespace credentials => %d, want 200", code)
	}
	if got := db.GetSetting("smtp_username"); got != "ops " {
		t.Fatalf("smtp_username = %q, want %q (untrimmed)", got, "ops ")
	}
	if got := db.GetSetting("smtp_password"); got != " secret  " {
		t.Fatalf("smtp_password = %q, want %q (untrimmed)", got, " secret  ")
	}
}

// TestSMTPOtherExtraFieldsStillTrimmed pins the non-credential half: the
// trim stays for every other extra field, so a padded port or address is
// stored clean as before.
func TestSMTPOtherExtraFieldsStillTrimmed(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	mux := srv.Mux()

	body := `{"providers":[{"kind":"smtp","url":" 10.0.0.25 ","extra":{"port":" 587 ","from":" ops@home.lan ","password":"x"}}]}`
	if code := f10putSettings(t, mux, body); code != http.StatusOK {
		t.Fatalf("PUT with padded non-credential fields => %d, want 200", code)
	}
	if got := db.GetSetting("smtp_port"); got != "587" {
		t.Fatalf("smtp_port = %q, want %q (trimmed)", got, "587")
	}
	if got := db.GetSetting("smtp_from"); got != "ops@home.lan" {
		t.Fatalf("smtp_from = %q, want %q (trimmed)", got, "ops@home.lan")
	}
	if got := db.GetSetting("smtp_host"); got != "10.0.0.25" {
		t.Fatalf("smtp_host = %q, want %q (trimmed)", got, "10.0.0.25")
	}
}

// TestSMTPMaskComparedRaw pins the mask "unchanged" contract on the RAW
// value: the exact mask leaves the stored credential untouched, while a
// mask with surrounding spaces is a literal password, not the token.
func TestSMTPMaskComparedRaw(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	mux := srv.Mux()

	seed := map[string]string{
		"port": "587", "from": "pulsemon@home.lan", "to": "ops@home.lan",
		"username": "pulsemon", "password": "secret", "tls_mode": "starttls",
	}
	if err := srv.applyProviderUpdate("smtp", strPtr("10.0.0.25"), boolPtr(true), seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Exact mask over a stored password: the credential survives.
	if code := f10putSettings(t, mux, `{"providers":[{"kind":"smtp","extra":{"password":"••••••••"}}]}`); code != http.StatusOK {
		t.Fatalf("PUT with exact mask => %d, want 200", code)
	}
	if got := db.GetSetting("smtp_password"); got != "secret" {
		t.Fatalf("smtp_password = %q after mask PUT, want %q (unchanged)", got, "secret")
	}

	// Mask with surrounding spaces: NOT the token — stored as a literal.
	if code := f10putSettings(t, mux, `{"providers":[{"kind":"smtp","extra":{"password":" •••••••• "}}]}`); code != http.StatusOK {
		t.Fatalf("PUT with padded mask => %d, want 200", code)
	}
	if got := db.GetSetting("smtp_password"); got != " •••••••• " {
		t.Fatalf("smtp_password = %q, want %q (padded mask is a literal)", got, " •••••••• ")
	}
}

// TestSMTPTLSModeNoneBlocksWhitespaceOnlyCredential pins the F27 guard on
// raw presence: a spaces-only password (or username) is still a
// credential and must be rejected under tls_mode=none. Pre-fix it trimmed
// to "" and slipped through, storing a plaintext-mode config.
func TestSMTPTLSModeNoneBlocksWhitespaceOnlyCredential(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	mux := srv.Mux()

	if code := f10putSettings(t, mux, `{"providers":[{"kind":"smtp","extra":{"tls_mode":"none","password":"  "}}]}`); code != http.StatusBadRequest {
		t.Fatalf("none + spaces-only password => %d, want 400", code)
	}
	if code := f10putSettings(t, mux, `{"providers":[{"kind":"smtp","extra":{"tls_mode":"none","username":" "}}]}`); code != http.StatusBadRequest {
		t.Fatalf("none + spaces-only username => %d, want 400", code)
	}

	// Deliberate clearing still works: empty strings are not credentials.
	if code := f10putSettings(t, mux, `{"providers":[{"kind":"smtp","extra":{"tls_mode":"none","username":"","password":""}}]}`); code != http.StatusOK {
		t.Fatalf("none + cleared credentials => %d, want 200", code)
	}
	if got := db.GetSetting("smtp_tls_mode"); got != "none" {
		t.Fatalf("smtp_tls_mode = %q, want none", got)
	}
}

// TestSMTPTLSModeNoneStoredWhitespaceCredential pins the EFFECTIVE-state
// half: a spaces-only credential already in the DB blocks a partial PUT
// that flips tls_mode to none (the same bypass class as the F27 review
// fix, now with raw semantics).
func TestSMTPTLSModeNoneStoredWhitespaceCredential(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	mux := srv.Mux()

	seed := map[string]string{
		"port": "587", "from": "pulsemon@home.lan", "to": "ops@home.lan",
		"username": "pulsemon", "password": " pass ", "tls_mode": "starttls",
	}
	if err := srv.applyProviderUpdate("smtp", strPtr("10.0.0.25"), boolPtr(true), seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if code := f10putSettings(t, mux, `{"providers":[{"kind":"smtp","extra":{"tls_mode":"none"}}]}`); code != http.StatusBadRequest {
		t.Fatalf("partial none over stored whitespace credential => %d, want 400", code)
	}
	if got := db.GetSetting("smtp_tls_mode"); got != "starttls" {
		t.Fatalf("rejected save mutated smtp_tls_mode to %q", got)
	}
}
