package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// SMTP is the one alert provider that is not a single-URL HTTP POST. It dials
// a mail server with net/smtp (stdlib — no third-party dependency), so it has
// its own transport (sendSMTP), its own config shape (host/port/from/to/user/
// pass/tls, all under the smtp_ prefix), and a protocol-level test instead of
// the JSON-post test the webhook providers share.
//
// The settings "url" field is not used for SMTP (host lives in
// smtp_host); the UI's URL input is repurposed as the Host field. Delivery is
// a plain-text email so it renders identically in every mail client.

// smtpConfig is the persisted SMTP settings, read fresh on every send so an
// operator editing the dashboard takes effect on the next alert.
type smtpConfig struct {
	Host string
	Port int
	From string
	To   string
	User string
	Pass string
	TLS  string // "auto" (default), "starttls", "tls", "none"
}

func (pw *ProbeWorker) smtpConfig() smtpConfig {
	db := pw.db
	cfg := smtpConfig{
		Host: db.GetSetting("smtp_host"),
		From: db.GetSetting("smtp_from"),
		To:   db.GetSetting("smtp_to"),
		User: db.GetSetting("smtp_username"),
		Pass: db.GetSetting("smtp_password"),
		TLS:  db.GetSetting("smtp_tls_mode"),
	}
	if p, err := strconv.Atoi(db.GetSetting("smtp_port")); err == nil && p > 0 {
		cfg.Port = p
	} else {
		cfg.Port = 587 // conventional submission port
	}
	if cfg.TLS == "" {
		cfg.TLS = "auto"
	}
	return cfg
}

// smtpPort validates a stored smtp_port value: a 1–65535 integer. Empty is
// rejected (the UI always supplies one; a blank port can't dial).
func smtpPort(v string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("port must be a number, got %q", v)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d out of range (1-65535)", n)
	}
	return n, nil
}

// sendSMTP delivers a plain-text alert email. It is context-aware: a cancelled
// ctx (shutdown) aborts the dial at its next read, matching how the webhook
// deliveries are bounded. net/smtp's Client has no pluggable dialer, so we dial
// the TCP connection ourselves (net.Dialer + DialContext for ctx) and hand it to
// smtp.NewClient.
//
// TLS mode:
//   - "auto"     (default) — implicit TLS on port 465 (handshake on the raw
//     conn before SMTP), opportunistic STARTTLS elsewhere (a 25-port relay
//     without STARTTLS stays plaintext, which is normal for a LAN relay).
//   - "starttls" — require STARTTLS.
//   - "tls"      — implicit TLS on any port (a relay on a non-465 port).
//   - "none"     — plaintext, no TLS at all.
func (pw *ProbeWorker) sendSMTP(ctx context.Context, subject, body string) error {
	cfg := pw.smtpConfig()
	if cfg.Host == "" {
		return fmt.Errorf("smtp: no host configured")
	}
	if cfg.To == "" {
		return fmt.Errorf("smtp: no recipient configured")
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	d := net.Dialer{Timeout: 10 * time.Second}
	if ctx == nil {
		ctx = context.Background()
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp dial %s: %w", addr, err)
	}

	// Implicit TLS ("tls" mode, or "auto" on 465): handshake on the raw conn
	// BEFORE the SMTP conversation starts.
	implicitTLS := cfg.TLS == "tls" || (cfg.TLS == "auto" && cfg.Port == 465)
	if implicitTLS {
		tc := tls.Client(conn, &tls.Config{ServerName: cfg.Host})
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return fmt.Errorf("smtp tls handshake: %w", err)
		}
		conn = tc
	}

	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp hello %s: %w", cfg.Host, err)
	}
	defer c.Close()

	// STARTTLS upgrade for the non-implicit modes.
	switch cfg.TLS {
	case "starttls":
		if err := c.StartTLS(&tls.Config{ServerName: cfg.Host}); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	case "auto":
		// Opportunistic: only if the server advertises STARTTLS in EHLO.
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{ServerName: cfg.Host}); err != nil {
				return fmt.Errorf("smtp starttls: %w", err)
			}
		}
	case "none":
		// no TLS
	}

	if cfg.User != "" {
		auth := smtp.PlainAuth("", cfg.User, cfg.Pass, cfg.Host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(cfg.From); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	if err := c.Rcpt(cfg.To); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	msg := "From: " + cfg.From + "\r\n" +
		"To: " + cfg.To + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: 8bit\r\n" +
		"\r\n" + body + "\r\n"
	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp end data: %w", err)
	}
	return c.Quit()
}

// smtpSubject picks the email subject from the transition, mirroring the
// webhook cards' recoveryTitle.
func smtpSubject(oldState, state string) string {
	switch {
	case state == "up":
		return "✅ pulsemon: recovered"
	case state == "warning" && oldState == "error":
		return "⚠️ pulsemon: partial recovery"
	default:
		return "pulsemon: " + state
	}
}

// SMTP alert body. Plain text (no markup) so it renders identically in every
// mail client — the same information as the Discord/Google Chat/Telegram cards.
func smtpBody(oldState, state, name, target string, rttMs float64) string {
	icon := statusIcon(state)
	if icon == "" {
		icon = "✅"
	}
	title := recoveryTitle(oldState, state)
	body := fmt.Sprintf("%s pulsemon: %s\nSensor: %s\nTarget: %s\nState: %s", icon, title, name, target, state)
	if rttMs > 0 {
		body += fmt.Sprintf("\nPing: %d ms", int(rttMs+0.5))
	}
	return body
}

func smtpBodyRe(state, name, target string, rttMs float64) string {
	icon := statusIcon(state)
	if icon == "" {
		icon = "✅"
	}
	body := fmt.Sprintf("%s pulsemon: still %s (re-alert)\nSensor: %s\nTarget: %s\nState: %s — no change, re-notifying", icon, state, name, target, state)
	if rttMs > 0 {
		body += fmt.Sprintf("\nPing: %d ms", int(rttMs+0.5))
	}
	return body
}

// smtpEnabled: explicit "1" flag. No legacy default (fresh install = off).
func smtpEnabled(db *DB) bool { return db.GetSetting("smtp_enabled") == "1" }

// smtpHasURL: SMTP is "configured" when it has a host AND a recipient — the
// mail-server equivalent of Telegram needing a URL and a chat_id. A host alone
// can't deliver (no one to send to), a recipient alone has nowhere to go.
func smtpHasURL(db *DB) bool {
	return db.GetSetting("smtp_host") != "" && db.GetSetting("smtp_to") != ""
}
