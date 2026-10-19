package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"mime"
	"net"
	"net/mail"
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

// smtpAddr validates a stored smtp_from / smtp_to value: it must be a single
// RFC 5322 address (bare a@b, or "Display" <a@b>) and must contain no CR/LF —
// sendSMTP builds the raw message headers by string concatenation, so a
// control character in a stored address would inject a forged header line.
// It returns the BARE address (addr.Address), which is what MAIL FROM /
// RCPT TO need: net/smtp wraps its argument in <...>, so a display name
// (PulseMon <a@b>) or a comma-separated list would produce
// MAIL FROM:<PulseMon <a@b>> — a 501 syntax error that silently kills every
// alert.
func smtpAddr(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", fmt.Errorf("required")
	}
	if strings.ContainsAny(v, "\r\n") {
		return "", fmt.Errorf("must not contain newline characters")
	}
	a, err := mail.ParseAddress(v)
	if err != nil {
		return "", fmt.Errorf("invalid address %q: %s", v, err.Error())
	}
	if a.Address == "" {
		return "", fmt.Errorf("invalid address %q: missing @address", v)
	}
	return a.Address, nil
}

// smtpDial establishes sendSMTP's TCP connection. It defaults to dialChecked
// (webhook.go): the rebind-safe, blocklist-enforcing dial the webhook
// providers use. Tests override it to reach an in-process server on loopback.
var smtpDial = dialChecked

// smtpConnDeadline caps the WHOLE SMTP conversation (greeting → QUIT) on one
// absolute conn deadline — the SMTP equivalent of the webhook path's
// http.Client 10s total-request timeout. A LAN relay completes the exchange
// in well under a second; 15s is the tarpit bound. A var so tests can
// shorten it.
var smtpConnDeadline = 15 * time.Second

// sendSMTP delivers a plain-text alert email. Every phase is bounded,
// matching the webhook deliveries:
//
//   - dial — 10s ctx timeout (dialChecked's shared dialer has none of its
//     own) through smtpDial (default: dialChecked, webhook.go) — the same
//     rebind-safe path the webhook providers use: resolve the host, enforce
//     the reserved-range blocklist on every answer, and pin the dial to the
//     checked IP. A save-time-allowed name that rebinds to loopback or
//     cloud-metadata (169.254.169.254) at dial time is refused, and a stored
//     reserved literal is refused too.
//   - conversation — an absolute deadline on the conn (smtpConnDeadline)
//     covers every read/write from the 220 greeting through QUIT, and
//     context.AfterFunc closes the conn when ctx is cancelled. Both are
//     needed: net/smtp's Client methods take no ctx and have no timeout of
//     their own, so a relay that accepts TCP and then hangs (tarpit, missing
//     220 greeting) would otherwise block this goroutine forever — leaking
//     the alert delivery and stalling the settings Test button. Closing the
//     conn is the ONLY way to abort a blocked net/smtp read, which is what
//     lets StopAlerts (shutdown) and an abandoned test request cancel an
//     in-flight delivery.
//
// net/smtp's Client has no pluggable dialer, so we dial the TCP connection
// ourselves and hand it to smtp.NewClient.
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
	if cfg.From == "" {
		return fmt.Errorf("smtp: no sender configured")
	}
	if cfg.To == "" {
		return fmt.Errorf("smtp: no recipient configured")
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	if ctx == nil {
		ctx = context.Background()
	}
	// dialChecked's shared dialer has no per-dial timeout of its own; keep
	// the 10-second dial bound the plain net.Dialer used to provide.
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := smtpDial(dctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp dial %s: %w", addr, err)
	}
	// Conversation bounds (see the sendSMTP doc): an absolute deadline caps
	// every read/write through QUIT, and ctx cancellation closes the conn —
	// the only way to abort a blocked net/smtp read.
	if err := conn.SetDeadline(time.Now().Add(smtpConnDeadline)); err != nil {
		conn.Close()
		return fmt.Errorf("smtp deadline %s: %w", addr, err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

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
	tlsOn := implicitTLS
	switch cfg.TLS {
	case "starttls":
		if err := c.StartTLS(&tls.Config{ServerName: cfg.Host}); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
		tlsOn = true
	case "auto":
		// Opportunistic: only if the server advertises STARTTLS in EHLO.
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{ServerName: cfg.Host}); err != nil {
				return fmt.Errorf("smtp starttls: %w", err)
			}
			tlsOn = true
		}
	case "none":
		// no TLS
	}

	// Q1 (2026-10-19 review F26): what TLS state did we ACTUALLY end up in?
	// A relay without STARTTLS is legitimate in "auto" mode (a 25-port LAN
	// relay) — but only credential-free: with NO username configured the
	// plaintext send is allowed and gets a one-line warning per send (pre-fix
	// it was completely silent, so an operator who believed auth was in
	// effect had no idea the mail — and the session it rode in — was
	// cleartext). WITH credentials configured, a plaintext wire is a
	// credential leak, not a relay preference: fail clearly (the operator
	// must set tls_mode=starttls or remove the credentials). "none" is the
	// explicit plaintext choice; new saves of none+credentials are refused at
	// save time (F27), so this guard only fires for legacy stored configs.
	if !tlsOn && cfg.User != "" {
		return fmt.Errorf("smtp: credentials are configured but the connection to %s is plaintext (no STARTTLS); set tls_mode=starttls or remove the username/password", cfg.Host)
	}
	if !tlsOn && cfg.TLS == "auto" && cfg.User == "" {
		log.Printf("smtp: %s does not offer STARTTLS; sending in plaintext (no credentials configured)", cfg.Host)
	}

	if cfg.User != "" {
		auth := smtp.PlainAuth("", cfg.User, cfg.Pass, cfg.Host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	// Normalize the stored addresses to bare form. Save-time validation
	// (smtpAddr) does this for new values; this also rescues LEGACY values
	// stored before the validator existed (e.g. a display name), so an
	// upgrade doesn't break a working config. An unparseable value is
	// passed through raw — it will 501 at the server, which is exactly the
	// pre-validator behavior.
	from := cfg.From
	if a, err := mail.ParseAddress(cfg.From); err == nil {
		from = a.Address
	}
	to := cfg.To
	if a, err := mail.ParseAddress(cfg.To); err == nil {
		to = a.Address
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	fromAddr := from
	if a, err := mail.ParseAddress(from); err == nil {
		fromAddr = a.Address
	}
	domain := ""
	if parts := strings.Split(fromAddr, "@"); len(parts) == 2 {
		domain = parts[1]
	}

	msgIDBytes := make([]byte, 16)
	if _, err := rand.Read(msgIDBytes); err != nil {
		return fmt.Errorf("smtp: failed to generate random msg-id: %w", err)
	}
	msgID := hex.EncodeToString(msgIDBytes)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\nMIME-Version: 1.0\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n%s\r\n",
		from, to, time.Now().Format(time.RFC1123Z), msgID, domain, mime.QEncoding.Encode("utf-8", subject), body)
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
	target = alertTarget(target)
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
	target = alertTarget(target)
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

// smtpHasURL: SMTP is "configured" when it has a host, a SENDER, and a
// recipient — the mail-server equivalent of Telegram needing a URL and a
// chat_id. A host alone can't deliver (no one to send to), a recipient
// alone has nowhere to go, and a missing sender produces MAIL FROM:<>
// (a null reverse path that submission servers reject with 501) — so all
// three are required for the provider to count as ready.
func smtpHasURL(db *DB) bool {
	return db.GetSetting("smtp_host") != "" && db.GetSetting("smtp_from") != "" && db.GetSetting("smtp_to") != ""
}
