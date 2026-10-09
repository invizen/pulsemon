# v0.2.6

## New: Email (SMTP) alert provider

pulsemon can now send alerts to an email address. The fifth destination in the
🔔 Alerts panel alongside Google Chat, Discord, and Telegram.

- **Transport**: pure-Go `net/smtp` — no new dependencies, no agents.
- **TLS modes**: `auto` (implicit TLS on 465, opportunistic STARTTLS elsewhere),
  `starttls`, `tls` (implicit on any port), `none` (trusted LAN relay).
- **Config**: host, port, from, to, user, password, TLS mode — all editable in
  the dashboard.
- **Password handling**: stored in the local database, masked in the API and UI
  (never returned in the clear). Re-saving the mask is a no-op, so the real
  credential is never clobbered.
- **Works with**: Gmail (port 587 + App Password), Fastmail, Proton, and any
  standard SMTP submission relay.

## New: alerts setup guide

The Alerts panel now links to a per-destination setup guide at
[pulsemon.net/alerts](https://pulsemon.net/alerts) — step-by-step for Discord
webhooks, Google Chat connectors, Telegram bots (token + chat ID), and Gmail
App Passwords.

## Alert icons now match the dashboard

Alert cards (Discord, Google Chat, Telegram, email) use the same status emoji
as the dashboard: ✅ up/recovered, ⚠️ warning, ❌ error, ⏸️ paused. The six
per-provider card builders were consolidated around a single `statusIcon()`
helper.

## Tests

- 9 new SMTP tests, including an end-to-end delivery test against an
  in-process SMTP server (real TCP socket, no transport mocking).
- Settings round-trip tests for the SMTP extra fields (host, port, from, to,
  user, TLS mode), port/TLS-mode validation, and unknown-key rejection.
- Full suite green under `go test -race`.
