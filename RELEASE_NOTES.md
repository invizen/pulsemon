# pulsemon v0.2.5

## New: Telegram notification provider
- Full Telegram bot support: paste the BotFather endpoint URL + Chat ID in the Alerts modal
- Token stays masked in the UI; chat_id stored as a gated `extra` field
- Unknown extra keys rejected with 400 (no silent data leakage)

## New: Dedicated Alerts modal
- Alert Destinations, Routing, and Re-Alert Interval moved out of Settings into a dedicated 🔔 Alerts modal (bell icon in header)
- Settings modal now focuses on Maintenance, Version, TLS, and Authentication
- Self-saving sections (no aggregate "Save Settings" button)

## UI: Card layout tightening
- Reduced card padding (`p-2.5 pb-1`) and section gaps for a more compact feel
- Tags row: now full-width (aligns with metrics box + sparkline), top-aligned, 2-row height reserved
- Sparkline: "paused" / "collecting…" text centered in the box
- Footer: `mt-auto` + `items-end` — action icons hug the bottom edge (5px gap)

## Security: Partial TLS config is now fatal
- `certPaths()` returns a fatal error if only one of `PULSEMON_CERT` / `PULSEMON_KEY` is set
- Previously: warning + silent fallback to plain HTTP
- Now: process exits with a clear message (no silent plaintext degradation)
- Stubbed `certFatal` var for testability; `certpaths_test.go` covers all 4 cases
