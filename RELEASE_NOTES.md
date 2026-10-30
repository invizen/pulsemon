# v0.4.2 — 2026-10-30 external-review hardening batch

A patch release closing out the 2026-10-30 external-review batch: 8
findings adjudicated — 6 fixed, 2 rejected and pinned (documented
decisions, no behavior change). No new features. Gated with `gofmt`,
`go vet` (incl. `GOOS=windows`), `node --check`, and the full `-race`
suite on every commit.

## Security & correctness fixes

- **Settings read is admin-only** (`api.go`, `web/`). `GET /api/settings`
  passed the bare session gate, so a lower-trust viewer account could read
  the full settings payload (SMTP from/to/username, `telegram_chat_id`,
  webhook scheme+host, TLS cert metadata, alert scope/filter) while `PUT`
  was already admin-gated. The GET is now `requireAdmin`; the settings
  modal entry points (gear button, update pill) are hidden from
  non-admins so they no longer hit a 403 on open. `requireAdmin` stands
  down on auth-off / zero-account installs, so those deployments are
  byte-for-byte unchanged.
- **Telegram `chat_id` resolved up front, fail-closed** (`alerts.go`).
  The chat_id was re-read live inside the delivery goroutines via the
  swallow-to-`""` setting getter while every provider URL was already
  resolved error-aware — a transient DB lock at delivery time posted an
  empty chat_id (Telegram 400), and the storm-summary path (no retry)
  dropped the coalesced alert. `resolveDestinations` now resolves the
  chat_id once and fails the whole send on read failure, matching the URL
  handling.
- **`IsAdmin` is TTL-cached, fail-closed** (`auth.go`). `IsAdmin` was the
  only per-request auth check without a cache — every admin-gated request
  ran an uncached SQLite point query. Both answers now cache for the
  standard 2s user-TTL; DB errors fail closed and are never cached;
  in-app mutations (create/remove/last-admin promotion) invalidate
  immediately.
- **Request context threaded into the last four ctx-less handler DB
  calls** (`db.go`, `api.go`). `ActiveSensorIDs`,
  `EnterMaintenanceWithFreshSnapshot`, `SetMaintenanceMode`, and
  `DeleteTag` ignored `r.Context()`, so a client that disconnected
  mid-request left those statements running. They now carry the request
  context (pool-level fast-fail: a dead ctx means the statement never
  runs), completing the context-propagation contract pinned by
  `TestFix_HandlerDBCallsHonorRequestContext`.
- **Markdown link-bracket escaping** (`alerts.go`). `mdEscape` escaped the
  emphasis characters that `validSensorName` permits but not `[` `]` — and
  the validator permits those too. A sensor named
  `[click here](https://evil.example)` was legal input and rendered as a
  masked hyperlink in the Discord/Google Chat cards and storm summary.
  Brackets are now escaped (all five Markdown builders); parens stay
  unescaped (no link syntax can form without the brackets) and targets
  remain verbatim.

## Refactor

- **Single webhook transport seam** (`alerts.go`). `TestWebhook` (the
  settings test button) duplicated `postJSON`'s HTTP transport
  construction (request build, headers, capped drain, URL redaction, 3xx
  classification), risking drift. Both now share
  `doWebhookPost(ctx, url, body)`; behavior-preserving — same hardened
  client, same headers, same drain, same messages, same contexts.

## Pinned decisions (no behavior change)

- **`GET /api/update-check` stays open to any session** (re-adjudicated).
  Read-only, non-secret (versions already render in the header pill),
  fixed upstream URL, 60s global `?refresh=1` throttle. The admin gate
  belongs on `POST /api/update` (code download + execute + restart), which
  is already admin-only. Pinned in-code, in `docs/DECISIONS.md`, and with
  a hermetic non-admin 200 test.
- **`shouldAlert`'s per-decision filter read is deliberate** (rejected
  cache proposal). The default path is O(1); the loop only runs for
  opt-in routing on a 500-capped list, on a cold path; and the
  read-current-setting-per-decision pattern (shared with the
  `maintenance_mode` gate) means a routing change takes effect on the next
  transition with zero staleness. Pinned in `docs/DECISIONS.md` and
  in-code.

## Notes for operators

- No config changes required. Self-update signing (ed25519) is unchanged
  from v0.4.0; existing clients verify v0.4.2 as usual.
- Auth-off / zero-account installs (the current fleet) are behaviorally
  identical to v0.4.1 — the new admin gate stands down without accounts.

## Assets

- `pulsemon-linux-amd64`, `pulsemon-linux-arm64` (+ sha256 sidecars + `.sig`)
- Windows assets added by the `windows-release.yml` workflow on tag push
  (`pulsemon-windows-amd64.exe`, `pulsemon-setup-0.4.2.exe` + sidecars + `.sig`)
