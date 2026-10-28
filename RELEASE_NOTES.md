# v0.3.31 — External-review hardening (9 findings: 6 fixes, 1 test-hygiene, 2 annotations)

A security- and alerting-correctness point release from the 2026-10-28
external review batch. Every finding was verified against the real code
first; six were valid and fixed with regression tests, one was test
hygiene, and two were adjudicated non-bugs (pinned with in-code
annotations so future review passes don't re-flag them). Gated with
`gofmt`, `go vet` (incl. `GOOS=windows`), and the full `-race` suite.

## Alerting

- **SMTP email alerts deliver again** (`a507e06`). `resolveDestinations`
  looked up `smtp_url` — a settings key nothing writes (SMTP's host lives
  in `smtp_host`) — so every enabled, configured SMTP provider resolved to
  **zero** destinations and `sendWebhookDeliver` returned "delivered" with
  nothing sent. Every status alert, re-alert, recovery, and storm summary
  silently skipped email since the multi-provider split. Webhook providers
  were unaffected; **email-only alerting was fully broken**. Now resolved
  via the provider's real `URLField`.
- **Storm summaries: partial recovery + per-sensor dedupe** (`6a6de8e`).
  A sensor going up → error → warning inside one storm window produced two
  conflicting lines (the partial recovery burned the non-recovery budget
  and was coalesced separately). Partial recoveries now count as
  recoveries, and `flushStorm` dedupes the queue by sensor id keeping the
  latest transition — one line per sensor.

## Access control

- **Non-admins are viewers + pulse operators** (`22c17a3`). Per-sensor
  mutations (create, edit, delete, clone, per-sensor history wipe) were
  open to any session — a known deferral from v0.3.21. A lower-trust
  account could create/repoint/delete sensors and erase per-sensor
  `events` rows. Every mutation route is `requireAdmin`; reads and "Pulse
  Now" stay open to every authenticated session. The UI hides the
  mutation controls (new-sensor, add, per-sensor pause/edit/clone/delete,
  clear-history) for non-admins while keeping Pulse Now visible.
  `requireAdmin` stands down with auth-off, so the "auth off = fully open"
  contract is unchanged.

## Alert card formatting

- **Markdown: names escaped, URLs verbatim** (`a8f32b8`). `mdEscape` was
  applied to the whole card line including the target, so a URL path with
  `_`/`~` (legal) got visible backslashes — corrupting the text and
  breaking the clickable auto-link in Discord/Google Chat. Now the sensor
  **name** (free text) is escaped in all five Markdown builders and the
  **target** stays verbatim so it renders and auto-links. `discordMentionSafe`
  also no longer drops the `@` (inserts the zero-width space *after* it).

## Login

- **Throttle clears a stale lockout on refund** (`557ec03`). `beginAttempt`
  sets a 5-minute lockout at `loginFailMax` failures, but `refundAttempt`
  only popped the counter and never cleared the lockout. A burst of
  no-KDF-cost rejections that are all refunded (browser double-submits,
  setup-path errors) drained the count to zero while leaving the IP locked
  out for the full 5 min. A refund that drops the count under the threshold
  now clears the lockout. Genuine attackers who pay the KDF cost keep
  theirs.

## Sensor clone

- **Clone clamps legacy params to current floors** (`284a45e`). Cloning
  copied the source's `interval_s`/`timeout_ms`/`loss_warn`/`down_after`/
  `spike_mult` verbatim, so a legacy out-of-range row (e.g. a 1s sensor)
  could be cloned into arbitrarily many new out-of-range sensors, bypassing
  the API floor the create/PATCH paths enforce. A clone is a new write and
  now clamps each param into its valid range (plus the `timeout ≤
  interval*1000` cross-field rule). Clones start paused, so the operator
  reviews the normalized values.

## Tests / annotations (no behavior change)

- **Test JSON decode errors checked** (`186b085`): 11 test assertions now
  route response-body decodes through the `jsonDecode` helper so a
  non-JSON body can't silently zero a struct and mask a regression.
- **Annotation closing review n7** (`9d067ab`): `alertGateConsumer`'s
  idle-timer lifecycle documented as correct (goroutine-local timer,
  complete drain-then-Reset, single post-fire exit) — a `defer idle.Stop()`
  would be a no-op.
- **Annotation closing review n9** (`4c3f2e7`): `/api/tags` and
  `/api/events` stay bare-pattern routes on purpose — the method-less `/`
  catch-all defeats `ServeMux`'s 405+Allow, so converting would regress the
  handler's JSON 405 into an HTML 404 for no benefit.

## Notes for operators

- If you alert via **email only**, you have been receiving no email
  alerts since the multi-provider split — this release restores them.
- The **non-admin role** is the groundwork for enterprise viewer accounts:
  create a second (non-admin) account to get a read + Pulse-Now-only
  session. The first/bootstrapped account is always admin.

## Assets

- `pulsemon-linux-amd64`, `pulsemon-linux-arm64` (+ sha256 sidecars)
- Windows asset added by the `windows-release.yml` workflow on tag push
