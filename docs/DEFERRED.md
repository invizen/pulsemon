# Deferred / accepted security trade-offs

Single source of truth for security trade-offs that were CONsciously
accepted (not forgotten). Each entry names the in-code location that
enforces or documents the same rule; if code and this file disagree, the
code wins and this file is stale.

## Accepted limitations

### Bootstrap (first-user) POST is open to the LAN
On a fresh install (no account has ever existed), `POST /api/auth/users`
is reachable by any LAN host — whoever wins the race owns the first
account, and a DNS-rebinding page can win it remotely. Everything else is
403 until an account exists (the bootstrap surface is locked down in
`Server.authGate`, api_middleware.go).
**Mitigation:** set `PULSEMON_ALLOWED_HOSTS` — the bootstrap POST is then
refused unless the request's Host header is allowlisted.
**Why accepted:** a setup token or loopback-only bootstrap is worse UX
than the risk on a trusted homelab LAN.

### "Auth off = fully open" (except self-update)
If the operator deletes all accounts, authentication is disabled and the
whole dashboard (sensor CRUD, settings, TLS upload, history wipes, user
management) is open to any LAN host.
**Mitigation:** `PULSEMON_ALLOWED_HOSTS` gates every /api/ request (reads
and writes — the route-level requireHost, not just the sessionless
mutating surface).
**Why accepted:** the operator deliberately removed every account; the
documented contract is an open dashboard. The one surface EXCLUDED from
this contract is `POST /api/update` — see "Lifted" below.

### Sensor targets with embedded credentials: admin-visible, viewer-redacted
`GET /api/sensors` returns `target` raw to ADMINS and auth-off installs
(the UI needs it for editing), but NON-ADMIN sessions get the
userinfo-stripped form (`viewerTarget`, api_sensors.go — reuses
`alertTarget`'s last-'@' cut, parse-failure safe): a viewer account can
never read the credentials an operator stored in an http target
(`https://user:pass@host/health`). Webhook URLs are masked for everyone
(`webhookMasked`).
**Mitigation:** don't store credentials in sensor targets; if you must,
keep authentication enabled (the redaction stands with it).

### Telegram alert cards do not neutralize @username mentions (2026-10-30)
The Discord card path neutralizes `@everyone`/`@here`
(`discordMentionSafe` + `allowed_mentions.parse = []`), but the Telegram
card and storm-summary HTML (telegram.go, `stormSummaryHTML` in alerts.go)
carry sensor names and targets verbatim (HTML-escaped only). In a
Telegram GROUP, a sensor name or target path containing `@username` that
matches a group member's Telegram username would notify that user.
**Mitigation:** point Telegram alerts at a private bot chat (the common
setup — mentions don't apply there), and don't name sensors after people's
Telegram usernames when alerting to a shared group.
**Why accepted:** `@everyone`/`@here` don't exist in Telegram (the Discord
mass-ping vector isn't a Telegram concept); the real vector requires a
shared group AND a name/username collision; and the zero-width-space
neutralization used for Discord would corrupt the target URL in the card
(copy-pasted links break) — the HTML/plain paths deliberately carry text
verbatim (alerts.go, `stormSummaryLine` comment, 2026-10-24 review). The
companion finding in the same review (chat_id re-read per delivery) was
FIXED, not deferred: `resolveDestinations` now resolves the chat_id
error-aware alongside the URL and `dest` carries it (pinned by
`TestTelegramDeliveryFailsClosedOnChatIDReadError`).

## Lifted

### Non-admin sensor mutations (lifted 2026-10-28)
The per-sensor mutation routes (`POST /api/sensors`, `PATCH`/`DELETE
/api/sensors/{id}`, `POST /api/sensors/{id}/clone`,
`DELETE /api/sensors/{id}/history`) were `requireAuth`-only during the
v0.3.21 admin-gate work (commit f3eddbf), so a regular (lower-trust)
account could create/edit/delete sensors — including wiping per-sensor
`events` rows one sensor at a time, the same audit log the
`requireAdmin`-gated `DELETE /api/events` exists to protect — and
repoint sensors at arbitrary internal targets. The 2026-10-28 review
lifted the deferral: every sensor mutation is now `requireAdmin`
(`Server.routes`, api.go); non-admin sessions keep all sensor reads
and Pulse Now (`POST /api/sensors/{id}/ping`) — the viewer +
manual-pulse role model. Pinned by `TestNonAdminCannotMutateSensors`.

### M4c — self-update while auth is off (lifted 2026-10-24)
`POST /api/update` used to run on auth-off installs (any LAN host could
trigger a download + binary swap + service restart; a compromised
upstream release would auto-install). The 2026-10-24 review (M1) lifted
the deferral: the endpoint is now 403 whenever authentication is
disabled — UNLESS the operator explicitly set `allow_unauth_update` in
Settings → Authentication (a documented, default-off opt-in for
auth-off installs that still want dashboard self-update; `handleUpdate`,
update_api.go; pinned by `TestUpdateRefusedWhenAuthDisabled`). The CLI
(`pulsemon update`) remains the operator path.

### Self-update authenticity (lifted 2026-10-29; manifest-bound 2026-11-05)
`verifyDownloadedAsset` (update.go) checked the SHA-256 only — integrity,
not authenticity. The binary and its SHA-256 come from the same GitHub
release, so a compromised account or pipeline publishes both and the check
passes, leading straight to code execution on every install that updates
(often with ping privileges). This was the documented, deliberate deferral
and the highest-impact residual risk in the project. The 2026-10-29 review
lifted it: a release binary is now installed only if its detached ed25519
`.sig` asset verifies against the embedded `release_pubkeys` (fail-closed),
with the SHA-256 kept as a redundant integrity net. Both the CLI and the
dashboard update path go through the shared check. See `docs/DECISIONS.md`
→ `release-signing` for the rationale, rotation, and key custody.
**2026-11-05 tightening:** the signature now covers a manifest (tag +
asset + sha256) instead of the raw bytes — a compromised account/pipeline
can no longer replay an old signed binary under a new tag — and an
anti-downgrade floor (`max_version_seen` in settings, `--allow-downgrade`
CLI opt-out) refuses release tags below the highest version the install has
ever run. Residual: a full pipeline compromise (key + tag) can still sign
an old binary under a fake-newer tag; key custody/rotation is the
mitigation.

### No HSTS header when serving TLS (2026-11-16)
`startListener` serves TLS without a `Strict-Transport-Security` header.
**Why accepted (deliberate, not an oversight):** `DELETE /api/settings/tls`
is a supported revert to plain HTTP; a long `max-age` would strand
browsers on an https:// origin that no longer listens (and the
in-app TLS install flow is LAN/self-signed, where HSTS pinning of a
throwaway cert buys little). **If this is ever added:** keep `max-age`
short (order of one hour) or make it operator opt-in, so the TLS→HTTP
revert stays survivable.

### GET /api/sensors carries the full sparkline payload every poll (2026-11-16)
Each sensor ships 60 hour-tier + 30 recent-tier floats per poll
(~0.5-1 MB per 5s tab at a few hundred sensors). Accepted for the
stated homelab/1080p target: loopback/LAN bandwidth, and the payload is
one indexed read amortized across the poll. **Scaling step if the fleet
grows:** ETag/If-None-Match on the JSON (the static-asset machinery
exists) or SSE deltas; not worth the cache-invalidation surface at
homelab scale.

### Slow sensors with status windows wider than the series tail read SQLite every tick (2026-11-16)
`deriveStatus` asks for `max(statusWindow, down_after)` probes;
`recentFromCache` can hold at most `seriesTailProbes` (60), so a sensor
with e.g. down_after=96 falls through to `recentFromDB` every tick.
**Why accepted:** the tail cap bounds resident memory; the cross-field
rule (`down_after x interval <= 24h`) bounds the worst case at ~96 rows
of an indexed `ORDER BY ts DESC LIMIT` per 15-minute tick. Comment at
`seriesTailProbes` (probe.go) pins the reasoning against future
"optimization".

### Re-alert hot path keeps an in-memory copy of alert_state (2026-11-16)
`maybeRealert` reads `ProbeWorker.alertMem` (write-through from
`setAlertState`); the DB row stays the durable copy. Accepted
simplification: the cache is invalidated on every path that writes
alert_state outside the worker (sensor delete, per-sensor and
all-history clear — `Remove` / `ResetStatsFor` / `ResetStatsAll`), and
a miss re-reads the row, so a restart converges. No write-back is ever
done from the cache.

### Private CA for HTTPS sensors: PULSEMON_CA_FILE, not SSL_CERT_FILE (2026-11-16)
The stdlib honors `SSL_CERT_FILE`/`SSL_CERT_DIR`, and it does work in a
deployed pulsemon process (env set at launch; even in the FROM scratch
image). Deliberate product choice: the supported knob is
`PULSEMON_CA_FILE` (initProbeCA, http.go) because Go caches the system
pool at the FIRST TLS verification for the process lifetime — the stdlib
env is un-settable after boot, untestable in-process, and invisible from
pulsemon's docs surface — and a fail-loud startup check on the bundle
(unreadable / zero certificates = refuse to start) is only possible with
a knob we read ourselves.

### IPv6: HTTP accepts v6 literals; ICMP/TCP refuse them (2026-11-16)
`validURL` accepts bracketed IPv6 hosts (`[::1]`) while `validTarget`
(ICMP/TCP) is IPv4-only. **Why accepted (deliberate asymmetry, no IPv6
ICMP roadmap item):** HTTP probes dial through net/http, which speaks
IPv6 end-to-end for free; refusing v6 there would cut a probe path that
works. The ICMP engine is IPv4-shaped by design (raw/datagram sockets,
4-byte-normalized demux keys) and the TCP probe reuses that resolution
path; v6 ICMP/TCP is a feature, not an oversight.
Comment at `validURL` (http.go) pins the reasoning.

### Masked sensor targets: declined (2026-11-16)
Proposed: mask `target` in list responses, raw only on
`GET /api/sensors/{id}` (the edit modal). **Declined:** the edit modal
populates from the LIST payload (no detail fetch — see web/app.js), so a
masked list target would round-trip into PATCH/PUT and persist the mask.
A safe split needs the modal refactored to fetch detail first, and on
auth-off installs the detail endpoint is equally open, so the split buys
little against the accepted mitigation (don't store credentials in
targets; keep auth on).

### Windows: core runtime is QA-box-tested; the reasoned-not-executed
note is scoped to the CLI self-update/rollback rename (2026-11-16)
`windows-release.yml` runs on a Windows CI runner (exe + installer +
signing per tag), and the service runtime (install, ICMP/HTTP/TCP probes,
dashboard, alerting) was QA-tested on a real Windows host. The
"reasoned, not executed" note (update.go, rollbackBinary) covers ONLY
the Win32 image-rename semantics of the CLI update/rollback path:
manual `pulsemon update rollback` while the service runs fails safe
(sharing violation, running binary untouched) — stop the service first.
No README best-effort banner: the runtime is tested; the one caveat is
documented where it bites (update.go) and in the installer flow, which
restarts the service on upgrade.
