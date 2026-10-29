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
`Server.authGate`, api.go).
**Mitigation:** set `PULSEMON_ALLOWED_HOSTS` — the bootstrap POST is then
refused unless the request's Host header is allowlisted.
**Why accepted:** a setup token or loopback-only bootstrap is worse UX
than the risk on a trusted homelab LAN.

### "Auth off = fully open" (except self-update)
If the operator deletes all accounts, authentication is disabled and the
whole dashboard (sensor CRUD, settings, TLS upload, history wipes, user
management) is open to any LAN host.
**Mitigation:** `PULSEMON_ALLOWED_HOSTS` gates every mutating request.
**Why accepted:** the operator deliberately removed every account; the
documented contract is an open dashboard. The one surface EXCLUDED from
this contract is `POST /api/update` — see "Lifted" below.

### Sensor targets with embedded credentials are returned verbatim
`GET /api/sensors` returns `target` unmodified (the UI needs it for
editing), so a target like `https://user:pass@host/health` is readable by
anyone who can read the sensor list. Webhook URLs, by contrast, are
masked (`webhookMasked`).
**Mitigation:** don't store credentials in sensor targets; if you must,
keep authentication enabled.

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
disabled (`handleUpdate`, update_api.go; pinned by
`TestUpdateRefusedWhenAuthDisabled`). The CLI (`pulsemon update`)
remains the operator path.

### Self-update authenticity (lifted 2026-10-29)
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
