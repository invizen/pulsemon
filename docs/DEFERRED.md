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

### M4c — self-update while auth is off (lifted 2026-10-24)
`POST /api/update` used to run on auth-off installs (any LAN host could
trigger a download + binary swap + service restart; a compromised
upstream release would auto-install). The 2026-10-24 review (M1) lifted
the deferral: the endpoint is now 403 whenever authentication is
disabled (`handleUpdate`, update_api.go; pinned by
`TestUpdateRefusedWhenAuthDisabled`). The CLI (`pulsemon update`)
remains the operator path.
