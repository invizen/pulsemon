# v0.3.18 — review hardening batch

Fixes the confirmed findings from the v0.3.17 code review (8 major, 10 minor;
see the review workspace for the full finding/verification records). All fixes
ship with regression tests; the full `-race` suite is the release gate.

## Security

- **Login throttle is un-rotatable behind trusted proxies.** `X-Forwarded-For`
  is now walked right-to-left and the first entry that is NOT itself a trusted
  proxy is used (previously the leftmost entry — client-supplied and
  rotatable per request). Throttle buckets are per /24 (IPv4) or /64 (IPv6):
  one IPv6 host no longer owns 2^64 separate 7-attempt budgets.
- **`PULSEMON_ALLOWED_HOSTS`** (new, optional): when set, creating the first
  account on a fresh install is refused with `421` unless the request's `Host`
  is allowlisted. This closes the DNS-rebinding route by which a malicious web
  page could claim the first account through a LAN browser. Unset = the
  documented LAN-trust default.
- **Container/unit hardening:** compose now runs with `cap_drop: [ALL]`,
  `no-new-privileges`, a read-only root filesystem (the DB and all app writes
  live on the `/data` volume) and a `tmpfs` on `/tmp`; the systemd unit gains
  `NoNewPrivileges=yes`.
- Webhook/SMTP DNS lookups are bounded at 5s (a hung resolver could stall the
  caller indefinitely).

## Correctness

- **The last dashboard account can no longer be deleted by a race.** The count
  guard now lives inside the DELETE statement (`... AND (SELECT COUNT(*) FROM
  users) > 1`); two concurrent removals can no longer both pass the count and
  silently switch auth off.
- **Name/tags edits take effect without a process restart.** The alert path
  reads the sensor name (alert text) and tags (routing) from the spawn-time
  config copy, so a name/tags PATCH now respawns the probe loop like the other
  config fields.
- **Alerts are no longer silently dropped on a transient DB read failure.**
  Alert delivery resolves provider URLs via a new `GetSettingErr` path and
  fails loudly (logged, retried) instead of looking "unset" and reporting
  delivered. URLs resolve before any provider fires — a failed read can't
  leave a partial alert behind.
- **HTTPS probes handshake fresh each tick**, so the displayed certificate
  expiry can't be up to 10 minutes stale from a reused keep-alive connection.
- **Rate-limited alert providers are respected:** 429 responses honor
  `Retry-After` (integer seconds or HTTP-date, capped at 60s) instead of being
  re-hit on the fixed 2s/10s schedule.
- The settings save (providers + routing fields) is one transaction — a
  mid-save failure can no longer leave a partial save behind a 500.
- `tlsValidatePair` accepts Ed25519 cert/key pairs (previously rejected).
- Passwords over bcrypt's 72-byte input limit are rejected with a 400 and a
  clear message (create previously returned 500).
- Deleted sensors release their cached 24h stats series from memory.
- Startup stats warm-up runs before probing starts, so it can no longer wipe
  probes recorded during the warm window.
- The ICMP reader's closed-socket check now uses `errors.Is` (the wrapped
  `OpError` never matched the bare sentinel).
- UNIQUE-constraint detection matches the exact constraint text at all four
  sites (a bare "UNIQUE" substring could misattribute other constraint
  failures to name collisions).

## Docs

- New "Behind a reverse proxy" README section: `PULSEMON_TRUSTED_PROXIES`
  (required behind a proxy — without it, all clients share the proxy's
  throttle budget) and `PULSEMON_ALLOWED_HOSTS`.

## Notes

- The update endpoint's auth state is unchanged (owner decision, 2026-10-15).
- Test: `TestFix_M10a_StatusStaysConsistentWhenUpdateFails` now drains alert
  goroutines before the DB closes, matching the production shutdown order
  (StopAlerts → DrainAlerts → db.Close).
