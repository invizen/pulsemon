# v0.3.17 — security, reliability and scalability hardening

A code-review release. It fixes three critical, eleven major and a set of minor
issues found in an end-to-end review, plus the toolchain/CVE bump. Probing,
status derivation and the dashboard layout are otherwise unchanged.

## Security

- **Webhook secrets are no longer exposed.** `GET /api/settings` shows only
  `scheme://host/***` for provider URLs (the Telegram bot token used to be shown
  in full). Errors from failed webhook deliveries no longer carry the URL either.
- **Login throttle can no longer be bypassed by concurrent requests.** Attempts
  are counted before the password hash is checked; 60 parallel guesses used to
  get ~59 evaluations, now at most 7 per IP per minute, then a lockout.
- **Dashboard auth fails closed.** A transient database error no longer turns
  authentication off for a couple of seconds.
- **Data directory and database are owner-only** (0700 / 0600), including when
  `PULSEMON_DB` points somewhere other than `/data`; the TLS directory too.
- **Self-signed certificate handling is correct.** Common OpenSSL certificates
  (CA:FALSE, or CA:TRUE with digitalSignature) are accepted, forged
  "self-signed" certificates are rejected, and after a redirect the certificate
  is verified against the final host.
- **A configured TLS certificate that cannot be read is now fatal** instead of
  silently serving plain HTTP. Set `PULSEMON_ALLOW_PLAINTEXT_FALLBACK=1` to keep
  the old behaviour.
- **TLS certificate upload is atomic** (both files validated and installed
  together; the port is saved last), so a failed upload cannot leave a
  mismatched pair that crash-loops the next boot.
- Security headers on every response (`X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `frame-ancestors 'none'`).
- Internal error text (SQL, file paths) is no longer returned in 500 responses.
- The session cookie is `Secure` behind a trusted TLS-terminating proxy
  (`PULSEMON_TRUSTED_PROXIES` + `X-Forwarded-Proto: https`).
- Go toolchain 1.26.9 and `golang.org/x/net` 0.60.0: govulncheck reports 0
  reachable vulnerabilities (29 in v0.3.16). Releases now run a govulncheck gate.
- `pulsemon auth-user add <user>` reads the password from stdin
  (`--password-stdin` also accepted); the old `<user> <password>` form still
  works but warns that the password is visible in `ps`.

## Reliability

- **A sensor whose own sends fail now reaches `error` and alerts.** Status no
  longer depends on a process-wide error counter that other sensors could bump.
- **Probe scheduling spread is fixed for ~half of all sensors** (an integer
  overflow made them fire immediately and in lockstep); an interval of 0 no longer
  panics; a panicking probe is contained.
- **Alert delivery retries** transient failures (3 attempts, 2 s / 10 s backoff),
  sends to all providers in parallel, and a failed delivery no longer burns the
  re-alert interval.
- **Settings and sensor updates are atomic and validated first.** Changing one
  setting no longer resets alert routing; an invalid PATCH no longer half-applies;
  renaming to an existing name returns 409.
- The ICMP reader goroutines restart after an unexpected stop.
- Rows with query errors are no longer treated as "no sensors"; a partial read
  can no longer cancel healthy probe loops.
- HTTP server read/idle timeouts and a header size limit (no write timeout on
  purpose: self-update streams for up to a minute).
- A graceful-shutdown error no longer skips closing the database.

## Performance and scale

- Status and history for each probe come from memory instead of two extra
  queries; the stats series is no longer copied per call.
- SQLite `synchronous=NORMAL` in WAL mode (measured on ext4: 0.55 ms to 0.02 ms
  per probe insert).
- Timestamps are fixed-width, so string ordering equals time ordering (retention
  purge and `ORDER BY ts` are now exact). Older rows remain readable.
- Graph totals come from the bucket rows (one query fewer); static assets get a
  strong ETag and `304 Not Modified`.

## Upgrade notes — behaviour changes

- **Sensor limits are now enforced on create and update:** `interval_s` 5–3600,
  `down_after` 1–100, `timeout_ms` no greater than the interval. Existing sensors
  are not migrated; scripts that create sensors faster than 5 s will get a 400.
- Clone (`POST /api/sensors/{id}/clone`) retries on a name collision and returns
  409 when it gives up.
- Self-update keeps the previous binary at `<exe>.prev`; new
  `pulsemon update rollback [--restart]`, and `pulsemon update --restart` rolls
  back automatically if the new version fails its health check. (The `.prev` copy
  is made by the updater that is *running*, so it appears on updates made **from**
  v0.3.17 onward.)

## Known limitations (deferred, not fixed here)

- **The dashboard's update button works on installs with authentication
  disabled.** Anyone who can reach an auth-off dashboard can trigger an update,
  including pinning an older release. Binaries are still SHA-256 verified.
  Enable authentication (`pulsemon auth-user add <name>`) on any install reachable
  beyond a trusted LAN.
- Release signing for self-update, a read-only/viewer role, and HEAD/Range support
  for HTTP probes are not part of this release.
