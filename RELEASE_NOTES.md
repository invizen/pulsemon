# v0.3.20 — Review-hardening batch (REVIEW3 full-codebase audit)

Third-round full-codebase review (REVIEW3) produced 31 confirmed findings,
all verified real (repro tests, live zendev/zentest checks, and an empirical
Docker build probe). This release fixes them across auth, probe correctness,
update safety, alert-card hygiene, build/packaging, and ops. M7 (update
body-pin quirk) is deliberately left open per owner decision; M8
(alert-storm) is deferred.

## Auth

- **Deleted-user sessions are now invalidated** (F1). Session validation
  re-checks the account against the `users` table (TTL-cached) so a user
  removed out-of-band (CLI `auth-user remove`) loses access within the
  window, even though the in-memory session map can't see it.
- **Login/remove race closed** (F2). `CreateSession` re-verifies the user
  exists under lock before minting a token.
- **First-account bootstrap race closed** (F11). The setup-mode check moved
  inside an `ImmediateTx` (`BEGIN IMMEDIATE`): concurrent first-account
  POSTs now serialize, the winner commits the account + bootstrap flag
  atomically, and the losers get a clean 409 instead of each creating an
  account.
- **Multi-line `X-Forwarded-For` handled** (N7) — the first (client) entry is
  used, not a concatenated string.
- **Host allowlist gates sessionless mutating endpoints** (N2): with
  `PULSEMON_ALLOWED_HOSTS` set, an unauthenticated POST (e.g. logout) from a
  non-allowlisted `Host` is refused; login stays exempt as the auth entry
  point.

## Probe correctness

- **HTTPS→HTTP downgrade is now a loss, not a pass** (F3): a final plain-HTTP
  redirect from a configured HTTPS target is reported as `error`.
- **Alert ordering is per-sensor FIFO** (F4): webhook sends for one sensor
  queue on an ordered gate, so a burst can't deliver a stale `up` after a
  newer `error`.
- **Provider liveness is DB-backed with a last-known-good cache** (N3): the
  active-provider list survives a transient DB error instead of reporting
  "not delivered" on an unreadable table.
- **Redirects to a new host:port/scheme open a fresh connection** (N4), so a
  pooled TLS connection to the origin can't be reused against the redirect
  target.
- **Tag delete respawns affected probe loops** (N5): sensors losing their last
  tag are re-synced so the loop reflects the new state.
- **Warm stats load restored to the correct window** (F29): the startup
  `warmStats` fetch returns the true last-60-per-sensor series (deduping
  `UNION`); an earlier `UNION ALL` split was reverted for over-counting.

## Update safety

- **`degraded` healthz no longer aborts a good update** (H1): the post-update
  health check accepts `ok` and `degraded`.
- **Pre-release semver ordering fixed** (H2): `v0.4.0-rc.1` correctly sorts
  below `v0.4.0`.
- **Unit-env fallback for healthz host/db** (H3): when the shell env is
  empty, the updater reads the systemd unit's `Environment=` lines.
- **Binary swap is fsync-durable** (H4): the staged binary is fsynced before
  the atomic rename, and the directory fsynced after.
- **Cross-process update lock** (F19/I1): the CLI `pulsemon update` and the
  dashboard `POST /api/update` now serialize on a file lock beside the binary
  (`flock`/`LockFileEx`), so two overlapping installs can't clobber each
  other's `.prev` rollback artifact. The API returns 409 while held.
- **Detached update watchdog** (I2): the API auto-restart spawns a detached
  `pulsemon update watchdog` that polls healthz after the restart and rolls
  back to `.prev` if the new binary is unhealthy.

## Alert-card hygiene

- **Target URL credentials are stripped from every card** (F22): Discord,
  Telegram, Chat, and SMTP no longer leak `user:pass@` from a sensor target.
- **Discord mass-mention neutralized** (F23): `@everyone`/`@here` in a
  sensor name or target is broken with a zero-width space, and the payload
  sends `allowed_mentions.parse = []`.
- **TLS fullchain intermediates are kept** (F5): uploading a CA-issued
  fullchain no longer drops the intermediate (the leaf was being stored
  alone, breaking client trust).
- **TLS install is fsync-atomic** (F18): cert/key are written to a temp file,
  fsynced, then renamed into place.
- **SMTP plaintext is explicit** (F26/Q1): a `tls_mode=none` transport with
  configured credentials fails clearly; without credentials it sends with a
  one-time warning.

## Build / packaging

- **Dockerfile `TARGETARCH`** (F10/J1): `ARG TARGETARCH` is now declared so
  BuildKit populates it for arm64 (the amd64-only build was silent).
- **Compose `stop_grace_period: 30s`** (F20/K1) and an **HTTP healthcheck**
  (K2) that polls the same targets the updater does.
- **Windows installer hardening**:
  - **ProgramData ACL repair on every install** (F30/M1): `icacls` resets
    inheritance and grants SYSTEM/Administrators, so upgrades fix a
    previously-inherited `C:\ProgramData\Pulsemon` ACL.
  - **Firewall rule is private+domain only** (F31/M2): the 9299 rule no
    longer exposes the dashboard on Public networks.
- **Release gates** (F21/L1–L4): `release.sh` now fails on a dirty tree, runs
  the full test suite, pins `govulncheck`, verifies the version stamp via
  `go version -m`, and pushes the tag LAST (after the GitHub release exists)
  so the Windows workflow can't race a self-update poll with no assets.

## Ops / hardening

- **Data-dir startup is safe** (F15/N1): `ensureDataDir` refuses a relative
  `PULSEMON_DB`, sets `umask 077`, and tightens only the directories it
  creates (not pre-existing parents).
- **ICMP DNS results cached 30s** (F24) and the **raw-socket echo ID is
  per-process random** (F32), reducing per-probe DNS load and cross-host
  echo collisions.
- **Webhook response bodies are drained** (F25) so the TLS connection is
  reusable.
- **Webhook IP blocklist expanded** (P1): NAT64, Teredo, Class E/broadcast,
  and IPv4-embedded-IPv6 forms are all rejected; zone identifiers (`%`) are
  refused.
- **Provider updates validate without DNS under the write lock** (N6/D8) and
  **PATCH is re-validated in-transaction** (F14), closing the TOCTOU.
- **README TLS docs corrected** (F7/O1): HTTPS-only on `listener_https_port`
  (default 443) when a cert/key pair is present; non-root/Docker must set an
  unprivileged port (e.g. 8443).

## Not changed (by decision)

- **M7** — the update body-pin quirk stays open (owner decision 2026-10-15).
- **M8** — alert-storm throttling is deferred to a future release.
