# v0.3.21 — External review hardening (10 findings)

Second-round external review of the full codebase produced 10 findings.
All ten were verified against the real code before any change: six were
valid and fixed, one was partial (half fixed, half kept by design), one
was a real mechanism with an overstated impact (hardened), and one was
invalid as described (documented). Every commit was gated with gofmt,
go vet, GOOS=windows go vet, and the full -race suite.

## Security

- **Admin flag gates the account panel** (`f3eddbf`). Any authenticated
  user could delete other accounts, disable auth entirely, or create new
  users. `users.is_admin` now exists: the first bootstrapped account is
  admin, legacy `admin` tokens migrate as admin, and a one-time migration
  promotes the oldest user on pre-existing DBs with no admin. Deleting
  the last admin atomically promotes the oldest remaining user in the
  same transaction (no lockout window). UI shows an admin badge and hides
  admin-only controls from non-admins.
- **Login throttle is per-host on the LAN** (`167489d`). The /24 IPv4
  bucket let 7 failed logins from one device lock out the entire
  homelab subnet for 5 minutes. Private (RFC1918) and loopback IPv4 now
  bucket per host (/32); public IPv4 stays /24 (anti-rotation) and IPv6
  stays /64 (privacy-extension address rotation).
- **Zoned IPv6 redirect literals are judged, not skipped** (`16b0e9f`).
  `net.ParseIP` returns nil for zoned literals (`fe80::1%eth0`), which
  fell through to DNS resolution. The SSRF guard now uses
  `netip.ParseAddr`, explicitly refuses zone-bearing literals, and
  judges `Unmap()`-ed addresses so IPv4-mapped metadata/loopback forms
  are blocked on the literal path deterministically. Fail-closed either
  way; the literal path is now total.

## API / data integrity

- **Single-read PATCH validation** (`3a7c170`). `PATCH /api/sensors/{id}`
  ran up to two pre-lock SELECTs and duplicated the type/target pair and
  timeout-vs-interval cross-check validation, then re-read the row inside
  the write transaction and re-ran the same checks. Only pure
  request-shape checks run before the lock now; the row is read once,
  in-transaction, and all DB-dependent validation runs on fresh values.
  Same status codes and messages for every request shape; one new
  regression test pins all six moved cases.
- **`rows.Err()` checked in every iteration loop** (`6654b3e`). A
  mid-stream SQLite error (busy timeout, I/O) previously produced a
  truncated 200 OK array that looked complete. All 9 unchecked loops in
  api.go and db.go now surface the error per each site's existing
  contract.
- **Rune-length caps + UTF-8 validation** (`0c35448`). Sensor names and
  tags were capped in bytes, so CJK/emoji names hit the UI's 60/30
  character limit 3–4x early, and invalid UTF-8 could be stored. Caps
  now count runes (matching the UI `maxlength`) and invalid UTF-8 is
  rejected at the write path.
- **Request context threaded through tag writes** (`3d0308b`). The last
  `context.Background()` in api.go is gone; a cancelled request now
  aborts in-flight tag updates. `ImmediateTx` rollback additionally runs
  on a fresh context so a cancelled caller can no longer strand an open
  transaction on a pooled connection.

## Probe engine

- **Restart syncs immediately, respawn reads fresh config** (`035822a`).
  A PATCH/Restart deferred the loop respawn to the next 5-second
  `syncSensors` tick (blind spot) and spawned with the config snapshot
  taken before the request's write committed (stale-config TOCTOU,
  deferred M1b). `Restart` now signals a dedicated sync pass that runs
  under lock, and the respawn branch re-reads the row from the DB inside
  `syncSensors`. The shutdown invariant is preserved: loop spawning
  stays inside `syncSensors` under the `Run` context.

## Housekeeping

- **Dead code removed, test seam documented** (`2568182`).
  `setSensorTagsInTx` (zero callers) removed; `applyProviderUpdate`
  documented as the standalone provider-test seam (12 test call sites)
  so it stops getting re-flagged.
- **`httpClient` keep-alive strategy documented** (`03a42d5`). The
  HTTPS no-keep-alive trade (fresh TLS cert readings, M5) and the
  bounded-pool rationale are now stated on the client so the transport
  values stop reading as contradictory.

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
