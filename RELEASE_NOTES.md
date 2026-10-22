# v0.3.24 — External-review hardening pass

Eight verified external-review findings, each fixed with a regression test
that fails on the pre-fix baseline and gated with gofmt, go vet,
GOOS=windows go vet, and the full -race suite. No behavior changes beyond
the fixes; the 5-second poll hot path and probe engine are untouched.

## Correctness

- **Non-atomic sensor create + clone** (`abe0871`). `POST /api/sensors` and
  `POST /api/sensors/{id}/clone` inserted the sensor row, then wrote its
  tags in a second transaction — logging and swallowing any tag-write error
  while still returning 201 with the tags in the response. A torn or empty
  tag set with `alert_scope='tags'` silently changes which sensors alert, so
  the API could claim tags were saved that the database never had. The
  sensor INSERT and tag write now commit in ONE `ImmediateTx` (the same
  pattern the PATCH path already used); a tag failure rolls back the sensor
  row and returns 500.
- **Unbounded, unvalidated `alert_filter`** (`956c1c6`). `PUT /api/settings`
  stored the `alert_filter` list verbatim — up to the 1 MiB body cap, with
  no per-entry validation — and it is re-read on every alert decision and
  settings load. Entries are now trimmed, deduped, validated with
  `validSensorName`, and capped at 500; an oversized or invalid list 400s
  with the store (including sibling fields) left untouched.
- **Dead non-atomic `(*DB).AddUser`** (`4934379`). The DB-level `AddUser`
  ran `SELECT COUNT(*)` and `INSERT` as two separate auto-commit
  statements, duplicating the first-admin invariant that `AuthState
  .AddUserMode` already owns atomically — a concurrent call on an empty
  table could create two admins. It had zero production callers (API,
  in-app, and CLI all go through `AddUserMode`), so it was removed and the
  one test that used it as a seeding shortcut now inserts rows directly. A
  new test pins the production bootstrap path: 8 concurrent first-user
  POSTs yield exactly one account.

## Sessions

- **Sliding session cookie defeated by the browser** (`c5dd319`). The login
  cookie carries a fixed `Max-Age=30d`, so the browser deleted it exactly 30
  days after login even though the server slid the in-memory session on
  every use — an active user was logged out at day 30 with no way to renew.
  The gate now re-issues the SAME token once the cookie ages past half the
  TTL: at most one `Set-Cookie` per ~15 days of activity, never per 5-second
  poll. The token is not rotated, so the client is never invalidated.

## Performance

- **Clone name pick ran up to 100 sequential queries** (`f0588a2`).
  `handleSensorClone` probed `SELECT COUNT(*) ... WHERE name = ?` for
  `-copy1` … `-copy100` one at a time before the first INSERT. Existing
  clone names are now fetched in ONE `GLOB` query and the first free suffix
  is picked in memory. `GLOB` (not `LIKE`) matches the case-sensitive
  `BINARY`-collation `UNIQUE` index; the `UNIQUE` index + retry loop remain
  the arbiter for metacharacter edge cases, so behavior is unchanged.

## Hardening / observability

- **Missing `request.Context()` propagation** (`704555e`). The read/write
  queries in the sensor, history, graph, events, tags, and settings
  handlers used `s.db.Query/QueryRow/Exec/Begin` without a context (the
  PATCH path already threaded `r.Context()` through `ImmediateTx`). Every
  in-handler DB call now uses its `*Context(r.Context(), ...)` counterpart,
  so a request whose context is dead (client disconnect, proxy timeout)
  fails fast at the pool level instead of executing its queries. (The
  modernc driver does not interrupt a statement already blocked inside the
  driver on the 15 s `busy_timeout` — verified empirically; that limit is
  documented in-code.)
- **Silent row-scan error swallowing** (`d68ef86`). `fetchSensors` logs a
  per-row `rows.Scan` failure before skipping, but the history, graph,
  events, clone, and tags loops dropped a corrupt row silently — a bad
  timestamp or a schema-migration type mismatch produced a 200 with a
  truncated list and zero visibility in the service log. All five loops now
  log the failure before skipping (a mid-stream failure still 500s via the
  existing `rows.Err()` checks).
- **Missing `Cache-Control: no-store` on `/api/*`** (`458a7a0`). Static
  assets set `no-cache`, but JSON API responses set no `Cache-Control` at
  all — leaving sensitive payloads (`/api/settings`, `/api/auth/status`,
  sensor data) exposed to intermediate proxies and aggressive browser
  caching. The auth gate now answers `no-store` on every `/api/` response,
  200s and error paths alike; static assets keep their own `no-cache`
  contract.

---

# v0.3.23 — Alert-storm coalescing + TLS cert hot-reload

The two findings deferred from the v0.3.17 review round (M8 alert-storm
throttling, m10 TLS certificate hot-reload) are now implemented. Every
other item in that deferred batch was audited against v0.3.22 and found
already fixed or present — this release closes the batch. Gated with
gofmt, go vet, GOOS=windows go vet, and the full -race suite (182 s, 0
failures); four new tests pin the new behavior.

## Reliability

- **M8: alert-storm coalescing** (`3a7990b`). A mass outage used to fan
  out one webhook/email per sensor — twenty flapping sensors meant
  twenty near-identical messages in the same second. There is now a
  global budget of **10 individual non-recovery alerts per 30 s
  window**. **Recoveries are always admitted** — you never miss the
  "it's back up" — while over-budget down-alerts are queued and
  delivered as **one coalesced storm summary** when the window
  elapses: "pulsemon: alert storm — N sensors changed state" with one
  `name: old → new (target)` line per sensor. Entries that recover
  before the flush are dropped so the summary never contradicts the
  recovery alert it raced. The summary is a global meta-alert sent
  with the same per-provider fan-out (google_chat, discord, telegram,
  SMTP) and is deliberately NOT queued on any sensor's per-sensor
  ordering gate, so per-sensor alert ordering is untouched. The 429
  `Retry-After` handling added in v0.3.22 still applies to the
  individual deliveries.
- **m10: TLS certificate hot-reload** (`3a7990b`). The TLS listener
  loaded the cert/key pair ONCE at startup, so a renewed certificate
  (dashboard TLS upload, acme.sh cron) required a process restart.
  `GetCertificate` now re-reads `data/tls/{cert,key}.pem` whenever
  either file's mtime changes — the renewal takes effect at the NEXT
  handshake, no restart. A failed reload (half-written file, transient
  cert/key mismatch) keeps the LAST GOOD pair instead of failing every
  handshake; the next handshake retries the reload.

## Tests

- `TestStormCoalescing` — 5 simultaneous down-alerts at budget 3 =
  exactly 3 individual deliveries + 1 summary carrying the 2
  suppressed sensors; every sensor appears exactly once.
- `TestStormRecoveryAlwaysAdmitted` — at budget 0, recoveries are
  still delivered individually and never coalesced.
- `TestStormFlushDropsRecovered` — a suppressed sensor that recovers
  before the flush is absent from the summary.
- `TestHotReloadCert` — renewal takes effect on the next call,
  unchanged files serve the cached pair, a corrupt reload keeps the
  last good pair, and a repaired file is picked up again.

---

# v0.3.22 — External review hardening (17 findings)

Third-round external review (two parallel passes) produced 17 findings.
Every one was verified against the real code before any change: thirteen
were valid and fixed, four were documented (two by design, two stale
from earlier fixes). Every commit was gated with gofmt, go vet,
GOOS=windows go vet, and the full -race suite, and behavior changes were
sabotage-verified (reverting the fix fails the new test).

## Security

- **Setup-mode bootstrap is keyed off a valid session, fresh-install
  only** (`d1b78b3`). Setup mode was detected by the session cookie being
  ABSENT, so a browser holding a stale 30-day cookie got "403 admin
  only" when creating the first admin. Conversely, once auth was
  intentionally disabled, an unauthenticated LAN client could still win
  the bootstrap and lock the operator out — the new account is admin and
  re-enables auth server-wide. Setup now requires auth disabled + no
  valid session + not bootstrapped; the status payload gains
  `bootstrapped` so the UI shows the bootstrap button only on fresh
  installs and a CLI re-enable hint on operator-disabled ones.
- **Sec-Fetch-Site arm on the cross-port CSRF gate** (`0412032`). The
  Origin-only check missed browsers that send `Sec-Fetch-Site` without a
  usable Origin. Non-GET/HEAD requests with `Sec-Fetch-Site` other than
  `same-origin`/`none` are now refused — including `same-site` (another
  port on the same IP). Requests without the header (curl,
  server-to-server, tests) pass, as before.
- **Every HTTPS redirect hop gets a fresh connection** (`37f54ee`). The
  2026-10-19 fix closed only host/scheme-changing hops; a SAME-host
  HTTPS redirect reused the pooled conn a previous probe's redirect hop
  left behind (the shared transport pools idle conns for 10 min), so the
  hop reported the cert from that conn's ORIGINAL handshake — a renewed
  cert stayed invisible in the displayed expiry for up to 10 min, and
  cert verification judged the STALE cert (a renewed-and-valid install
  could read as "expired"). `req.Close` is now set on every HTTPS hop;
  plain-HTTP hops keep pooling (no cert data).
- **Redirect guard delegates to the canonical IP check** (`e60ac37`).
  `redirectTargetAllowed` carried a hand-copied judge that lacked the
  `embeddedIPv4` check, so a cross-host 302 to `http://[::7f00:1]/`
  (loopback) or `[::a9fe:a9fe]` (cloud metadata) got through. The copy
  is gone; both the literal-IP and DNS paths call `checkWebhookIP` — no
  more drift. Regression cases for all three embedded forms added.
- **Change-password / delete-user 500 real failures** (`5412207`). Both
  handlers mapped their ENTIRE error space to 400 with raw `err.Error()`
  text — a failed UPDATE/DELETE surfaced the driver string
  ("no such table", "database is locked") as a client error. Validation
  sentinels (and the last-user guard, now the `errLastUser` sentinel)
  stay 400; everything else is a generic 500 with the detail logged —
  the same pattern AddUser got in the 2026-10-19 review.
- **Removing a nonexistent user fails with 404** (`60aee7b`).
  `db.RemoveUser` treated no-such-user as a silent no-op, so a mistyped
  username reported success end to end: the API answered 200 and the CLI
  printed "User removed: <name>". It now returns the `errUserNotFound`
  sentinel; the API answers 404 (same policy as the password endpoint),
  the CLI exits 1 with the message, and a mistyped name in a single-user
  install is "no such user" rather than "cannot remove the last user".

## Reliability

- **A respawned probe loop probes within 1s** (`0cc3e9e`). The sync pass
  drops paused sensors within ~5s, so the resume "kick" never found them
  — a resumed sensor (and every sensor after maintenance mode ends)
  started a fresh loop with a random start delay of up to one interval:
  up to an hour of darkness for an hourly sensor. `ProbeWorker` now
  tracks which sensors it spawned; respawns cap the first tick at 1s
  while first spawns keep the stagger (no thundering herd on boot).
- **Pulse Now never touches status or alerts** (`38eb4ba`). The docs
  say manual pulses never affect status, but the rows landed in the same
  history the status logic reads — one lost manual pulse (1s timeout)
  plus one lost scheduled probe could trigger a `down_after=2` alert.
  `probes` gains a `manual` column (one-time migration); Pulse Now rows
  are tagged and excluded from status derivation, while history,
  sparkline, and graph keep showing them.
- **Shutdown stops the HTTP server first** (`7b92e29`). The server used
  to stop LAST, so requests were still handled after the probe worker
  and alerts had stopped, and slow handlers (e.g. a webhook test) could
  run into the closed database. New order: `srv.Shutdown(5s)` → probe
  worker → alerts → DB close. A/B-verified against a real slow handler
  at SIGTERM: the old order closed the DB mid-operation.

## API / data integrity

- **Clone name truncation is by runes, not bytes** (`9a5ba74`).
  `handleSensorClone` truncated the base name at 52 BYTES with a
  continuation-byte rollback, over-truncating (and in the worst case
  invalidating) multibyte names. It now slices to 52 runes; a 60-rune
  CJK name clones to 52 runes + `-copy`.
- **The SMTP `tls_mode=none` guard evaluates the effective state**
  (`0e1c92b`). Settings PUTs are partial — omitted keys keep stored
  values — but the guard checked only the incoming map, so a
  `{"tls_mode":"none"}` PUT over stored credentials bypassed the
  "no credentials with TLS off" rule. Validation and apply now share one
  pre-transaction stored snapshot per provider and judge the merged
  state; a deliberate none+clears still succeeds.
- **The session cookie carries Max-Age alongside Expires** (`733b413`).
  Only `Expires` was sent, leaving expiry to client clock accuracy.
  `Max-Age` (30 days) is now sent on set — RFC 6265 §5.3 gives it
  precedence — and `Max-Age=0` on deletion (negative values omit the
  attribute in Go).

## Performance

- **Graph queries range-seek the probe index** (`347d53e`). The window
  filter ran on `CAST(strftime('%s', ts) AS INTEGER)`, which defeats the
  index and full-scans every row for the sensor. A coarse seekable
  `ts >= ?` bound (1s slack for legacy variable-width fractionals) is
  added alongside the exact epoch filter, which remains the arbiter.
  The plan changes from `sensor_id=?` to `sensor_id=? AND ts>?`; on a
  17,280-row sensor the 1h window drops scanned rows to ~720
  (191.7µs → 185.8µs, and the scan bound no longer grows with history).

## Documented (no behavior change)

- **`PULSEMON_ALLOWED_HOSTS` is setup-mode hardening by design**
  (`83c65f2`). The README defines it as having no effect once an account
  exists; a global host gate would lock out direct-IP operator use
  (Host is client-controlled, and authenticated browser traffic is
  already covered by the Origin/Sec-Fetch-Site gate).
- **Static ETag hashes are memoized** (`ea36475`). Measured on the
  toolchain box: one-time SHA-256 of the 109 KB index.html ~54µs, warm
  lookup ~9ns, per-request read ~6.5µs.
- **The clone rune-truncation test also pins the invalid-UTF-8 variant**
  (`0ae869c`). The old byte-cut algorithm was empirically shown to
  produce a dangling 0xE7 (invalid UTF-8) for CJK names; the rune test
  is annotated so the hazard isn't re-flagged.
- **Session validation keeps its lock scope** (`de45f89`). The
  users-table lookup under the session lock is a sub-millisecond point
  query capped by a 2s TTL; moving it outside would need
  unlock/query/re-lock/re-validate and open a race window. The gate +
  handler double validation is deliberate layered authorization.

## Upgrade notes

- One-time schema migration: `probes` gains `manual INTEGER NOT NULL
  DEFAULT 0` (existing rows are scheduled probes). No action needed.
- If you relied on `DELETE /api/auth/users/<name>` succeeding for a name
  that doesn't exist, it now returns 404 (it always said "ok" before).
- Session cookies now include `Max-Age`; browsers that honored only
  `Expires` with a skewed clock get correct expiry.


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
