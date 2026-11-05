# v1.0.0 — 1.0: hardened

The 1.0 release. Core functionality (ICMP/HTTP probing, dashboard, auth,
alerts, self-update, Windows service, Docker) was built out through the
v0.3.x series; this release ships the external-review hardening pass —
16 security/robustness/correctness findings plus a code-hygiene batch —
on top of a stable core.

## Security

- **CSP inline handlers removed** (ed457a0, 4c45ee7). All 7 inline
  event-handler attributes stripped from markup; handlers bound as
  explicit JS listeners. Server rejects empty `alert_filter` when
  effective scope is `tags`/`sensors`. `toggleScopeItem` added to
  `ACT_NEEDS_EL` (alert-routing item selection was dead).
- **Release manifest signature + downgrade floor** (f937d17). Release
  assets are signed over a manifest (tag + asset name + SHA-256), not
  raw bytes — an old signed binary replayed under a new tag no longer
  verifies. `max_version_seen` persisted at boot; a lower post-rollback
  version is refused. CLI `--allow-downgrade` and dashboard version-pin
  are explicit opt-outs.
- **DNS-rebinding TOCTOU closed** (e2f4482). `redirectTargetAllowed`
  returns the checked IP; `CheckRedirect` rewrites cross-host redirect
  URLs to that IP before the transport dials. Initial target is the
  operator's own configured sensor (admin-privileged by design) and is
  not rewritten.
- **Per-username login throttle + bcrypt concurrency cap** (8565cea).
  A per-username fail counter on top of the per-IP throttle closes the
  multi-IP account-spray vector. A blocking `bcryptSem` (capacity
  `runtime.NumCPU`) queues excess KDFs under attack instead of
  rejecting the operator's login. Hard-cap wipe is all-or-nothing
  across per-IP and per-username maps.
- **`allow_unauth_update` gated** (6282bb2). The toggle requires an
  existing account / auth-on state to change; the stored value is
  untouched, only mutation is gated.
- **README data-dir perms** (789dbd6). `chmod 0777 data` replaced with
  `sudo chown 1000:1000 data && chmod 700 data` — the directory holds
  password hashes and plaintext webhook/SMTP/Telegram secrets.

## Robustness

- **Atomic status/event commits** (1c1ca42). `doProbe` wraps the status
  UPDATE and event INSERT in one `ImmediateTx`; `rememberStatus`
  advances only after commit.
- **Generation-based syncSensors** (e7c88cf). `syncSensors` no longer
  holds `pw.mu` across DB reads; per-sensor generation reconcile
  replaces the full re-scan.
- **Tiered stats series** (55b86cb). `probeSeries` splits into raw
  per-probe entries (1h window) and older per-minute aggregate buckets.
  Memory footprint at 5s interval drops from ~110 MB (200 sensors) to
  ~10 MB. 24h graph served from memory.
- **Startup retention purge** (ae05680). `pw.purgeOld(ctx)` runs once
  at startup, not only 1h after start — crash-looping processes no
  longer skip the sweep.
- **Storm-summary re-check** (b516055). `deliverStormSummary` re-checks
  `currentStatus` per entry before the async post; a recovery admitted
  after the flush-time filter no longer lands before the summary that
  still lists the sensor as error.
- **Cert-freshness conn reuse** (8623763). HTTPS probes skip the TLS
  handshake when the host's cert was last read <10 min ago
  (`certReadTimes` map, keyed by `scheme://host`). Redirect hops always
  force fresh. Reported RTT unchanged (starts at `GotConn`).
- **Linux datagram ICMP → netpoller** (4840187). Hand-rolled
  `dgramTransport` (raw syscall + `SOCK_NONBLOCK` + `unix.Poll` 100ms
  loop) replaced with `icmp.ListenPacket("udp4", "0.0.0.0")` —
  netpoller-driven `ReadFrom`, no Poll loop, EINTR handled internally.
  Windows driver remains hand-rolled.

## Correctness

- **sensorSpec validation dedup** (de87f97). POST/PATCH/clone share
  one `sensorSpec` struct with `applyDefaults()`, `validate()`,
  `validateCrossField()`, and `clamp()`. Legacy `type=''→'icmp'`
  normalization replaced by a one-time `InitSchema()` migration.
- **DNS stale-IP fallback** (2a1ce3a). On re-resolution failure, serve
  the last good IP (bounded 10-min staleness) and surface the DNS error
  separately via `probes.dns_error`. `singleflight` collapses
  concurrent lookups for the same name.
- **Alert hot-path settings snapshot** (d0bad52). Per-call `GetSetting`
  reads on the alert path replaced with one typed atomic
  `alertSettings` snapshot, swapped after `PUT /api/settings` commit.

## Code hygiene

- **Comment cleanup + structural nits** (b7a2ea4). Review-history
  narration removed from code comments (the why stays, the history
  belongs in git / DECISIONS.md). `PingNow` doc block trimmed. Stale CI
  flake comment removed. `httptrace` captures mutex-protected. Session
  user stashed in request context (one `SessionUser` lookup per
  request, not three). Admin gating consistent (`requireAdmin` route-
  level for delete/disable). Unneeded `AUTOINCREMENT` removed from
  probes/events. `interface{}` → `any` (64 occurrences). SMTP retry
  classification uses `errors.Is` sentinel, not string prefix.
  `kick` wrapper simplified.

## Release signing transition

This is the first release carrying the manifest verifier. It is cut
with `RELEASE_SIGN_FORMAT=legacy` so v0.4.4-era clients (raw-bytes
signing only) can install it. The next release uses the default
`manifest` format.

## Assets

- `pulsemon-linux-amd64`, `pulsemon-linux-arm64` (+ sha256 sidecars + `.sig`)
- Windows assets added by the `windows-release.yml` workflow on tag push
  (`pulsemon-windows-amd64.exe`, `pulsemon-setup-1.0.0.exe` + sidecars + `.sig`)
- `install.sh`
