## v0.1.27

Closes the **silent ICMP failure mode**. When neither ICMP transport could
open (e.g. RHEL 8's default `net.ipv4.ping_group_range` excludes the service
uid and `CAP_NET_RAW` isn't granted), zenmon used to start the server, report
`status: "ok"` in healthz, and simply never ping — with no error anywhere.
The failure was only findable by noticing the *missing* `icmp_mode` key.
Now the failure is loud, at three layers:

### 1. `install.sh` preflight (fail before the service starts)

Before installing, the script reads `net.ipv4.ping_group_range` and checks
whether the installer's gid falls inside it. If not, it prints the exact
remediation (`sysctl` + the persistent `/etc/sysctl.d/90-zenmon-ping.conf`)
and, on an interactive terminal, asks before continuing (non-interactive
installs continue but flag that the dashboard will warn). Background: the
kernel default is `1 0` (nobody may ping); systemd ≥ 244 — RHEL 9+, Fedora,
Ubuntu/Debian — ships `0 2147483647` via `50-default.conf`, but RHEL 8
(systemd 239) does not.

### 2. Honest `healthz`

When the shared ICMP engine fails to open (both transports), `GET
/api/healthz` now returns:

```json
{"status": "degraded", "icmp_mode": "unavailable", "icmp_hint": "ICMP socket
unavailable: ... Fix: sudo sysctl -w net.ipv4.ping_group_range=\"0 65535\"
(persist via /etc/sysctl.d/90-zenmon-ping.conf) and restart zenmon — or grant
CAP_NET_RAW. See `journalctl -u zenmon` for the exact error.", ...}
```

instead of the previous `status: "ok"` with no `icmp_mode` key. The engine is
warmed at probe-worker startup, so this is visible on the first healthz after
boot — not after the first failed probe tick. The failure error now wraps the
`errNoIcmpTransport` sentinel so tooling can match it with `errors.Is` while
still carrying the underlying cause.

### 3. Dashboard banner

The existing warning banner now fires on `icmp_hint` (before the generic
`probe_error`), showing the remediation command right on the dashboard.

### Verified

- `go test` — full suite green, including the new `TestHealthzIcmpMode`
  (dead → degraded/unavailable/hint; unprivileged-datagram → ok; raw → ok).
- Live container matrix on zentest: RHEL-8-like netns (range `1 0`, no caps)
  → degraded + hint; wide range → ok; raw-socket-possible → ok.
## v0.1.26

A review-driven release: one new self-update convenience flag, and a batch of
correctness fixes to probe status, sensor editing, fresh installs, target
validation, and the "Echo Now" diagnostic. No change to how a normal probe
tick works on a healthy install.

### New: `zenmon update --restart`

The self-updater now optionally restarts the running service for you. By
default `zenmon update` keeps its install-and-hint contract (swap the binary,
print the restart command) because the fleet is mixed — containers, root
installs, and non-systemd hosts are safer told how to restart than
auto-restarted (a bad new version would otherwise take the monitor down).
With `--restart`:

```
zenmon update --restart
```

it first confirms a **live** systemd `zenmon` service via `systemctl is-active`
(user bus, or system bus when running as root), restarts on the correct bus,
then polls `healthz` and reports the outcome — exit 1 if the service fails to
come up healthy. Both `systemctl` calls are bounded (10s is-active / 60s
restart) so a wedged D-Bus can't hang the update. If no live service is
detected (container, no bus, non-systemd host) it degrades to the hint, and in
a container it warns to `docker compose up -d --build` instead. The flag is now
documented in both user-facing places (the `main.go` usage line and the README
command block), not just the in-code help.

### Fix: PATCH loss_warn / down_after now respawn the probe loop

Editing a sensor's `loss_warn` or `down_after` in the UI wrote the new value to
the database and echoed "updated," but the running probe kept the spawn-time
copy until a full process restart — so a user who set `down_after` 4 → 10 would
still get an error after 4 consecutive losses while the UI showed 10. Those two
fields now trigger the same probe-loop respawn as `target` / `interval_s` /
`timeout_ms`, so the operating thresholds change immediately. (`spike_mult`
stays informational-only — `deriveStatus` doesn't read it — so a PATCH of it
correctly does not churn the loop.)

### Fix: never read "up" on a DB read error

`deriveStatus` returned `"up"` when its probe-history query failed — the most
optimistic status, the exact opposite of the broken-socket path just above,
which deliberately returns `"warning"` (never fake up). A downed sensor would
read recovered for a tick on a database hiccup, and the probe would record a
"recovered" event and fire a recovery alert. It now returns `"warning"`
(unknown) on a `Query` error. Safe by construction: `warning` is dashboard-only
(it never fires an alert), so a transient WAL/SQLite hiccup just reads degraded
for one tick and self-clears the next.

### Fix: fresh-install seed sensors match the UI defaults

The demo sensors created on an empty database (`router`, `server`) used
5s / 2000ms / 5% / 3, ACTIVE, targeting `192.168.1.1` / `192.168.1.10` —
different tuning than a dashboard-created sensor (15s / 1000ms / 25% / 4,
spike_mult 3, paused), and hardcoded to a network many installs don't use. They
now match the UI defaults (15s / 1000ms / 25% / 4, spike_mult written explicitly
as 3 so they stop inheriting the schema column default of 5), start **paused**
so placeholder targets can't fire down alerts on day one, and point at
`127.0.0.1` — environment-neutral until the user edits the targets and resumes.
Only affects fresh databases; the seeding guard still no-ops when the sensors
table is non-empty, so existing installs are untouched.

### Fix: `validTarget` range-checks IPv4 and documents bare-hostname rejection

The IPv4 branch of the target validator (`\d{1,3}` per octet) accepted
out-of-range addresses like `999.999.999.999`, which then just failed DNS every
probe tick. IPv4 is now checked with `net.ParseIP`, so out-of-range octets are
rejected at save time with the existing 400; IPv6 is rejected explicitly (not a
supported ICMPv4 target). A comment now states that bare single-label hostnames
(`router`, `NAS`) are **deliberately** rejected (they're almost always a typo for
an ICMP tool and won't resolve) — intentional, not a bug a future maintainer
might "fix."

### Fix: "Echo Now" records its sample at a fixed 1s timeout

The manual "Echo Now" probe used a hardcoded 2s timeout (independent of the
sensor's configured timeout) and discarded its result. It now runs at a fixed
1s and **records** the sample — a `probes` row plus the dashboard sparkline — so
a manual probe shows up in the sensor's history. It deliberately does not derive
a status or fire an alert: a single manual echo keeps history honest without
flipping a healthy sensor to error or firing a recovery webhook. Works while
paused, and the dashboard tooltip now reads "recorded to history."

### Cleanup: drop a dead `database/sql` import

`probe.go` imported `database/sql` solely to satisfy a `var _ = sql.ErrNoRows`
at the bottom of the file — no other symbol in the file used it, and the files
that do (`api.go`, `db.go`) import it themselves. Both the import and the
blank-var keeper are gone.

### Verification

- Full test suite green with `-race`, `go vet` and `gofmt` clean.
- New regression tests per fix, each confirmed to fail against the pre-fix code:
  `--restart` service detection / bounded `systemctl` / container path;
  PATCH `loss_warn` / `down_after` respawn vs. `spike_mult` / `name` no-respawn;
  `deriveStatus` "warning" on a DB read error; fresh-install seed tuning /
  state / targets and the empty-DB guard; `validTarget` in-range vs. out-of-range
  IPv4, dotted hostnames, and bare-label rejection; and "Echo Now" recording its
  sample at exactly 1s while leaving status untouched.

---

## v0.1.25

Security hardening for outbound webhook delivery. Four fixes to
`webhook.go` (and its callers) close gaps in how alert URLs are validated
and how in-flight deliveries are bounded. No change to probe behavior,
status logic, or the self-updater.

### Fix: enforce the webhook IP blocklist at dial time (DNS-rebinding TOCTOU)

`validateWebhookURL` resolved the host at save time, but the webhook client's
default transport re-resolved it at dial time — so a rebinding domain that
flipped from an allowed public IP to `127.0.0.1` / `169.254.169.254` between
save and dispatch slipped past the SSRF blocklist. The client now dials
through `dialChecked`: it resolves (or parses the literal IP), runs the
blocklist on **every** resolved address, and connects to the very IP it
checked — closing even the check→connect microsecond window. The transport
still performs the TLS handshake itself (ServerName = URL host), so SNI and
certificate verification are unchanged.

### Fix: allow `http://` webhooks to RFC1918 private relays, `https` elsewhere

Internal homelab relays (self-hosted ntfy, chat bridges) commonly run plain
HTTP with no local TLS certs, but the validator demanded `https://` for
every destination — rejecting the exact internal-relay use the code comments
said was allowed. Scheme is now: `https://` anywhere; `http://` only when the
host is, or resolves to, a private RFC1918 / ULA address. Public destinations
still require https, and the IP blocklist still applies afterwards, so
`http://127.0.0.1`, `http://169.254.169.254` etc. are refused regardless of
scheme.

### Fix: bound outbound webhook POSTs with a cancellable context

`webhookClient` only had a global 10s timeout; both call sites used
`webhookClient.Post()`, which cannot be cancelled. If shutdown happened during
a network blip, an in-flight alert delivery kept its connection open until the
10s timeout and held process exit that long. `postJSON` now builds the request
with `NewRequestWithContext` bound to a worker-level `stopCtx`, and
`StopAlerts()` — called by `main` on shutdown before `DrainAlerts` — aborts
any in-flight POST at its next read. `TestWebhook` takes a caller-provided
context (the settings-test handler passes `r.Context()`), so an abandoned
dashboard request aborts its delivery the same way. The stop context is
deliberately separate from `Run`'s: `Run`'s cancel stops new probes/alerts,
while in-flight ones get their own bounded second chance before `db.Close()`.

### Fix: report blocked literal IPs with an accurate reason (IPv6 reorder)

A blocked literal IP over `http` was misreported: `http://[::1]:8080` said
"must be an https:// URL unless `::1` is a private RFC1918 host" — telling the
user to use https or RFC1918 when the truth is "this is loopback, never
allowed". A literal IP is now judged against the blocklist **first**, for
every scheme, so loopback / link-local / unspecified / multicast are refused
up front with an accurate "blocked address". RFC1918 / ULA literals pass the
blocklist and are then gated by scheme. The `.local` / `.localhost` /
`localhost` host check is kept: a `.local` name that mDNS-resolves to a
private RFC1918 address passes the blocklist, so the suffix check is the only
thing keeping those out of the http-relay path.

## v0.1.24

First multi-architecture release: zenmon now ships for **linux/amd64 and
linux/arm64**, so the self-updater, the `install.sh` installer, and the Docker
image all work on ARM SBCs and single-board computers (Jetson, Raspberry Pi,
RK3588) as well as x86_64. Nine `zenmon update` hardening fixes ship
alongside. No change to probe behavior or status logic.

### New: linux/arm64 release asset

The release now publishes a static, stripped `zenmon-linux-arm64` (with its
`.sha256` sidecar) next to the existing `zenmon-linux-amd64`. `zenmon update`
resolves the asset for the platform it runs on (`zenmon-<GOOS>-<GOARCH>`), and
`install.sh` picks the matching binary from the host's `uname -m`. The Docker
image is multi-arch (`TARGETARCH`), so `docker compose up -d --build` builds
for the host it runs on.

> **Note:** `zenmon update` on an ARM box now looks for
> `zenmon-linux-arm64`. Until this release's arm64 asset is published, an ARM
> host correctly refuses with `release has no zenmon-linux-arm64 asset` —
> install v0.1.24+ via `install.sh`, which now ships the arm64 binary.

### Fix: `zenmon update` no longer leaks the downloaded binary

`runUpdate` returned an exit code to `main()` instead of calling `os.Exit`
directly. `os.Exit` skips deferred functions, so every failed verification,
corrupt download, or `--check` run had been orphaning the multi-megabyte
binary in the system temp dir. The defer stack now unwinds on every path.

### Fix: `installBinary` closes the source file; drops the `mustOpen` panic

The downloaded binary was opened via a `mustOpen` helper that never closed the
returned file handle (leaking a descriptor on every update) and panicked on a
failed open instead of returning an error. `installBinary` now opens the source
itself with a deferred close and returns a wrapped `open source binary` error.

### Fix: sidecar checksum resolved by asset name, not URL string-munging

The fallback checksum URL was built by `strings.TrimSuffix(assetURL, name)` +
name, which only works when the binary URL is the CDN download URL. When the
URL fell back to the GitHub API endpoint (`.../assets/N`) — which carries no
asset name — the munged URL 404'd and every no-digest update was refused. The
sidecar is now looked up directly in the release's asset list by name.

### Fix: release asset name follows the running platform

The asset name was hardcoded to `zenmon-linux-amd64`. It is now derived from
`runtime.GOOS`/`GOARCH` (honoring `$GOARCH`), so the updater targets the right
binary on every platform. Asset/sidecar/digest selection moved into a small
testable `selectAssets()` helper.

### Fix: `EvalSymlinks` error no longer ignored

`exe, _ = filepath.EvalSymlinks(exe)` could leave the binary path empty or
inconsistent on a failed resolution, making `installBinary`'s `filepath.Dir`
fall back to the CWD. The result is now used only on success; a failure warns
and keeps the `os.Executable()` path.

### Fix: `--check` respects version ordering for explicit pins

`zenmon update check v0.1.5` while running v0.1.16 reported "new version
available: v0.1.5" and exited 2 — the version-ordering check was gated on
the target being `latest`, so an explicit pin skipped it. An older pin must
read "target version … is not newer" and exit 0, so automation can't treat a
downgrade pin as an available upgrade.

### Fix: self-update restores original ownership on every binary

When swapping the running binary, the old code only restored the original
file's owner when it was *not* root — so a root-installed binary updated by
a non-root updater with CAP_CHOWN (a setuid installer, a service with file
capabilities) was silently left owned by the updater. The recorded owner is
now restored on every original, including 0:0; a failed restore warns
instead of skipping.

### Fix: app-specific User-Agent on all GitHub API requests

The releases lookup, sidecar download, and asset download now send
`User-Agent: zenmon-updater/<version>` instead of the Go stdlib default.
GitHub's API guidelines require a custom User-Agent; generic clients are
throttled or 403'd far more aggressively.

### Fix: sidecar SHA-256 accepts uppercase hex

The sidecar digest was rejected unless every character was lowercase
`a-f`. Checksum tools and pipelines that emit uppercase (or mixed-case)
hex produced a valid digest that the updater refused with "no trusted
SHA-256 available". The digest is now normalized with `strings.ToLower`
before validation.

### Verification

- Full test suite green with `go vet` and `gofmt` clean.
- New regression tests: exit-code paths leave no temp file behind; a SHA
  mismatch refuses the install; the fd count is flat across 50 installs;
  the sidecar resolves by name; the asset name tracks `GOARCH`/`runtime`;
  each fix was confirmed to fail against the pre-fix code.
- Both arches cross-compiled and verified (static ELF, version-stamped,
  sidecar self-check).

---

## v0.1.23

A hardening release: one shutdown fix, one dashboard clarification, and two
internal cleanups. No change to probe behavior or status logic.

### Fix: alert deliveries drained before the database closes on shutdown

Alerts (`sendAlert` / `sendRealert`) fire as detached goroutines so a slow
webhook never blocks a probe tick. But on shutdown the process could close the
SQLite handle while a final alert was still in flight — and the delivery's
first act is a settings read, so an alert fired on the last probe tick before
a restart died silently (or, if the POST had already started, mid-TLS).

Deliveries are now tracked in their own wait group and drained (bounded,
15s) after probing stops and before the HTTP server shuts down — so a
recover/error alert that lands on the final tick actually gets delivered.
The drain is effectively unreachable in practice: the webhook client already
carries its own 10s timeout.

### Inspector: shows the status-window loss the badge came from

Since the v0.1.22 status model derives status from the last 8 probes, a
recovering sensor can read **up** (green) while the inspector's `Loss (60p)`
still showed the outage-era 60-probe loss — at a glance, a green badge next to
an amber number. The inspector now also shows the number the badge actually
came from:

```
0 / 60 dropped (60p)  ·  status window 8p: 0% (0 lost)
```

No change to what any window means — the dashboard just no longer hides the
one that drives the status.

### Cleanup

- `recordProbe` now holds one write lock across the whole read-create-append,
  instead of the previous check-then-act (lock → check → unlock → re-lock →
  append). Behavior was already safe; the single held lock is clearer and
  strictly more defensive.
- Removed a vestigial `cancel` variable from the sensor spawn loop that was
  assigned but never read.

### Verification

- Full test suite green with `-race`, `go vet` and `gofmt` clean.
- New regression tests: the alert drain blocks until an in-flight delivery
  finishes (and returns immediately when idle); a concurrency test hammers
  `recordProbe` + stats reads from 16 goroutines and stays race-free (a
  deliberately broken variant makes it fail with a data race); the differential
  stats test now also checks the status-window fields.
- Shutdown sequence verified live: `Shutting down → Probe worker stopped →
  Alert deliveries drained → Server exited`.
