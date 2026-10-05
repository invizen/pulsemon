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
