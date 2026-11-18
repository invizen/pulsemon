# pulsemon v1.1.12

## What's new

Hardening + trust batch from the 2026-11-16 external review (M1–M3,
m1–m10, nits, Q&A round). Two new operator knobs, one first-install
security fix, six real fixes, and a zero-behavior sweep. Every fix is
regression-pinned with sabotage-verified tests and full `-race` gates.
No DB changes.

### Security: install.sh now verifies the release signature
The in-app updater has long refused releases without a valid ed25519
manifest signature — but the first install (`install.sh`) checked only
the SHA-256 sidecar, and binary + sidecar come from the same release.
install.sh now mirrors the updater's verification: it fetches
`<asset>.sig`, rebuilds the signed manifest, and verifies it against
the release public keys before installing anything. Fail-closed: a
missing signature, unverifiable manifest, or missing tooling aborts the
install. This closes the "compromised release/CI token" case that
manifest signing was designed for.

### New: PULSEMON_CA_FILE — trust a private CA for HTTPS sensors
Sensors behind an internal CA (step-ca and friends) read as lost:
verification accepted only system roots or exact self-signed certs.
Point `PULSEMON_CA_FILE` at a PEM bundle of your CA roots (mounted into
the container — a `FROM scratch` image has no system bundle, so this
file is the probe trust store) and those sensors verify UP. The bundle
replaces the system trust paths for probes; an unreadable file or a
bundle with no parseable certificates fails startup loudly. The
dashboard's own TLS is unaffected.

### New: PULSEMON_DISABLE_UPDATE_CHECK
Set to `1` to silence the periodic update check entirely:
`/api/update-check` answers "no update" with zero network calls, so a
pulsemon install can run with no outbound GitHub traffic. Operator-run
`pulsemon update` / `pulsemon update-check` are unaffected.

### Fixed: leaving maintenance mode could silently disable sensors forever
The leave path read the paused-sensor snapshot with an
error-swallowing getter: a momentary SQLite failure (or an undecodable
snapshot) resumed nothing, wiped the snapshot, and cleared the mode
flag — the banner disappeared while every maintenance-paused sensor
stayed paused, un-alerted, with no record of the set. The snapshot is
now read inside the leave transaction, and an unreadable/undecodable
snapshot fails loud (HTTP 500, mode stays ON, snapshot intact).

### Fixed: SMTP config no longer read per send
SMTP was the one provider path still doing seven per-send settings
reads; a transient lock read as "not configured" — classified
non-retryable, so in-band retries were skipped. The mail config is now
resolved into each destination at alert-snapshot load, like every other
provider; the delivery hot path does zero settings reads.

### Fixed: a resumed sensor waited a full interval to probe
A sensor created paused (by design) and then resumed counted as a first
spawn, so an hourly sensor sat dark for up to an hour after Resume.
Resumes of created-paused sensors now take the respawn fast path and
probe promptly, while normal first spawns keep their full stagger.

### Fixed: update-check data race and dashboard stalls
The update-check state was read outside its mutex (a real data race,
benign in practice) and the lock was held across the network fetch, so
every dashboard poll queued behind one 10s cache miss. State is now
guarded by the lock with snapshot-copy-out, and concurrent misses
coalesce on a single in-flight fetch.

### Changed: dashboard updates need an explicit downgrade opt-out
`POST /api/update` treated a pinned `version` in the body as implicit
consent to go below the running version's floor — an asymmetry with the
CLI's `--allow-downgrade`. Pins are now refused (409) unless the body
carries `"allow_downgrade": true`. The dashboard's own Update button
never pins, so its behavior is unchanged.

### Fixed: TLS install leaked file descriptors on write failures
A failed certificate install (write/sync failure mid-install) closed
neither temp file; the cleanup removed the names, not the descriptors.
Both temps now get a deferred close on every path.

### Fixed: ICMP reply demux — the compound key is the source check
The per-entry destination check in the reply path became unconditionally
true once replies were keyed by (seq, destination), and the probe start
timestamp was stamped after publishing the pending entry (a formally
unsynchronized write). The dead branch and the write-only field are
gone; the start stamp now happens under the lock at publish.

### Internal
- `install.sh` signature verification harness (`scripts/release-sig-harness.sh`).
- Dockerfile builder pinned to the exact Go toolchain (matches go.mod + CI).
- Dead/test-only code left the production files (moved to `_test.go`
  twins or deleted, grep-verified zero callers).
- Comments state the current contract; incident history lives in
  `docs/DECISIONS.md` (63 dated citations removed, token-equality gated).
- Tailwind build inputs moved `web/` → `frontend/`, so the embedded
  asset bundle ships served files only.

## Verification
- Full `-race ./...` on the release tree, zero data races.
- Each fix carries dedicated regression tests, sabotage-verified (the test
  fails when the fix is reverted).
- install.sh signature verification is exercised end-to-end by
  `scripts/release-sig-harness.sh` (sign→verify round trips + 4 negatives).
- Rationale for every decision: docs/DECISIONS.md.
