# pulsemon v1.1.11

## What's new

Hardening batch: the 2026-11-13 external-review batch (7 findings audited,
6 fixes). No new features, no API/DB changes. Every fix is
regression-pinned with sabotage-verified tests and full `-race` gates.

### Fixed: transient DB errors could silently disable alert providers
Provider reads during alert-snapshot reloads, the settings GET payload, and
the settings-save pre-checks went through an error-swallowing settings
read: a momentary SQLite failure read as "provider disabled/unset". An
alert snapshot could silently load with zero destinations (alerting off
until the next settings save), and GET /api/settings could answer 200 with
`enabled:false/has_url:false` rows that a save would echo back. All
provider keys — flags, URLs, chat id, SMTP extras — are now evaluated from
ONE bulk settings-table read that fails loud: a failed read aborts the
reload (the last good snapshot stays in force) and answers 500 instead of
reporting silent falses.

### Fixed: settings save could bypass the empty-alert-filter guard on a DB hiccup
The pre-transaction checks of PUT /api/settings (effective alert scope,
stored filter, per-provider stored state, maintenance-mode pre-check) used
the same swallowing reads. A transient failure read the stored alert scope
as "all", so the guard that refuses the dead-alert state
(scope=tags/sensors + empty filter) skipped and PERSISTED it. A
maintenance re-enable whose stored mode read as "off" also took the entry
path, replacing the maintenance restore snapshot — sensors paused at entry
would have been left paused forever. The whole pre-flight phase now rides
one fail-loud bulk read: a read failure answers 500 before any write.

### Fixed: settings save ran some statements outside the request context
The settings PUT transaction is bound to the request context, but the
in-transaction SMTP credential guard and the settings writes themselves ran
unbound. Every apply-phase statement now honors the request context, and a
failed guard read fails closed: a read that never ran can no longer answer
"no stored credentials" and wave `tls_mode=none` through over real ones.

### Fixed: client disconnects queued behind bcrypt could burn the per-IP login budget
A login (or change-password) request that disconnects while QUEUED behind
the bcrypt semaphore pays no KDF cost, yet still counted as a failure
against the 7-failures/60s per-IP throttle. Zero-cost queued cancels now
refund the attempt; disconnects that paid the KDF still count.

### Fixed: oversized change-password inputs paid the bcrypt cost before rejection
Login rejects structurally invalid credentials (empty, <8, >72 bytes)
before any DB/KDF work; the change-password route was the missed sibling.
Weak and oversized inputs now answer 400 up front, and an over-72-byte
"current password" no longer burns a bcrypt run and a throttle slot to
answer 401.

### Fixed: cloning sensors with GLOB metacharacters in the name
Sensor names may legally contain `[`, `*`, `?`. The clone-name enumeration
query builds a GLOB pattern from the base name, and an unescaped `[` made
it never match, so after 5 copies of a sensor like `nas[01]` cloning
permanently failed with 409 while `-copy6` and higher were free.
Metacharacters are now GLOB-escaped.

## Verification
- Full `-race ./...` on the release tree, zero data races.
- Each fix carries dedicated regression tests, sabotage-verified (the test
  fails when the fix is reverted).
- Rationale for every decision: docs/DECISIONS.md.
