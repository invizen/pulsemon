# v0.3.26 — Code hygiene point release (5 review nits + CI flake)

Follow-up to the v0.3.25 hardening batch: five small review nits, all
verified against the real code and gated with gofmt, go vet, and the full
-race suite. No dashboard-visible features change; the two behavior
deltas are edge-case-only and called out below.

## Behavior

- **Oversized login body returns 413, not 400** (`68b2b22`).
  `handleAuthLogin` was the one JSON handler that did not route decode
  errors through the shared `requestBodyErr` mapper, so a login POST over
  the 1 MiB body bound answered 400 "bad request" where every other
  endpoint answers 413. Now consistent.
- **Unreachable `loss_warn == 0` branch deleted from `deriveStatus`**
  (`b0d7edb`). The API cannot produce a zeroed `loss_warn` (create maps
  <= 0 to the 25 default, PATCH requires 1-100, seed inserts 25), so the
  special-casing was dead code. A hypothetical legacy zeroed row now
  degrades loudly to `warning` on any loss instead of reading `up` —
  no reachable state changes behavior.

## Maintenance

- **`probe.go` split** (`b0d2b67`). The 2,800-line file is now four:
  `probe.go` (worker core: lifecycle, pause/restart, probe loop,
  doProbe), `stats.go` (in-memory probe series + the read path off
  SQLite), `status.go` (deriveStatus + recent-window readers),
  `alerts.go` (gate, storm coalescing, provider routing, delivery,
  cards). Pure moves — no logic changes.
- **Review audit trail out of the source** (`5774917`). ~200 inline
  references to dated reviews ("2026-10-19 review F11", "2026-10-23
  external review F5") across 14 non-test files removed; the *why* stays,
  the audit trail lives in the commit history where those changes
  already are. Comment ratio on non-test code drops from ~33% to single
  digits.
- **Test files renamed by feature** (`218e94f`). Reviewer-named files
  (`fix_claude_test.go`, `fix_gemma_test.go`, `fix_esthero_*`) are gone;
  28 feature-named files (`alert_storm_test.go`, `datadir_hardening_test.go`,
  ...) replace them.
- **Auth count logic deduplicated** (`cee15b2`). `Enabled()` and
  `refreshEnabledNow()` share one unlocked helper; fail-closed semantics
  unchanged.
- **CI flake killed** (`f808d68`). `TestStormFlushDropsRecovered` was
  bimodal (~50% red) because which of two concurrent alerts was admitted
  vs queued was a coin flip; the test now forces the deterministic
  both-queued path. Production storm logic was correct all along.
- **Pre-existing bootstrap-test flake fixed** (`cc62f6a`).
  `TestFix_FirstUserConcurrentSingleAdmin` only accepted 200/409, but a
  loser whose POST reaches the auth gate after the winner commits
  correctly gets 401 — schedule-dependent red on faster machines. The
  single-admin invariant assertions are untouched.

## Assets

- `pulsemon-linux-amd64`, `pulsemon-linux-arm64` (+ sha256 sidecars)
- Windows asset added by the `windows-release.yml` workflow on tag push
