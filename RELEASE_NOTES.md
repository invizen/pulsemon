# pulsemon v1.1.17

## What's new

Comment hygiene: fixed a batch of stale and garbled comments. **No behavior
change** — the code is byte-identical to v1.1.16 after stripping comments
(verified by comment-stripped code-token equality).

### Fixed: comments that contradicted the code
Several comments had drifted from the code they describe. In auth and
concurrency code a wrong comment is worse than none, so each was corrected to
state the current invariant:

- `api.go` (clear-history + `deleteRowsBatched`): the batching rationale
  pointed at "syncSensors' deliberate under-lock fresh reads" — reads that
  probe.go removed (it now reconciles under the lock with no DB reads, via a
  generation fingerprint). Reworded to the actual reason: a whole-table DELETE
  holds the WAL write lock and stalls probe INSERTs / concurrent readers up to
  the 15s busy_timeout.
- `api.go` (DELETE /api/tags): claimed "per-sensor edits stay operator-scoped"
  — but per-sensor edits (PATCH) are admin-only. Corrected to the real
  rationale (destructive + fleet-wide → admin surface).
- `status.go`: the `statusWindow` comment assumed a "default 15s interval"; the
  actual default is 60s (so 8 probes is ~8 min of history, not ~2 min).
- `internal/store/store.go` + `internal/store/db_test.go`: `spike_mult` was
  called a "(deprecated, unread) compatibility column" whose seed "matches UI
  defaults (3x)" — it is a LIVE dashboard-only display knob and the UI default
  is 5, not 3. Corrected both.
- Garbled sentences from earlier edits: the `setSensorTagsInConn` doc
  ("…BEGIN IMMEDIATE ImmediateTxa *sql.Tx…"), the tag-DELETE body
  ("…the new setwithout this…"), and the `AddUser` doc (missing sentence break
  after "BEGIN IMMEDIATE transaction").

## Verification
- **Comment-only, proven:** comment-stripped code tokens are identical to
  v1.1.16 for every changed file (string/rune/backtick-aware stripper,
  whitespace-normalized).
- `gofmt -l` clean, `go vet` clean, `go build` OK on the gate box.
- Full `-race` on the release tree, zero data races, no failures.
- Rationale: docs/DECISIONS.md → `comment-hygiene-stale-fixes`.
