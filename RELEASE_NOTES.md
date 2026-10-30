# v0.4.3 — internal/store extraction (package-structure pilot)

A code-hygiene release with **no behavior change**: the data layer
(`db.go`) is extracted from the monolithic `package main` into
`internal/store`, and the package-structure thread is closed in
`docs/DECISIONS.md`. Pure moves only — no logic, schema, API, or UI
changes. Gated with `gofmt`, `go vet` (incl. `GOOS=windows`), and the
full `-race` suite on every commit.

## Structural changes

- **`db.go` → `internal/store/store.go`** (commit c4d8433). The data
  layer — schema, migrations, settings, users, sensor state, tags,
  maintenance mode, and the write pool — now lives in its own package.
  `DB` is renamed `Store`, `NewDB` → `NewStore`, and nine symbols are
  relocated and exported for the rest of the app: `FormatTS`, `Now`,
  `TSLayout`, `SetSettingInTx`, `InQueryChunk`, `AuthUser`, `NewID`,
  `MigrateLegacyAuthToken`, and the `ErrLastUser` / `ErrUserNotFound`
  sentinels (moved in from `auth.go`; `NewID` moved in from `probe.go`).
- **Alias dropped, references qualified** (commit 054f425). The
  temporary `type DB = store.Store` alias used to keep the move
  mechanical is removed; every remaining reference is now
  `store.Store`, so the package boundary is explicit in the source.
- **Docs** (commits cb180ba, 23d4ebe). `docs/DECISIONS.md` records the
  pilot outcome and closes the package-structure thread: the full
  split into further internal packages is **not planned work** at
  current scale; the accepted operational costs (test-swapped-global
  capture rule, no `t.Parallel()`, ~4-min `-race` gate) are the
  standing state, and the former revisit triggers are a re-litigation
  clause, not a watchlist.

## Verification

Both code commits gated green on the release gate box (Go 1.26):
`gofmt` clean on all touched files, `go vet` linux + windows clean,
`go build` ok, full `go test -race ./...` at the 241.6s baseline
(238–239s) with zero failures. The `internal/store` package carries
its own 4 test files (~880 LOC) that moved with the code.

## Notes for operators

- No config changes, no data migration, no API changes — the SQLite
  schema and every endpoint are byte-for-byte identical to v0.4.2.
- Self-update signing (ed25519) is unchanged; existing clients verify
  v0.4.3 as usual.

## Assets

- `pulsemon-linux-amd64`, `pulsemon-linux-arm64` (+ sha256 sidecars + `.sig`)
- Windows assets added by the `windows-release.yml` workflow on tag push
  (`pulsemon-windows-amd64.exe`, `pulsemon-setup-0.4.3.exe` + sidecars + `.sig`)
