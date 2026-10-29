# v0.4.0 — Self-update release signing + external-review hardening

A security-hardening minor release. The headline change closes the
self-update **authenticity** gap: release binaries are now cryptographically
signed, so a compromised GitHub account or release pipeline can no longer
push a malicious binary that passes the update check. The remaining nine
commits are the 2026-10-29 external-review batch (probe security, session
lifetime, dashboard CSP, and probe-correctness fixes). Every finding was
verified against the real code first and is gated with `gofmt`, `go vet`
(incl. `GOOS=windows`), and the full `-race` suite.

## Self-update release signing (the headline)

- **Release binaries are now signed with ed25519** (`c69c2d0`). The client
  verifies a detached `.sig` asset against embedded trusted public keys
  (`release_pubkeys`) **before** installing. Verification is fail-closed: a
  missing, corrupt, mis-sized, or untrusted signature is refused. The SHA-256
  integrity check is kept as a second, redundant layer.
- **Why it matters:** the binary and its SHA-256 come from the *same* GitHub
  release, so a compromised account or pipeline could previously publish a
  trojaned binary **and** its matching SHA-256, and every client that updated
  would run it (code execution, often with ping privileges). A signature
  proves the publisher held the private key, which a compromised pipeline
  does not. This was the project's highest-impact residual risk.
- Both the CLI (`pulsemon update`) and the dashboard update button are
  covered (they share one verification path).
- **New maintainer commands:** `pulsemon sign genkey`, `pulsemon sign release
  <file> <keyfile>`, and `pulsemon sign verify <file>`.
- The Linux and Windows release pipelines now sign every binary and **fail
  the release if a binary is unsigned**; a `.sig` asset ships alongside each
  binary.

## Probe security

- **TLS certs verified during the handshake** (`3b70288`). The probe client
  now verifies the server cert *before* any request bytes are written (dial +
  handshake + verify in one step), on every redirect hop. Previously the full
  request — including an `Authorization` header auto-derived from a
  `user:pass@` target — was sent to whoever answered the handshake before the
  cert was judged, so an on-path spoofer could collect the credentials. Cert
  policy is unchanged (system-trusted OR a genuine self-signed match).
- **HTTP body drained only when the connection is reused** (`3397096`). An
  HTTPS probe forces a fresh handshake per probe, so its connection is
  discarded anyway — draining up to 1 MB of body was pure waste. The drain now
  runs only when the connection is kept and is capped at 64 KB.

## Access control

- **Sessions have an absolute 30-day lifetime** (`0cae5bb`). The 30-day TTL
  was a *sliding* inactivity window, so a continuously-active session (an open
  dashboard tab, or a stolen cookie used periodically) never expired — each
  poll slid the expiry forward by another 30 days. A session is now
  hard-capped at 30 days from login; only activity in between extends an idle
  session up to that cap.

## Dashboard

- **Strict CSP + precompiled Tailwind** (`a4725bf`). The CSP was only
  `frame-ancestors 'none'`; it is now a strict `'self'`-only policy (no
  `unsafe-inline`, no hashes) — the theme/app/CSS moved out of inline blocks
  into files so the policy needs no exceptions. Tailwind is precompiled to a
  static ~30 KB stylesheet at build time, replacing the ~400 KB in-browser JIT
  that regenerated CSS on every page load (not recommended for production).

## Probe correctness

- **Fast-retry matches the sensor interval** (`e8d8ff6`). An ERROR sensor
  re-checks every `min(30s, interval)` — the old 10s floor made 5–9s sensors
  re-check *less* often while down, slowing recovery detection.
- **Status window mirrors the badge** (`ffaa4d3`). Window loss% and
  sort-by-loss now use the same 8-*scheduled*-probe window as the badge (a
  manual "Pulse Now" no longer shrinks the denominator or floats a healthy
  sensor to the top of a loss-sorted list).
- **TLS cert hot-reload: no respin while broken** (`fe3ae49`). A failed cert
  reload now records the (broken) mtimes, so a busy TLS server no longer
  re-parses and re-logs on every handshake for as long as the files stay
  broken.

## Update check

- **`?refresh=1` throttled** (`75da4b2`). A forced update-check refresh is now
  ignored if the last fetch attempt was under 60s ago, so it can't be spammed
  into GitHub's unauthenticated rate limit (or used to block other callers
  behind the single-flight lock). The version check stays read-only; the
  actual update remains admin-gated.

## Docs

- **`docs/DECISIONS.md`** (`0c1b1c5`). Rationale, rejected alternatives, and
  the review-ID map for non-obvious code now live in a durable file; in-code
  comments state the current contract only.

## Notes for operators

- **Self-update is now authenticated.** If your install is on a release from
  before this one, its first update to a signed release works as usual (older
  clients only check the SHA). From this version on, an update is installed
  only if its signature verifies against the embedded key.
- No config changes are required. The signing public key is embedded in the
  binary; the private signing key is the maintainer's release secret and is
  never distributed.

## Assets

- `pulsemon-linux-amd64`, `pulsemon-linux-arm64` (+ sha256 sidecars + `.sig`)
- Windows assets added by the `windows-release.yml` workflow on tag push
  (`pulsemon-windows-amd64.exe`, `pulsemon-setup-0.4.0.exe` + sidecars + `.sig`)
