# pulsemon v0.2.3 — full-code-review fixes + the test suite goes public

This release ships the results of a full-codebase review (every Go file + the
dashboard), and — for the first time — the entire test suite is committed to
the repository. 163 tests across ~37 files, race-tested, including the
security tests that pin pulsemon's SSRF, auth, and certificate-verification
boundaries.

## Security fixes
- **Webhook blocklist: `0.0.0.0/8`.** On Linux the whole block routes to the
  local table, so `http://0.1.2.3/` reached local services while passing the
  old `IsUnspecified()` check. Locked by `TestCheckWebhookIPBlocksZeroEight`.
- **HTTP sensor redirect guard.** A monitored public host can 302 a probe
  anywhere — including cloud metadata (169.254.169.254) or loopback.
  Cross-host redirect hops are now resolved and refused when they land in a
  never-monitorable range (loopback, link-local, unspecified, multicast, or a
  webhook reserved range). Same-host hops and LAN-to-LAN redirects remain
  allowed by design. Locked end-to-end by
  `TestProbeHTTPCrossHostMetadataRedirectIsLoss`.
- **Update-flow hardening.** Pinned versions are validated against a strict
  tag-token shape before touching the releases URL (`validVersionToken`),
  `http.NewRequest` errors are checked instead of discarded, and asset
  downloads are capped at 512 MiB so a lying Content-Length can't fill the
  temp filesystem.
- **Webhook save path resolves DNS once.** The http-private-host check and
  the reserved-range check previously resolved separately and could disagree
  across a DNS rebind; both now judge the same answers.

## Reliability fixes
- **Restart-after-update no longer kills the process when the re-exec
  fails.** `reexec()` reports errors now; a bare-metal update that can't
  start the new binary leaves the old one running instead of SIGTERM-ing
  itself into downtime.
- **TLS-enable restarts are detected correctly.** The post-restart health
  wait tries `https://` before `http://` (self-signed accepted), so enabling
  TLS no longer looks like a failed restart.
- **ICMP engine shutdown is prompt.** `Engine.Close()` closes the raw socket
  before waiting for the reader goroutine, eliminating a shutdown stall of
  up to the read timeout.
- **`EngineMode()`/`EngineDead()` data race closed** (read the shared engine
  only after `sync.Once` initialization; found by `-race` review).
- **TLS settings apply atomically-ish**: a rejected certificate no longer
  silently changes the stored TLS port.
- **Update-check is outage-tolerant.** A GitHub failure now serves the last
  good result (`"cached": true`) with a 1-minute negative cache instead of
  erroring on every dashboard poll; `?refresh=1` bypasses both caches.

## Dashboard
- Update-banner dismiss/undo buttons now JS-escape the version strings
  inside their inline handlers (they were HTML-escaping in a JS string
  context — wrong layer).

## Tests go public
`*_test.go` is no longer gitignored. The suite includes the security
regressions named above plus the full behavioral lock (auth throttling and
XFF-spoofing defenses, cert verification semantics incl. IP SANs, SQLite
pool/deadlock and IN-chunking guards, alert dispatch, status derivation,
self-update flow). All pass under `go test -race`.

Test data now uses neutral `10.99.99.x` placeholders instead of home-LAN
address shapes.
