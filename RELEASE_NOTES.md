# v0.4.1 — HTTPS probe SNI fix + strict-CSP dashboard fix

A patch release that fixes two regressions introduced in v0.4.0. No new
features; both changes are correctness fixes for behavior that broke on
update. Gated with `gofmt`, `go vet` (incl. `GOOS=windows`), `node --check`,
the CSP + SNI regression tests, and the full `-race` suite.

## HTTPS sensors failing after v0.4.0 (the headline)

- **HTTPS probes now send SNI** (`http.go`). v0.4.0's new dial-then-verify
  TLS path (`probeDialTLS`) built the manual TLS client with
  `InsecureSkipVerify: true` but **no `ServerName`**, so no SNI was sent.
  SNI-dependent frontends — Cloudflare in particular — reject a SNI-less
  handshake with `remote error: tls: handshake failure`, which put
  Cloudflare-fronted HTTPS sensors (e.g. `invizen.com`, `pulsemon.net`) into
  a permanent `error` state even though the host was reachable. The fix sets
  `ServerName: host` so the correct virtual host is selected. IP-literal
  targets are unaffected: Go blanks SNI for IPs and `verifyHTTPCert` judges
  the IP SAN as before.
- **Regression-locked** with `TestProbeHTTPEndToEndSNIRequired`: a TLS test
  server whose `GetCertificate` *requires* a matching SNI and fails
  otherwise. The probe only passes if it sends SNI. Sabotage-verified —
  removing `ServerName` makes the test fail.

## Dashboard: strict CSP restored, no inline handlers

- v0.4.0 shipped a strict CSP (`script-src 'self'; style-src 'self'`, no
  `unsafe-inline`) but the dashboard still generated **inline `onclick`
  handlers and inline `style="height:…"` sparkline bars** at runtime, which
  the strict policy blocks — so every control was dead and sparklines
  rendered at zero height. A stopgap (`'unsafe-inline'`) was deployed to
  unblock; this is the proper fix that removes the need for it.
- **Event delegation** (`web/app.js`, `web/index.html`): every inline
  `onclick="…"` is replaced with `data-act` + `data-args` (a JSON array of
  the handler's arguments) dispatched by a single delegated click listener.
  Handlers that took `this` receive the clicked element. Zero inline
  `onclick`/`onload`/`onerror` attributes remain.
- **Sparkline heights via JS, not inline style**: bars carry `data-h` and
  `layoutSparklines()` sets `el.style.height` from it, so no inline `style`
  attribute is ever written.
- **CSP re-tightened** (`api.go`): back to the strict
  `default-src 'self'; script-src 'self'; style-src 'self'; object-src
  'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` —
  the stopgap `'unsafe-inline'` is gone. The security-headers test asserts
  this exact string.
- Verified in a real browser under the strict policy: sensors render,
  per-sensor Edit opens a populated form (args pass through `data-args`),
  sparkline bars have non-zero heights, and an injected inline
  `style="…"` is confirmed blocked by the policy.

## Notes for operators

- **HTTPS sensors recover automatically** on update — no config change.
  Cloudflare-fronted and other SNI-dependent hosts will probe normally.
- **The dashboard is fully interactive again** under the strict CSP (edit,
  clone, delete, pulse, tags, settings, alerts, TLS, self-update, inspector).
- No config changes required. Self-update signing from v0.4.0 is unchanged.

## Assets

- `pulsemon-linux-amd64`, `pulsemon-linux-arm64` (+ sha256 sidecars + `.sig`)
- Windows assets added by the `windows-release.yml` workflow on tag push
  (`pulsemon-windows-amd64.exe`, `pulsemon-setup-0.4.1.exe` + sidecars + `.sig`)
