# v0.2.8

A small hardening + hygiene release. No change to probing, status
derivation, alert routing, or the dashboard layout.

## Changes

- **Update-banner buttons: single-quote-safe escaping.** The "dismiss" and
  "undo" buttons in the update-available banner now build their inline
  `onclick` handlers with `escJs()` instead of `esc()`. `escJs()` also escapes
  single quotes, which is required for a value interpolated into a
  single-quoted JS string literal. The affected values (the running/latest
  version strings) are build-controlled today, so this is defense-in-depth
  and pattern-consistency with every other user-value handler in the UI — not
  a fix for a reachable bug.

- **Logout now fully clears the session cookie.** Logging out sets the
  `pulsemon_session` cookie with a past `Expires` (epoch 0) so the browser
  drops the cookie outright, rather than leaving an empty-valued cookie with a
  30-day future expiry. The session was already invalidated server-side on
  logout (the gate 401s a stale cookie); this makes the cookie deletion
  explicit for browsers that retain empty-valued cookies.

- **compose.yaml: drop the dead version build-arg.** The `build.args V: v0.2.0`
  entry did nothing — the Dockerfile stamps the version from the `VERSION`
  file, not from a build arg — so it was removed in favor of an explicit
  `build: .` context.

## No behavioral change

ICMP/HTTP probing, the in-memory stats cache, status derivation, the
multi-provider alert path, auth, and the dashboard UI are all unchanged. The
full test suite passes under `-race`.
