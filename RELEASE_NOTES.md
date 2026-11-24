# pulsemon v1.2.0

## What's new

Windows in-dashboard update now stages the binary — you restart the
service. One commit since v1.1.22 — no DB schema changes.

### Windows: staged in-dashboard update
- The dashboard update button downloads the new binary, verifies it
  (ed25519 signature + SHA-256), atomically swaps it in, and then
  **tells you how to restart the service** — the service no longer
  restarts itself.
- Why: the Windows service runs as `NT SERVICE\Pulsemon` (a virtual
  service account) that Windows mandatory-integrity policy forbids from
  starting or stopping its own service. The previous
  exit-code → service-recovery-action handoff proved unreliable in live
  testing (the update hung between the HTTP response and the process
  exit).
- The response carries a restart hint: services.msc → Pulsemon →
  Restart service, or `Restart-Service Pulsemon`. The new binary takes
  effect on the next service start.
- Unchanged: the installer's on-failure recovery action (crash safety
  net), `pulsemon update --restart` / `pulsemon restart` from an
  elevated console, and the rollback watchdog.

### Linux
- No change — the systemd install path still self-updates
  automatically (202 → restart → new version).

---
The change is regression-pinned (Go + source-shape test pins) and gated
on the full `-race` suite (Go 1.27.4) + CI.
