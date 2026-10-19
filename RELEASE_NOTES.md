# v0.3.19 — Windows self-update asset name fix

One-line fix (plus regression test) for the Windows self-update path.

## Fix

- **`pulsemon update` on Windows now finds the release asset.**
  `targetAsset()` built the asset name as `pulsemon-<GOOS>-<GOARCH>` —
  the Linux convention — so a Windows host looked for
  `pulsemon-windows-amd64` while releases publish
  `pulsemon-windows-amd64.exe`. The exact name-match found nothing and
  the update failed with "release … has no pulsemon-windows-amd64
  asset" even with the asset present. The asset name is now
  platform-shaped (`.exe` on Windows) via a pure, testable
  `targetAssetName(goos, goarch)`; the sidecar checksum
  (`…exe.sha256`) resolves through the same path.

This was latent because the update-path smoke tests ran on Linux; the
first real Windows self-update (v0.3.17 → v0.3.18) surfaced it.
