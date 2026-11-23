# pulsemon v1.1.19

## What's new

Windows service hardening and account-op re-authentication. Five commits
since v1.1.18 — no DB schema changes.

### Windows: Virtual Service Account (VSA)
- The Windows service now runs as `NT SERVICE\Pulsemon` (a per-service VSA
  with its own SID) instead of LocalSystem — least privilege, its own
  profile and data-dir ACLs.
- Native SCM restart replaces the PowerShell child process: the service
  restarts itself in-process, and `pulsemon.exe restart` works from a
  non-service console too.
- Live-verified on a Windows 21H2 box: service RUNNING as the VSA, ICMP
  probes working (24/24 up, 0% loss), ACLs correct, restart verified.

### Windows installer
- VSA ACL grants now run in the right order: data-dir ACLs apply AFTER
  `sc create` (the VSA SID does not exist until the service is
  registered), using a two-phase icacls (dir-only inheritable + explicit
  `/T`) so pre-existing file ACEs are not wiped.
- Fixes an upgrade-path crash loop: a single `icacls /T /inheritance:r`
  was stripping the ACL off an existing database file.
- The setup installer now ships an offline ed25519 `.sig` alongside its
  `.sha256` — the fresh-install authenticity anchor matches the
  self-update chain (the release asset set grows from 12 to 13).

### Auth: current-password re-auth for destructive account ops
- Adding a user (admin path), deleting a user, and disabling
  authentication now require the acting session's CURRENT password. A
  stolen session cookie can no longer win account-level decisions — mint
  a backdoor account, erase accounts, or strip the credential gate.
- The check shares the login gate's exact semantics: per-IP throttle,
  per-username failure budget (7 fails / 60s → 5-minute lockout),
  constant rejection delay, success clears the budget.
- The fresh-install bootstrap path is unchanged (no session exists by
  definition).
- UI: the add-user form gains a "Your password" field; remove and
  disable route through a current-password confirmation dialog.

---
Every fix is regression-pinned (new Go + frontend test pins) and gated on
the full `-race` suite (Go 1.27.4).
