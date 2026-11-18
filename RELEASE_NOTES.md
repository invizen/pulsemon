# pulsemon v1.1.15

## What's new

Auth hardening batch: three related fixes that close the gap between the
login throttle and the "must not be a free online password-cracking target"
contract the code itself states, plus the auth-off data-exposure vector.
Every fix is regression-pinned with sabotage-verified tests and a full
`-race` gate. No DB changes.

### Security: paced login guessing can no longer outrun the lockout
The per-username limit only watched a rolling 60-second window (7 fails →
5-minute lockout), so an attacker pacing 6 guesses a minute stayed under the
threshold indefinitely — ~8,640 guesses/day/account, enough to crack a
common-list password within days. A second, slower per-username budget now
runs alongside it: 30 failed checks in an hour locks the account for an hour.
The budget persists across 5-minute rolling lockouts (the rolling expiry
wipes the rolling window, not the hourly budget), so 7-fail bursts every 6
minutes (~70/hr) can't outrun the cap. The operator is unaffected: their
known-good (account, IP) pair is already exempt from the per-username layer,
and a successful login clears the budget.

### Security: the most common passwords are rejected at account creation
The 8-character minimum alone still admitted "password" and "qwerty123" —
the first entries of any cracking list. Account creation (CLI
`auth-user add` and the API, both through the single `AddUserMode` choke
point) now rejects a curated list of the most-frequent passwords with a
clear 400, before the bcrypt KDF. The list is a creation-time deterrent,
not the security boundary — the hourly login budget is.

### Security: auth-off installs no longer leak sensor targets and settings to rebinding
On an install with auth turned off, `PULSEMON_ALLOWED_HOSTS` gated only
POST/PUT/PATCH/DELETE — a DNS-rebinding page (whose domain the browser treats
as same-origin) still read `GET /api/sensors` (targets with `user:pass@`
credentials) and `GET /api/settings` (SMTP user, from/to, Telegram chat ID).
The allowlist now applies to every `/api/` request from a non-allowlisted
Host — reads included — with `/api/healthz` (the container healthcheck) and
the data-free static UI unaffected. When the allowlist is unset the LAN-trust
default stands, and a startup warning now names that exposure so an operator
who forgot the allowlist sees it.

## Verification
- Full `-race` on the release tree, zero data races, no failures.
- Each fix carries dedicated regression tests, sabotage-verified (the test
  fails when the fix is reverted).
- Rationale for every decision: docs/DECISIONS.md
  (`login-hourly-budget`, `password-common-blocklist`, `auth-off-rebinding`).
