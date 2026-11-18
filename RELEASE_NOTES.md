# pulsemon v1.1.15

## What's new

Eleven external-review findings plus four nits from the 2026-11-17 → 11-18
review batches. A mix of auth hardening, probe correctness, API strictness,
and performance — every fix regression-pinned with tests and a full `-race`
gate. No DB schema changes.

### Auth hardening
- **Hourly login budget + common-password blocklist** (findings #1–2): a
  rolling hourly budget caps brute-force beyond the per-IP lockout, and a
  blocklist of common passwords rejects weak first-install / user passwords at
  the door.
- **Auth-off rebinding gate** (findings #1–2): with auth disabled, the first
  `auth-user add` is gated so the port can't be silently re-bound to a new
  account.
- **Bootstrapped() latch** (finding #6): the auth gate no longer queries the
  DB for bootstrap state on every request — a one-way ratchet caches the true
  value and never re-reads a false one.

### Probes
- **Fleet-wide Pulse Now cap** (finding #7): a shared in-flight semaphore
  (cap 8) bounds aggregate concurrent Pulse Now probes; when full it's a 429,
  not an unbounded fan-out of outbound connections.
- **ICMP timeout now bounds DNS** (nit): `pingHost` wraps its context in the
  probe timeout, so the DNS lookup and the reply-wait are bounded TOGETHER — a
  30s ICMP Pulse Now can no longer run ~5s long and outlast the server's
  WriteTimeout, leaving the client nothing.
- **probeTCP nil-IP guard** (nit): an IPv6 literal in a hand-edited row is a
  clean loss, not a dial of `":port"` (localhost).

### API
- **Strict JSON decode** (nit): all nine request decoders now reject unknown
  fields, so a misspelled PATCH field is a 400 instead of a silent no-op.
  Frontend payloads verified field-exact, so nothing breaks.
- **Gzip responses** (finding #8): `/api/` responses are gzipped for clients
  that accept it.
- **Uniqueness by result code** (finding #10): duplicate-name / duplicate-user
  violations are detected by SQLite result code, not message text.
- **Batched delete cascade** (finding #5): sensor delete batches the large
  `probes` / `events` sweeps so the WAL write lock isn't held across the whole
  cascade.
- **Store dedup + context** (finding #11): the 3× copy-pasted sensor column
  list is deduped; `RemoveUser` threads the request context through the
  delete + last-admin promotion.

### Stats
- **Warm paused sensors at startup** (finding #3): paused sensors' history is
  warmed on boot too, so a paused-then-resumed sensor doesn't show a gap.

### Hygiene
- **Comment corrections** (finding #4): stale / garbled comments fixed
  (comment-only).
- **Graph/uptime pin + package-split re-adjudication** (finding #9): the
  restart → 24h graph + uptime path is pinned; the package-split proposal is
  re-rejected on the record.

---
Full `-race` suite green. No DB schema changes.
