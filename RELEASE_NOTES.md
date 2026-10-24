# v0.3.27 — Full-list review hardening (25 fixes: 9 Major + minor, nit, and tail batches)

The complete v0.3.26 code-review checklist, worked end to end: nine
Major findings, five Minor/hardening areas, thirteen nits, and the full
tail list — every item verified against the real code first, fixed, and
pinned with regression tests. Gated per batch with gofmt, `go vet`
(including GOOS=windows), Linux + Windows builds, JS syntax/semantic
checks on the dashboard, and the full `-race` suite
(final: `ok pulsemon 218.8s`, zero failures).

## Major (9)

- **Self-update watchdog actually guards now** (`c5585a7`). The
  dashboard-triggered restart watchdog could never do its job: the
  server held the update lock across the spawn, so the detached
  guardian exited instantly (verified empirically), and health polling
  started while the OLD process still answered healthz — false
  "healthy". The watchdog now waits for the old PID to exit, retries
  the lock with backoff, then polls health. A broken update gets a
  real guardian and a real rollback.
- **`warmStats` selects the `manual` column** (`df98562`). After every
  restart, "Pulse Now" rows re-entered loss/status aggregates for up
  to 24h — one manual pulse could trip `down_after` and fire a false
  alert. Now excluded on the warm path like every other reader.
- **Dashboard pollers start after login** (`e12a37c`). On auth-on
  installs the dashboard was a frozen snapshot until manual reload;
  the update pill never appeared.
- **Inspector RTT graph survives outage onset** (`51fd7e7`). An
  all-lost first bucket produced a path starting with `L` — per SVG
  spec the entire line+area vanished silently. Now one subpath per
  contiguous run; interior gaps read as gaps.
- **Storm flush tracked at arm time** (`5385b20`). The untracked flush
  goroutine raced shutdown's WaitGroup (runtime-panic class) and
  silently dropped queued storm summaries.
- **Windows dgram reader supervised** (`a66e409`). A reader death used
  to read as 100% loss on every ICMP sensor until restart; now
  supervised like the Linux twin.
- **Legacy auth_token kept on failed migration** (`65f15dd`). Old code
  destroyed the credential when migration failed — auth-off installs
  could lose their token with no recovery.
- **`ImmediateTx` rescues the pooled connection** (`7ec9620`). A
  failed COMMIT or panic left a zombie write transaction on the
  pooled conn, wedging ALL writes until restart.
- **Clear-history deletes batched** (`f90f1f5`). The mass delete held
  the WAL write lock for seconds; now chunked and retryable with the
  state-consistency steps atomic.

## Auth & validation

- Users roster is admin-facing **server-side** (`b777463`) — non-admin
  sessions see only their own row (the panel hid it client-side; not a
  boundary).
- Unclaimed installs: the setup POST now throttles **before bcrypt**
  (`b777463`, `2e9affa`) — unlimited-cost KDF from any LAN host is
  gone; free (pre-KDF) rejections are refunded so floods can't lock
  the operator out of claiming the install.
- Per-host throttle buckets for CGNAT/overlay space (`2e9affa`) — no
  more collateral lockout of 256 tailnet peers.
- `DELETE /api/tags` admin-gated (`2e9affa`).
- Target/URL length caps (253 / 2048) (`874ec70`) — shape passed but a
  1 MiB-body target echoed into every alert.
- Log lines neutralized: CRLF/control chars stripped at the single
  `respondInternal` choke point (`7fead81`) — no log forging via ids
  or tags.
- Throttle/session sweeps rate-limited with a hard memory cap
  (`1fc8986`) — O(n²) map walks under spray gone.
- Session cookie `Secure` pinned at mint and carried through renewal
  (`1fc8986`) — one non-XFP request can no longer silently downgrade
  an active session.

## Concurrency & robustness

- **Settings TOCTOU closed** (`ddb54a0`): two concurrent admin PUTs
  could jointly commit `tls_mode=none` with credentials stored.
  Re-checked inside the write transaction, with the write lock pinned
  at `BeginTx` so collisions wait-then-400 instead of failing with
  `SQLITE_BUSY_SNAPSHOT` 500s.
- Probe DB writes bounded (8s) and ctx-aware; `warmStats`/`purgeOld`
  stop on shutdown (`874ec70`).
- Maintenance pause snapshot read inside the transaction (`a699b63`) —
  sensors can no longer escape the pause in the read/commit gap.
- Alert goroutines recover panics (`874ec70`) — one poisoned payload
  no longer crashes the monitor or wedges a sensor's alerting forever.
- `doProbe` zero-`timeout_ms` fallback (`874ec70`) — legacy rows no
  longer read 100% loss while Pulse Now works.
- `recordProbe` clamps out-of-order timestamps (`874ec70`) — the
  ts-monotonic invariant the windowed stats depend on can't break.
- `syncSensors` closes its cursor before the lock section and deletes
  orphan state for rows that vanish mid-pass (`874ec70`).
- `SensorTagsFor` query failures logged, not swallowed (`0bd6508`);
  warm-up no longer drops Pulse-Now rows recorded mid-warm (`0bd6508`).

## Network & update path

- Webhook cleartext (`http://`) requires **every** resolved address
  private (`ab77816`) — a mixed public/private A-record host can no
  longer receive the provider token in cleartext.
- SSRF list corrected: `2002::/16` is 6to4 (comment), and Teredo
  (`2001::/32`) — the actual tunnel-embed bypass — is now blocked
  (`ddb54a0`).
- Raw-ICMP demux requires the probe payload prefix (`874ec70`) — closes
  the 1/65536 cross-talk window with other ping processes.
- SMTP addresses re-checked at SEND time (`ddb54a0`): stored values
  predating save-time validation can no longer forge headers with
  CR/LF.
- Update 5xx responses redacted (`dfb6f8c`) — upstream URL/DNS/proxy
  detail goes to the log, not the response body.
- Install hashes the exact staged bytes before touching the
  destination (`dfb6f8c`) — closes the verify/copy TOCTOU.
- No power-loss hole: `.prev` is a hardlink, the binary name never
  stops existing mid-swap (`14a5b32`); destination permission bits
  preserved (forced 0755 widened e.g. 0750) with owner-exec
  guaranteed; GOARCH override mismatch logs loudly;
  `PULSEMON_WATCHDOG_TIMEOUT` tunes the health budget (5s–5m) (`dfb6f8c`).
- Windows service posts `StopPending` with a 10s hint (`14a5b32`) —
  the SCM's 5s kill timer can no longer cut the ~30s drain on box
  shutdown. `pulsemon restart` systemctl calls bounded (`ddb54a0`).
- TLS settings: the false crash-safety comment corrected and a
  mismatched cert/key pair after a failed rename is logged loudly
  (`ddb54a0`).

## Dashboard

- **Fixes a break introduced post-v0.3.26** (`ecba719`): a syntax
  error had landed in `renderTable` (a raw template fragment spliced
  into a string-concat chain) — the dashboard built from that commit
  rendered blank. Restored with the intended neutral-color no-data
  behavior kept.
- Every dynamic id in inline handlers escaped (`s.id` ×12 → `escJs`,
  provider kind ×3 → `escJs`/`esc` with symmetric read-back)
  (`ecba719`, `1245f65`); overlay sub escaped; release-notes hrefs
  scheme-allowlisted (`9927147`).
- Pulse Now button re-enables on failed pulse (`265eaef`); delete
  confirm survives the 5s poll (id-keyed re-arm + outside-click
  cancel) (`ecba719`); Loss column colors the hour figure it displays
  (`ecba719`); keystroke re-renders only for search (`ecba719`).
- `esc()`/`escJs()` total for `0`/null/numbers (`9927147`); alert
  scope picks survive a scope switch (`9927147`).

## Notes for operators

- Two documented, deliberate limits from the review: a server-side
  GOARCH env mismatch warns loudly rather than refusing (it stays an
  operator knob), and the TLS settings install keeps its flat-rename
  contract — the crash window is now loud instead of auto-recovered.
- New env var: `PULSEMON_WATCHDOG_TIMEOUT` (optional, clamped 5s–5m,
  default 30s) for slow-but-healthy starts on large databases.
- Update semantics unchanged: auth-off installs remain fully open by
  design.

## Assets

- `pulsemon-linux-amd64`, `pulsemon-linux-arm64` (+ sha256 sidecars)
- Windows asset added by the `windows-release.yml` workflow on tag push
