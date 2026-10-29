# Design decisions and rejected alternatives

Home for the WHY behind non-obvious code: rationale, rejected
alternatives, and measured numbers. In-code doc comments state the
CURRENT CONTRACT only and link here by entry name
(`docs/DECISIONS.md → <entry>`). Commit messages carry the change
history; this file carries the decisions that outlive it.

## Review ID map

Code and tests cite review-batch IDs. Resolution map (batch → commit,
all on the release branch):

| ID | What it was |
|----|-------------|
| M1b | TOCTOU: config read outside the lock could respawn a stale config — closed by Restart's immediate-sync + under-lock re-read (v0.3.21) |
| M2 | The respawn design: Restart = cancel + delete + next syncSensors pass (DB is source of truth) |
| M5 | Per-probe fresh TLS handshake (`req.Close`) so the displayed cert/expiry is never from a pooled conn's original handshake |
| N4 | Close the conn on EVERY HTTPS redirect hop (not just host/scheme-changing hops), same pooled-stale-cert reason as M5 (v0.3.22) |
| F7 | Alert-consumer idle exit (goroutine leak per deleted sensor) (v0.3.25) |
| F10–F15 | v0.3.25 review batch: SMTP creds untrimmed, single-label hosts, RTT from conn-established, cert exact-hostname, visibility-gated pollers, Linux -race CI |
| F28 | SetPaused's kick fast-path: resume wakes the loop's select immediately instead of waiting out the held timer |
| g5 | Resolve DNS under the probe's context (a hung DNS is bounded by the probe timeout, not on top of it) |
| 2026-10-24 m1 | Shutdown ordering: HTTP server first (in-flight requests see a live DB) |
| 2026-10-28 n2/n4 | Mention neutralization scoped to Markdown; names escaped / URLs verbatim in cards |
| 2026-10-28 n5 | Clone clamps legacy out-of-range params to new-write floors |
| 2026-10-28 n7 | alertGateConsumer timer lifecycle — adjudicated non-bug, see `alert-gate` |
| 2026-10-28 n9 | /api/tags + /api/events bare patterns — adjudicated non-bug, see `bare-routes` |

## restart-respawn (probe.go `Restart`)

**Contract:** Restart cancels the loop, deletes its state, and signals an
immediate syncSensors pass; the respawn is the next pass, which re-reads
the row under `pw.mu`.

**Why signal + next pass (M2), not re-spawn in Restart:** the DB is the
source of truth and `deriveStatus` re-derives state from probe history,
so the respawn only needs fresh config. Doing it in the sync pass keeps
one code path for all respawns (initial start, resume, maintenance-mode
end, config edit) and makes duplicate loops structurally impossible:
spawn is guarded by `if _, ok := pw.loops[id]; !ok` under the same lock
that deletes.

**CRITICAL invariant — every loop is a child of Run's ctx.** Run's
shutdown does `case <-ctx.Done(): pw.wg.Wait()` and relies on every loop
exiting at its next select. Spawning with
`context.WithCancel(context.Background())` (a proposed review fix)
severs that: the Background-parented loop is never cancelled, so
`wg.Wait()` hangs forever for any sensor that was ever restarted — the
process can no longer shut down or close the DB. Any future change that
spawns loops must keep them children of Run's ctx.

**Concurrency note (rejected concern):** there is no duplicate-loop race
and no map race. `pw.loops` is guarded by `pw.mu` at every access;
`syncSensors` runs on a single goroutine (only Run's first pass + its
ticker); an old loop's `ctx.Done()` cleanup just returns and never
touches `pw.loops`. The only real overlap (old loop mid-doProbe when the
new one spawns) writes one shared `*ProbeState` under the mutex.

**Immediate-sync extension (M1b closure):** the sync request rides the
`syncReq` channel (non-blocking; a queued request is enough), so a
config edit no longer waits out the 5s tick, and the respawn branch
re-reads the row under the lock so a sync pass that started before the
commit cannot respawn a stale config.

## stagger (probe.go `staggerPhase`, `respawnFirstTickCap`)

**Contract:** first tick = deterministic per-sensor phase in
[250ms, interval+250ms); respawned loops cap the first tick at 1s.

**Why stagger:** without it, sensors added together (or sharing an
interval) fire on the same wall-clock second — a write thundering-herd
against SQLite. Spreading phases turns N simultaneous writes into N
writes across the interval.

**Implementation invariant:** the modulo MUST be done in uint64 BEFORE
converting to a Duration — converting the raw FNV hash first makes ~half
of all ids negative (>= 2^63), which fires the timer immediately and
defeats the stagger. The 250ms floor keeps probes out of the first
instant.

**Respawn cap tradeoff:** a full stagger for a RESPAWNED loop (resume
after a >5s pause, maintenance-mode end, config edit) would leave the
sensor dark for up to a whole interval — an hour on an hourly sensor,
with no data/status/alerts. Capping at 1s keeps the anti-herd property
where it matters (N sensors respawning together land across ~1s, not
the same instant) while bounding resume/edit delay.

## probe-tls-verify (http.go `probeDialTLS`)

**Contract:** the probe client verifies the server cert DURING the
handshake (dial + handshake + `verifyHTTPCert` in one
`DialTLSContext`), before any request bytes are written, on every hop.
Policy: system-trusted OR genuine self-signed matching the target.

**Why verify at dial time, not post-Do:** the old order sent the full
request — including an `Authorization: Basic` header auto-derived from a
`user:pass@` target's userinfo (DEFERRED.md documents such targets) —
to whoever answered the handshake before the cert was judged. An
ARP/DNS spoofer collected the credentials while the probe "correctly"
read lost. Same for every redirect hop (the post-hoc check judged only
the final hop's cert).

**Why not `tls.Config.VerifyConnection` (rejected, Go 1.26):** the
client's `ConnectionState.ServerName` is the SNI name, and
`hostnameInSNI` (crypto/tls, RFC 6066 §3) blanks IP literals —
`cs.ServerName` is `""` for every `https://IP` target, so that hook
would reject all IP-literal probes. Verified empirically on Go 1.26.8
(pinned by `TestVerifyConnectionServerNameBlanksIPLiterals`). The dial
address carries the host the URL asked for, so dial-time verification
judges each hop against exactly the right host.

**`InsecureSkipVerify` stays on** in the dial's config so the stdlib
chain check never rejects first; `verifyHTTPCert` is the sole cert
policy. The failing leaf rides back on the typed `certVerifyError` so
`certNotAfterFromErr` keeps the card's expiry note alive on a failed
verify.

## probe-redirect-guard (http.go `redirectTargetAllowed`)

**Contract:** same-host hops pass; cross-host hops are refused if ANY
resolved address is in a never-monitorable range (loopback, link-local
incl. cloud metadata, unspecified, multicast, webhook blocklist; CGNAT
under the `PULSEMON_ALLOW_CGNAT` opt-out). RFC1918/ULA cross-host hops
pass.

**Why RFC1918/ULA stay allowed (rejected "fix"):** the INITIAL target is
not IP-checked at all — it is the operator's own configured sensor, so
anyone who can create a sensor can already point a probe straight at a
LAN device as the first request. The redirect path grants no additional
reach; it duplicates a capability the tool has by design. A blanket
`ip.IsPrivate()` block would regress the pinned legitimate case (a
public hostname served via split-horizon DNS to a LAN IP, or an external
URL 302-ing to an internal dashboard) while shrinking the real attack
surface by zero. The guard's actual job — stopping an EXTERNALLY
monitored public host from 302-ing the probe into cloud metadata,
loopback, or reserved space — is what it does. This is a
single-operator LAN tool: the person who can create a sensor owns the
whole LAN's monitoring surface. See `TestRedirectTargetAllowed`
("LAN redirect stays allowed").

**Known limitation (accepted):** resolution here has a TOCTOU window the
webhook path closes by pinning its dial to the checked IPs. The probe
dial (`probeDialTLS`) does not pin: the initial target is
operator-configured, and redirect hops are vetted before their dial. A
rebinding attacker would need DNS control on the LAN — the same threat
the cert verification itself defends against.

## alert-gate (alerts.go `enqueueAlert`, `alertGateConsumer`)

**Contract:** one FIFO (8-slot buffer) per alerting sensor; the consumer
drains it and exits after `alertGateIdle` (10 min) with no queued jobs,
deleting its map entry only if it still owns it.

**Why idle exit (F7):** the channel is never closed (an in-flight
sendWebhook sending on a closed channel panics), so a `for range ch`
consumer lived forever — one goroutine leaked per deleted sensor for the
process lifetime. Idle exit reaps consumers of quiet sensors; the next
alert re-creates the gate (no deaf sensors).

**Why one critical section:** the map read, gate creation, and send are
under `alertMu` together — the consumer's idle-exit check runs under the
same lock, so it can never observe an empty queue while a send is in
flight (that window would orphan the job: a silently dropped alert). The
send is a NON-BLOCKING select: holding `alertMu` across a blocking send
parked the caller under the GLOBAL lock on a full buffer.

**Why the idle duration is captured in `enqueueAlert` and passed as a
param:** the consumer must NOT read the `alertGateIdle` package var
itself — a test shrinks the var and restores it in `t.Cleanup`, and a
consumer spawned near test end can be unscheduled past that restore;
reading the var concurrently with the restore is a data race (caught by
-race, 2026-10-23). In production the var is never mutated, so the
capture is invisible there.

**Timer lifecycle (n7, adjudicated non-bug 2026-10-28):** the idle timer
is local to the consumer goroutine — `enqueueAlert` only pushes to `ch`
and holds `alertMu`, never touches the timer — so the
Stop/drain/Reset sequence is sequential, not racy, and is the complete
canonical drain-then-Reset pattern (a Reset without draining a fired
value leaves a stale ready in `idle.C` read as a spurious idle-fire).
The only loop exit is the `return` in the `<-idle.C` branch, entered
only after the timer fired AND its value was read — so no
fired-but-unread timer remains at exit, and a `defer idle.Stop()` would
be a guaranteed no-op. Rejected: adding the no-op defer (speculative
code implying a concern that isn't real).

## bare-routes (api.go `/api/tags`, `/api/events`)

**Contract:** these two routes use BARE (method-less) patterns; the
handlers switch on `r.Method` and return a JSON 405 for unregistered
methods.

**Why bare (n9, adjudicated non-bug 2026-10-28):** the route table ends
with a method-less `/` catch-all (`handleStatic`), which matches EVERY
method. With method-prefixed `GET /api/tags`, an unregistered method
(e.g. POST /api/tags) does NOT earn ServeMux's canonical 405 + Allow —
the `/` catch-all wins the match and `handleStatic` returns a plain HTML
404. Converting would REGRESS the JSON 405 into an HTML 404 (405→404 is
semantically worse) and gain none of the 405+Allow (the catch-all
suppresses it). Verified empirically against a `/`-catch-all mux on Go
1.26.9: a minimal mux with only method-prefixed routes returns canonical
405+Allow; the same routes plus a `/` catch-all return 404 with no
Allow. The handler-level JSON 405 is the correct form under this
architecture.

**Inline admin check on the DELETE branches:** behaviorally identical to
a route-level `requireAdmin` (both stand down with auth off, and
`authGate` 401s a sessionless `/api/` request before the mux, so the
missing-session difference is unobservable dead code). No benefit to
moving it to the route.

**General lesson (mux architecture):** Go 1.22+ ServeMux's automatic
405+Allow for method-prefixed patterns only materializes when NO
method-less pattern matches the same path. A top-level `/` static
catch-all suppresses it for every method-prefixed route.

## fast-retry floor removed (probe.go `sensorLoop`, 2026-10-29)

**Contract:** an ERROR sensor re-checks every `min(30s, interval)` —
never faster than the user's pace, never slower.

**Why the old 10s floor went:** it made 5–9s sensors re-check *less*
often while down (5s sensor → 10s cadence), slowing recovery detection
and contradicting the fast-retry contract. It protected no load bound:
the `min(30s, interval)` cap ALONE guarantees the fast path is never
faster than the user's pace, so a total outage adds no load beyond the
normal probe rate for sub-30s sensors (longer-interval sensors re-check
at 30s — the only increase, by design). The floor only ever affected
sub-10s intervals, where `min()` already returns `interval`. All write
paths enforce `minIntervalS = 5` (POST/PUT validation, clone clamp), so
a legacy sub-5s row (DB surgery) in error re-checks at its own normal
pace — not a ping storm. Pinned by
`TestSensorLoopFastRetryMatchesInterval`.

## deriveStatus window (status.go)

**Contract:** window loss% is computed over the newest `statusWindow`
(= 8) probes — the same window the inspector displays, so the badge and
the inspector number agree. The read fetches `max(statusWindow,
down_after)` rows; the extra rows feed only the consecutive-loss test,
never the loss% math.

## package-structure (repo-wide) — DEFERRED, decision 2026-10-29

**Status:** single `package main` (~15k LOC production, 154 .go files)
with mutable package-level test seams (`probeTarget`, `alertGateIdle`,
`stormBudget`, `readerRestartDelay`, `reexecBindDeadline`, …) that tests
swap and restore in `t.Cleanup`.

**Decision: KEEP as-is for now; the split into internal packages
(store, probe/icmp, probe/http, stats, alert, auth, api) with injected
dependencies is DEFERRED as a project, not a review-batch fix.**

**Costs accepted (known, mitigated):**
- Swappable globals are a -race hazard by construction: a consumer
  goroutine that reads a swapped var can outlive the test's restore
  (the `alert-gate` capture rule exists because of a real -race hit).
  Standing rule: any new test-swapped var must be captured into a
  parameter at spawn time, never read by long-lived goroutines.
- No `t.Parallel()` anywhere: the shared globals make parallel tests
  unsafe. Test time is the price (~4 min full -race).

**Why not split now:** the split touches nearly every file and every
test seam, with regression risk across a 70+-test-file suite that is
currently -race-green on a steady release cadence. For a single-binary
homelab tool with one operator, the expected value of the split (faster
tests, compile-time dependency clarity) does not yet justify that risk.
The readability half of the finding IS addressed: rationale and
rejected alternatives live in THIS file, and in-code comments state the
current contract only.

**Revisit trigger:** if test time becomes a real bottleneck (the suite
doubled again), if a globals-related -race hit recurs after the capture
rule, or if a second developer joins the project.
