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

## probe-body-drain (http.go `probeHTTP`, 2026-10-29)

**Contract:** `probeHTTP` drains the response body ONLY to let the
transport reuse a keep-alive connection, and only up to `drainBodyCap`
(64 KB). The drain runs only when the final connection is kept —
`!resp.Request.Close`.

**Why the `!resp.Request.Close` condition:** an unread body makes
`net/http` discard the connection, so the drain exists purely to enable
reuse. But an HTTPS probe forces a fresh TLS handshake per probe
(`req.Close = true`, cert freshness — see `probe-tls-verify`), so its
connection is discarded anyway and the drain was pure waste: a 5s HTTPS
sensor on a heavy UI (Proxmox, Nextcloud) pulled ~1 MB plus a full TLS
handshake every 5s. `resp.Request.Close` is the exact "will this conn be
kept" signal: `true` for HTTPS (fresh handshake), `false` for plain HTTP
and for redirect hops (net/http builds each hop as a fresh request that
does NOT copy `Close`), so an `http → https` redirect still drains only
its kept hops. The reviewer's `scheme == "http"` guard would have missed
that the FINAL hop's scheme, not the target's, is what decides reuse.

**Why 64 KB, not 1 MB:** far above any real health endpoint (a JSON
status is bytes; even a small HTML page is under this). A body over the
cap is closed unread — the connection is simply not reused (next probe
pays one handshake, the pre-keep-alive behavior) instead of downloading
the whole page.

**Test:** `TestProbeHTTPDrainsOnlyReusableConnections` (Linux-only; an
`SO_SNDBUF`-bounded listener makes the server's written-bytes counter
track the client's reads, not an autotuned multi-MB socket buffer).
Serves a 1 MB body and asserts the fixed probe writes far less than
512 KB. Fails on the pre-fix code (writes the full 1 MB on both the
HTTPS and HTTP subtests).

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

## status-window manual handling (stats.go `computeSensorStats`)

**Contract:** `status_loss_pct` is the loss over the newest 8 SCHEDULED
probes — the walk collects 8 non-manual entries by scanning back from the
newest (skipping manual), which is byte-for-byte what `recentFromCache` /
`deriveStatus` do. The inspector therefore shows the exact number the
badge came from.

**Why not "last 8 raw entries, then skip manual" (the pre-2026-10-29
code):** a Pulse Now inside the last 8 raw entries shrinks the scheduled
denominator below 8 (7, 6, …), so the inspector read a *different* window
than the badge — e.g. a loss at the 7th-scheduled position plus a newest
manual pulse read 1/7 = 14.3% in the inspector but 1/8 = 12.5% on the
badge. The differential test's SQL reference
(`WHERE manual = 0 ORDER BY ts DESC LIMIT 8`) already encoded the correct
8-scheduled window, which is why the in-memory path was the odd one out.
Pinned by `TestStatusWindowMirrorsDeriveStatusWithManualPulse`.

**Sort-by-loss (web/index.html):** the list's "sort by loss" now orders on
`hour_loss_pct` (past-hour, manual-excluded) — the same value the
grid/table loss column displays — instead of the raw 60-probe `loss_pct`,
which counts manual rows. A lost *diagnostic* pulse could otherwise float
a healthy sensor to the top of the list. The inspector's own loss readout
keeps `loss_pct` on purpose: it is the raw 60-probe history view ("N / M
dropped" over what you actually see), and manual rows belong there.

## tls-cert-hot-reload (main.go `hotReloadCert`, 2026-10-29)

**Contract:** the TLS listener's `GetCertificate` serves the pair at
(certPath, keyPath), re-loading it only when a file's mtime changes. A
failed reload (half-written file, transient mismatch) keeps the LAST GOOD
pair AND records the (broken) mtimes, so it is not re-parsed + re-logged
on every handshake for as long as the files stay broken — the reload is
retried only when a file's mtime changes again.

**Why record the mtimes on failure:** the pre-fix failure branch returned
the cached pair without updating `certMT`/`keyMT`, so every subsequent
handshake saw the changed mtime, skipped the cached fast path, re-ran
`tls.LoadX509KeyPair` (failing), and logged — a log-spam + parse cost on
every handshake of a busy TLS server, for the whole time the files stayed
broken. Recording the mtimes makes the broken state a no-op fast path
until the operator (or a cron) writes the files again. The initial-load
failure path is unchanged (no good pair to fall back to → handshake
error), and a repaired file (new mtime) retriggers the reload as before.
Pinned by `TestHotReloadCertNoRespinWhileBroken` (counts the reload-failure
log lines: 1 on the first broken handshake, 0 on 5 unchanged-broken
handshakes, 0 on the successful repair).

## session-absolute-max-age (auth.go, 2026-10-29)

**Contract:** a session's 30-day `authSessionTTL` is a SLIDING inactivity
window — `ValidSession` and `SessionUser` move `expiry` forward on every
live hit. `authSessionMaxAge` (30 days) is the ABSOLUTE cap counted from
login time (`authSession.created`, set once at mint, never slid). A session
past the cap is rejected and deleted on presentation even if its sliding
expiry is still in the future, and `sweepExpiredSessions` reclaims it too.

**Why the cap:** with the sliding TTL alone, a continuously-active session
never lapses — an open dashboard tab polls `/api/auth/status` every few
seconds (the `SessionUser` path) and each poll slides `expiry` out by 30
days, so an open tab, or a stolen cookie used periodically, stayed valid
indefinitely. The cap bounds total session lifetime at 30 days from login
for both idle and maximally-active sessions; only activity in between
extends an idle session up to that cap. The cap must be enforced on BOTH
`ValidSession` and `SessionUser` — `SessionUser` is the gate-exempt
`/api/auth/status` path, so fixing only `ValidSession` would let a
status-poll-only client slide forever. Pinned by `TestSessionAbsoluteMaxAge`
(29-day-old active session still valid; 31-day-old active session rejected
+ deleted by both paths; fresh session unaffected).

## update-check-refresh-throttle (update_check.go, 2026-10-29)

**Contract:** `GET /api/update-check` serves the GitHub releases lookup from
a 30-min in-memory cache. `?refresh=1` forces a fresh lookup, but only when
the last fetch ATTEMPT was at least `updateCheckRefreshMinInterval` (60s)
ago; a fresher refresh is ignored and served from the cache like a normal
poll. `updateCheckAttemptAt` records the last attempt (success OR failure),
not just the last success, so an outage can't be used to keep forcing calls.

**Why the throttle:** pre-fix, `?refresh=1` bypassed the cache unconditionally
(both cache-hit cases were gated on `!refresh`). Any authenticated user — or
anyone on the LAN when auth is off — could spam it: each refresh forced
`fetchRelease` while `updateCheckMu` was held (the single-flight lock), so
every other caller (including the 5s dashboard polls) blocked for up to the
10s client timeout, and rapid refreshes walked straight into GitHub's 60
req/hour unauthenticated limit. Keying the throttle on the last ATTEMPT (not
the last success) matters: `updateCheckAt` only advances on success, so a
60s throttle measured from it would never bind during an outage.

**Why not require admin:** the version check is read-only (it only reports
the latest release), and the actual self-update (`POST /api/update`) is
already `requireAdmin`-gated. Requiring admin for a read-only "check now"
would be an odd tightening and conflicts with the standing M4c posture of
keeping the update path low-friction on auth-off installs (no admin exists
there). The 60s throttle bounds the abuse without that friction. Pinned by
`TestUpdateCheckRefreshThrottled` (first check fetches; an immediate
`?refresh=1` is ignored — no new upstream hit; a `?refresh=1` after the
interval forces a fresh fetch).

## precompiled-tailwind-strict-csp (web/, api.go, 2026-10-29)

**Contract:** the dashboard is fully self-contained and ships **zero** inline
`<script>`/`<style>`. Tailwind is PRECOMPILED to a static stylesheet
(`web/vendor/tailwind.css`, ~30 KB) at build time by the Tailwind CLI
(`make css`, pinned `tailwindcss@3.4.17`), replacing the ~407 KB Play CDN
in-browser JIT that used to be vendored as `web/vendor/tailwind.js` and
generated CSS on every page load. The theme, app, and custom CSS live in
files — `web/theme.js`, `web/app.js`, `web/styles.css` — so the CSP in
`api.go` (`authGate`) can be strict with **no** `'unsafe-inline'` and **no**
hashes:

```
default-src 'self'; script-src 'self'; style-src 'self';
object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
```

**Why precompile:** the Play CDN JIT is explicitly not recommended for
production — it runs a ~400 KB compiler in the browser and regenerates CSS on
every load. Precompiling removes that client-side cost and, because the
output is a static same-origin file, makes a `'self'`-only CSP practical
(the JIT's inline `tailwind.config` script was one of the two inline blocks
that forced hashes/`unsafe-inline`).

**Why the strict CSP:** the escaping (`esc`/`escJs`) is consistent, but a CSP
is defence in depth for the one interpolation that's ever missed. With
`script-src 'self'; style-src 'self'` and no inline source, a reflected
payload has no `<script>`/`<style>` it can run from. `object-src 'none'`,
`base-uri 'none'`, and `form-action 'self'` are locked down;
`frame-ancestors 'none'` keeps the clickjacking guard. Every asset is local
(`go:embed web/*`, no CDN, no `data:` URIs), so `'self'` is the whole story.

**Regeneration:** `make css` runs the Tailwind CLI against
`web/tailwind.input.css` (config `web/tailwind.config.js`, which mirrors the
old inline theme extension — CSS-variable colors so the `.light` theme swap
keeps working — and safelists the ok/warn/bad status utilities composed in
`app.js`). The compiled `web/vendor/tailwind.css` is COMMITTED so the Go
build works without a Node toolchain; regenerate it after adding/renaming a
Tailwind class. `content` paths use `path.resolve(__dirname, …)` so they
resolve to `web/` regardless of the CLI's working directory.

**Pinned by:** `TestFix_g1_SecurityHeaders` (asserts the exact CSP string)
and `TestFix_csp_NoInlineScriptsOrStyles` (asserts the served `index.html`
has no inline `<script>`/`<style>` and references the external files — a
re-inlined block, which the CSP would silently refuse to run, fails the test).
Sabotage-verified: injecting an inline `<script>` before `</body>` makes
`TestFix_csp_NoInlineScriptsOrStyles` fail.

## release-signing (update.go, release_pubkeys, 2026-10-29)

**Contract:** a release binary is installed ONLY if its detached ed25519
signature (`targetAsset() + ".sig"`, resolved by name in `selectAssets`)
verifies against at least one of the embedded trusted pubkeys
(`release_pubkeys`, `go:embed`). Verification is FAIL-CLOSED — a missing
`.sig`, an undecodable/mis-sized signature, or one that matches no trusted
key is a refusal. After the authenticity gate, the SHA-256 is still checked
(GitHub digest, else the `.sha256` sidecar) as a redundant integrity net.
Both the CLI (`runUpdate`) and the dashboard (`handleUpdate`) go through the
shared `verifyDownloadedAsset`, so one choke point secures both paths.

**Why a signature (the authenticity root):** the SHA-256 proves the bytes
survived the download intact (integrity) but NOT who published them
(authenticity) — the binary and its SHA-256 come from the SAME GitHub
release, so a compromised account or pipeline publishes both and the SHA
check passes. A detached ed25519 signature proves the publisher held the
private key, which a compromised pipeline does not. This was the
highest-impact residual risk in the project (a compromised release → code
execution on every install that updates, often running with ping
privileges) and the documented self-update authenticity deferral is now
lifted (see `docs/DEFERRED.md` → "Self-update authenticity").

**Why sign the raw bytes, not a manifest:** the signature is over the
binary's exact bytes. A valid signature for v1 will not verify against v2's
different bytes, so there is no replay risk, and a per-file detached `.sig`
is simpler than a signed manifest (no second artifact to keep in sync, no
manifest format to define).

**Why keep the SHA-256 after the signature:** a valid signature already pins
the exact bytes the key holder signed, so the SHA is redundant for
authenticity. It is kept because it is cheap, is the operator-facing
integrity signal (the mismatch message shows expected vs got), and catches a
sig/bytes skew (a `.sig` asset that drifts from its binary).

**Why immediate fail-closed, no soft-fail deprecation window:** the release
pipelines (`release.sh` for Linux, `windows-release.yml` for Windows) now
SIGN every binary and FAIL THE RELEASE if signing, or the
verify-against-`release_pubkeys` check, fails — an unsigned release cannot be
published. Clients verify the TARGET release, not their own running binary,
so the rollout is self-bootstrapping: a pre-signing client (no sig check)
installs the first signed release on a plain SHA match, and every signed
client thereafter installs only signed releases. No client is stranded, and
a manual rollback to a pre-signing release is an operator action (not
self-update), so fail-closed is the correct posture with no deprecation
window.

**Rotation:** `release_pubkeys` is a SET of trusted keys, not one. To rotate:
add the new pubkey on its own line, ship a release signed by the new key,
then retire the old key in a LATER release (keep both until the fleet is off
the old key). The set — not a single key — is what makes rotation a normal
update instead of a full re-bootstrap. Pinned by
`TestVerifyReleaseSignature_Rotation` (a sig from either of two embedded keys
verifies).

**Key custody:** the private key is the release-signing SECRET — it lives on
the trusted release host (a 600-perm file) and, for the Windows CI path, as
the `RELEASE_SIGNING_KEY` GitHub Actions secret. It is NEVER committed; only
`release_pubkeys` (the pubkeys) is committed. Maintainer tools:
`pulsemon sign genkey` (new keypair), `pulsemon sign release <file>
<keyfile>` (write a detached `.sig`), `pulsemon sign verify <file>`
(re-check a `.sig` against the embedded pubkeys — the release pipeline runs
this so a release cut with the wrong key is caught before it ships).

**Pinned by:** `update_sig_test.go` — `TestVerifyReleaseSignature_{Valid,
WrongKey,MissingSig,CorruptSig,WrongLength,Rotation}`,
`TestParseReleasePubkeys`, and the end-to-end
`TestVerifyDownloadedAsset_{Signed,Unsigned,ForeignSig}` (an unsigned or
foreign-signed binary with a MATCHING SHA is refused — the whole point). A
sabotage that drops the authenticity gate makes `_Unsigned` and `_ForeignSig`
fail.

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
