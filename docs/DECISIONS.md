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

**Cap scope fixed 2026-11-16 (external re-flag m3):** the cap keyed on
spawnedIDs only, so the resume of a sensor CREATED paused (POST creates
paused by design, never spawned) was a first spawn and sat dark up to a
whole interval after the operator clicked resume. syncSensors now reads
paused rows (state IN ('active','paused')), drops their loop + state
explicitly, and marks wasPaused; a spawn with wasPaused set counts as a
respawn (marker consumed).
**Rejected in the same re-flag: capping FIRST spawns** (proposed
min(interval, 60s) at process start). Steady-state probe times are
phase + k*interval; capping first-spawn phases under a minute packs every
same-interval sensor's steady-state probes into one 60-second window per
interval — manufacturing the herd the stagger exists to prevent. Startup
darkness is bounded by the interval by design; warmStats serves status
from history meanwhile.
**Pinned by:** TestResumeCreatedPausedSensorProbesPromptly (sabotage =
un-wire wasPaused → red) and TestFirstSpawnKeepsFullStagger (deterministic
id, cap/phase equality).

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

**TOCTOU (closed):** the webhook path closes its check-then-dial window by
pinning its dial to the checked IPs (`dialChecked`). The probe path now does
the same: `redirectTargetAllowed` returns the checked IP, `CheckRedirect`
records it in a per-probe pin map (`redirectPins`), and the dial hooks
(`probeDial` / `probeDialTLS`) dial that IP directly — no re-resolution. The
pin is applied at DIAL time, not by rewriting the request URL, so the URL
keeps its hostname: SNI and cert verification use the hostname (a DNS-name
cert verifies correctly for a cross-host redirect — the old URL-rewrite
design fed an IP literal to both and failed every DNS-name cert), and a
later relative hop's Host header stays the hostname, not the IP. The initial
target is NOT pinned (it is the operator's own configured sensor); only
cross-host redirect hops are. A rebinding attacker would need DNS control on
the LAN — the same threat the cert verification itself defends against.

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

**Re-adjudicated 2026-10-30 (second external review re-flagged the same
endpoint as an "unprivileged external network trigger"):** stance upheld.
Additional rationale: the response is non-secret — running/latest versions
are rendered in the header pill for every user, so an admin gate buys no
confidentiality; the upstream URL is a server-side constant (no SSRF); and
the only real cost (an outbound fetch against GitHub's 60 req/hour budget)
is bounded by the 60s global throttle above — worst case degrades the
version readout for ≤1h. On auth-off installs `requireAdmin` stands down,
so the gate would be a no-op fleet-wide; it would only bind on a future
auth-on install with viewer accounts, where it would gate a read whose data
the viewer already sees. The admin gate belongs on `POST /api/update`
(code execution + restart), which has it. Pinned by the in-code note at the
route (api.go routes()) and by the non-admin 200 assertion in
`TestNonAdminCannotReachAdminSurface`.

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

**Why sign a manifest, not the raw bytes (2026-11-05):** the signature is
over a small versioned manifest —
`pulsemon-release-v1\n<tag>\n<asset-name>\n<sha256-hex>\n`
(`releaseManifestMessage`) — binding it to the release TAG, the ASSET NAME,
and the digest, not just the bytes. The raw-bytes form (v0.4.4 and
earlier) had a replay hole its own rationale missed: "a valid signature for
v1 will not verify against v2's different bytes" is true, but a
compromised pipeline can RE-UPLOAD v1's signed bytes under v2's tag — the
signature still verifies (same bytes, same key), and v2's tag looks newer
than anything real, so every install "upgrades" to the old (vulnerable)
build and can sit pinned there. The manifest closes that: a v1 signature
cannot verify as v2, and a linux-amd64 `.sig` cannot verify for the
arm64 asset. **Transition (now complete):** the legacy raw-bytes form was
accepted as a fallback ONLY during the transition — the pipeline signed the
first release carrying the manifest verifier with `RELEASE_SIGN_FORMAT=legacy`
(the default is `manifest`) so v0.4.4-era clients could install it, and the
next cut reverted to the default. That transition is long past, so
`verifyReleaseSignature` now accepts the MANIFEST form only: the raw-bytes
fallback is removed because it bound the signature to the bytes alone, letting
a compromised release account (no signing key) replay an old signed binary
under a newer-looking tag — a replay the anti-downgrade floor can't catch
(the tag is attacker-chosen, so it sits above the floor). No client on this
verifier can self-update to a pre-manifest release anyway (downgrades are
floor-refused), so dropping the fallback strands nothing. Pinned by
`TestVerifyReleaseSignature_RawBytesReplayRejected`.

**Anti-downgrade floor (2026-11-05):** the manifest binds a signature to a
tag, but a compromised PIPELINE (which holds the signing key) can still sign
a fake-newer tag over an old binary. The second line is version ORDER: the
settings key `max_version_seen` records the highest version this install has
ever run (bumped monotonically at server boot — `bumpMaxVersionSeen`; a
post-rollback boot never lowers it, dev builds record nothing). Both
install paths refuse a release tag below the floor: the CLI with exit 1 and
a `--allow-downgrade` opt-out, the dashboard with 409 (an explicit version
pin in the request body is the API's opt-out — pinning an old tag is a
deliberate operator choice). A missing DB, an empty floor (fresh install),
or an unparseable value never blocks an update. **Residual (accepted):**
full pipeline compromise — key + tag control — can still sign an old binary
under a fake-newer tag; the mitigations are key custody/rotation above, and
the floor still stops the attacker's tag from silently creeping back DOWN.

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

**Key custody:** the private key is the release-signing SECRET — it lives ONLY
on the trusted release host (a 600-perm file); it never lives in CI (the
Windows `.exe` is signed offline there, same as Linux — see
`windows-signing-offline`). It is NEVER committed; only `release_pubkeys`
(the pubkeys) is committed. Maintainer tools:
`pulsemon sign genkey` (new keypair), `pulsemon sign release <file>
<keyfile> [tag asset-name]` (write a detached `.sig` — 2 args = legacy
raw-bytes form, 4 args = manifest form bound to the tag + asset),
`pulsemon sign verify <file> [tag asset-name]` (re-check a `.sig` against
the embedded pubkeys — the release pipeline runs this so a release cut with
the wrong key is caught before it ships).

**Pinned by:** `update_sig_test.go` — `TestVerifyReleaseSignature_{Valid,
WrongKey,MissingSig,CorruptSig,WrongLength,Rotation}`,
`TestParseReleasePubkeys`, and the end-to-end
`TestVerifyDownloadedAsset_{Signed,Unsigned,ForeignSig}` (an unsigned or
foreign-signed binary with a MATCHING SHA is refused — the whole point);
`update_manifest_test.go` — the manifest form: `TestVerifyReleaseSignature_{
ManifestValid,ManifestReplayWrongTag,ManifestWrongAsset,ManifestWrongSHA,
RawBytesReplayRejected,MissingBindingRefused,ManifestExactBytes}` and the
end-to-end `TestVerifyDownloadedAsset_ManifestReplay` (a v0.3.11 signature
served as v9.9.9 is refused); `update_downgrade_test.go` — the floor:
`TestDowngradeGuard` (decision table), `TestBumpMaxVersionSeen` (monotonic,
dev-safe), `TestRunUpdate_{RefusesDowngradeBelowMaxSeen,
AllowDowngradePassesGuard}` (CLI end-to-end) and
`TestUpdate_{RefusesDowngradeBelowMaxSeen,
ExplicitPinBypassesDowngradeGuard}` (dashboard 409 / pin opt-out). A
sabotage that drops the authenticity gate makes `_Unsigned` and `_ForeignSig`
fail; one that drops the manifest binding makes `_ManifestReplayWrongTag`
fail; one that re-adds the legacy raw-bytes fallback makes
`_RawBytesReplayRejected` fail; one that drops the floor makes
`_RefusesDowngradeBelowMaxSeen` fail.

## package-structure (repo-wide) — CLOSED, decision 2026-10-30 (pilot shipped)

**Status:** `package main` (~14.6k LOC production, ~150 .go files) plus
`internal/store` (the data layer, extracted 2026-10-30), with mutable
package-level test seams (`probeTarget`, `alertGateIdle`,
`stormBudget`, `readerRestartDelay`, `reexecBindDeadline`, …) that tests
swap and restore in `t.Cleanup`.

**Decision: the full split into internal packages (probe, alert, auth,
api, stats) with injected dependencies is CLOSED — not planned work.**
Originally deferred 2026-10-29; the user closed the thread 2026-10-30
with the hardening cycle complete: a deferral implies scheduled work,
and the recommendation was "not worth it at current scale" — so the
honest state is closed, not a permanent watchlist item. Nothing is
pending; this entry is the durable record.

**Pilot (shipped): `db.go` → `internal/store`.** C1 (c4d8433): the move
— db.go + 4 test files, `DB`→`Store`, 9 symbols relocated+exported
(`FormatTS`, `Now`, `TSLayout`, `SetSettingInTx`, `InQueryChunk`,
`AuthUser`, `NewID`, `MigrateLegacyAuthToken`, `ErrLastUser`/
`ErrUserNotFound`); a temporary `type DB = store.Store` alias kept all
existing signatures compiling. C2 (054f425): alias dropped, all
references qualified `store.Store`. Pure moves, zero behavior change;
each commit gated green (gofmt, vet linux+windows, build, full -race
238–239s — at the 241.6s baseline). Proved the extraction machinery
(rename detection, alias trick, sentinel/helper relocation, test-file
moves) works on this codebase without gate regression.
`tsformat_test.go`/`chunk_test.go` stayed in main (they exercise
`ProbeWorker`) and call the `store.*` exports.

**Why the rest is not worth it (current scale):** the split touches
nearly every file and every test seam, with regression risk across a
70+-test-file suite that is -race-green on a steady release cadence.
For a single-binary homelab tool with one operator, the expected value
(faster tests, compile-time dependency clarity) does not justify that
risk. The pilot's own result is the data point: a clean extraction that
bought no gate-time, no seam, and no parallelism — those payoffs live
in the probe/alert/auth packages, and reaching them costs the full
split.

**Standing operational costs (accepted, not pending):**
- Swappable globals are a -race hazard by construction (the `alert-gate`
  capture rule exists because of a real -race hit). Standing rule: any
  new test-swapped var must be captured into a parameter at spawn
  time, never read by long-lived goroutines.
- No `t.Parallel()` anywhere: the shared globals make parallel tests
  unsafe. Test time is the price (~4 min full -race).

**Re-litigation clause (a condition to REOPEN the decision, not a
watchlist):** if test time doubles again (~8+ min), a globals-related
-race hit recurs despite the capture rule, or a second developer joins,
revisit the split as a fresh decision. The pilot means it would then be
a known process (leaf-first, one green-gated package at a time,
constructor injection), not an experiment.

**Re-adjudicated 2026-11-16 (external review re-flag M3): stays CLOSED.**
All three clauses re-measured on the live tree: full -race suite 336.7s
(~5.6 min, below the ~8-min clause, though the +40%-in-2.5-weeks growth
from the 241.6s pilot baseline says the clause is trending toward
firing — re-measure each release cut); no globals-related -race hit has
recurred since the capture rule; solo developer. The seam inventory in
the re-flag is already stale (setMaintenanceMode was removed by the
maintenance-leave rework). If a clause fires, the documented process
applies (leaf-first, one green-gated package at a time, constructor
injection), not a big-bang move.

## admin-gate double session check (auth.go `requireAdmin`/`sessionFrom`) — REJECTED, decision 2026-10-30

**Finding (external review 2026-10-30 #4, second half):** `requireAdmin`
calls `s.requireAuth` (which calls `s.sessionFrom(r)`) and then calls
`s.sessionFrom(r)` a second time in the inner closure — "acquires a.mu
twice"; the suggested fix inlines the session check to avoid the double
call.

**Decision: REJECTED — the double check is deliberate defense-in-depth.**
A handler's authorization decision (admin-only gates, per-user scoping)
must not rest on the gate having run: a route registered without the
gate, or a future gate change, must not silently widen authorization.
The cost is one extra short `a.mu` critical section plus an in-memory
map lookup — the second pass almost always hits the `userOKTTL` cache,
so it adds no DB query. (The uncached-query half of the finding IS
addressed: `IsAdmin` is now `userOKTTL`-cached via `adminCache`,
fail-closed on DB error, cleared in `refreshEnabledNow` at the in-app
mutation sites.)

Pinned in-code: the `sessionFrom` comment in auth.go states the double
check is deliberate and must not be "fixed" away.

## shouldAlert filter reads (alerts.go `shouldAlert`) — REJECTED, decision 2026-10-30

**Finding (external review 2026-10-30 #8):** `shouldAlert` re-reads
`alert_scope`/`alert_filter` from SQLite and re-unmarshals the filter
list (up to 500 items) on every status transition and re-alert check;
suggested fixes were an in-memory cache invalidated in
`handleSettingsPut`, or a `map[string]struct{}` for large lists.

**Decision: REJECTED — the per-decision read is the established
alert-routing pattern, and the cost is unmeasurable.**
- The default path is already O(1): `alert_scope` defaults to "all" and
  returns after ONE point query — no filter read, no unmarshal, no loop.
- The loop only runs for opt-in routing (scope=tags/sensors), on a list
  already capped at 500 entries (2026-10-22,
  `TestFix_SettingsAlertFilterBounded`): worst case ~2.5K short-string
  comparisons (5 tags × 500 items) — tens of microseconds.
- Frequency is cold by the reviewer's own admission: transitions are
  rare, and re-alerts fire at most once per re-alert interval (default
  30 min) per sensor — after the alert_state read and interval check.
- `alertsEnabled` (the same gate chain) deliberately re-reads
  `maintenance_mode` from the DB on EVERY alert decision — the project's
  chosen pattern for alert routing is "read the current setting per
  decision": an operator's routing change takes effect on the next
  transition with zero staleness. A cached filter would deviate from that
  pattern inside the same gate chain and add an invalidation surface
  (dashboard PUT, CLI, env fallback) where a missed invalidation means
  STALE ROUTING — "why didn't I get an alert?" is a far worse failure
  mode than the microseconds saved.
- The `map[string]struct{}` variant saves the same unmeasurable amount
  and adds an allocation on the cold path.

Pinned in-code: the `shouldAlert` doc comment states the per-decision
read is deliberate.

## smtp delivery deadline (alerts.go `deliverOne`/`deliverStormSummary` → `sendSMTP`) — ALREADY ADDRESSED, decision 2026-11-03

**Finding (external review 2026-11-03):** `pw.sendSMTP(pw.stopCtx, …)` is
called with `pw.stopCtx` — cancelled only at process shutdown — in both
`deliverOne` (inside `retryAlert`, on the sensor's 8-slot `alertOrderGates`
FIFO) and `deliverStormSummary` (inside a `wg.Wait()`). The review: if
`sendSMTP` does not enforce an internal deadline on its dial and protocol
round-trip, a tarpitted relay hangs the delivery goroutine indefinitely,
and 8 stuck SMTP deliveries fill a sensor's `alertOrderGates` channel and
"permanently drop all subsequent alerts." Suggested fix: wrap
`pw.stopCtx` in a `context.WithTimeout(…, 15*time.Second)` before each
`sendSMTP` call.

**Decision: ALREADY ADDRESSED — the indefinite-hang mechanism no longer
exists; no code change.** `sendSMTP` (smtp.go) bounds every phase
internally:
- **Dial** — a 10s ctx timeout (`context.WithTimeout(ctx, 10s)` wrapping
  the shared dialer, which has none of its own).
- **Conversation** — an ABSOLUTE conn deadline (`smtpConnDeadline`, 15s)
  set on the `net.Conn` covers every read/write from the 220 greeting
  through QUIT. This is the tarpit bound: a relay that accepts TCP and
  then goes silent (missing 220, blackholed socket) is cut off at 15s
  with a deadline error, not held forever.
- **Cancellation** — `context.AfterFunc(ctx, conn.Close)` closes the conn
  when ctx is cancelled; closing the conn is the only way to abort a
  blocked `net/smtp` read (its `Client` methods take no ctx).

So the worst case for one SMTP delivery is **10s dial + 15s conversation =
25s**, after which it returns an error and releases its gate slot —
bounded, not indefinite. The 8-slot gate concern is real as a mechanism
but "permanently" is overstated: a tarpit relay holds a slot for ≤ 25s,
not forever.

**Pinned by:** `TestSendSMTPDeadlineBoundsHungGreeting` (a silent relay
must not block `sendSMTP` — the conn deadline turns the hang into a
bounded error; pre-fix it hung until `-test.timeout`) and
`TestSendSMTPContextCancelAborts` (cancelling ctx aborts an in-flight
conversation via the conn close — the deadline is set long on purpose so
the test returns via CANCELLATION, proving the AfterFunc path).

**Why not add the call-site `WithTimeout(15s)` (considered, not
adopted):** it is redundant with the internal bounds and only tightens the
worst case from 25s → 15s. It also shifts the budget split — a 15s TOTAL
cap leaves the conversation only 5s if the dial took 10s, whereas the
absolute conn deadline gives the full 15s to the round-trip after the
dial. The internal deadline IS the documented contract (the `sendSMTP`
doc names `smtpConnDeadline` as "the SMTP equivalent of the webhook
path's http.Client 10s total-request timeout"), and a second,
call-site-level cap would duplicate it without covering a behavior the
tests don't already pin. If provider-parity on the TOTAL cap (≤15s
including dial) is ever wanted, the 15s `WithTimeout` is a safe two-line
addition — a tightening, not a bug fix.

## dns-stale-cache (ping.go, probe.go, internal/store/store.go, 2026-11-05)
**Decision:** when re-resolution FAILS, `resolveICMPTarget` serves the last good IP for up to `dnsStaleMaxAge` (10 min) past the last SUCCESSFUL resolution (bounded staleness); concurrent same-name lookups collapse through `singleflight`; a probe lost at name resolution is marked (`PingResult.DNS`) and written to the row as `probes.dns_error` (NULL for packet losses and HTTP probes).
**Why:** the homelab resolver (Pi-hole/AdGuard) is itself a monitored sensor. Its death made every hostname sensor's re-resolution fail at once → each probe a loss → one root cause read as "N hosts down" and tripped the storm path. The 30s cache only stored successes, so a dead resolver flipped the whole cohort to "error" simultaneously, and the 5s DNS timeout sat outside `timeout_ms` (a 5s-interval sensor could run back-to-back). The staleness window is bounded (an IP older than 10 min is not trusted); the per-target "serving stale IP" log is rate-limited to one line / 30s.
**Singleflight ctx detail:** the shared lookup runs on its own 5s deadline rooted at `context.Background()` — NOT the first caller's probe ctx. Keying it to one caller's ctx would fail the lookup for every waiter on that one caller's cancellation (shutdown, sensor removed). A caller whose own ctx is done gets its ctx error back.
**Sweep detail:** the opportunistic cache sweep (map > 128 entries) drops entries past `expires + dnsStaleMaxAge`, not `expires` — an entry inside the staleness window is a live fallback for a failing re-resolution and must survive the sweep.
**dns_error surface:** `probes.dns_error TEXT` is a one-time additive migration (NULL for existing rows, packet losses, and HTTP probes). The UI does not render it yet — it is recorded so the distinction is durable and queryable (a future "resolver down" banner can key off it).
**Pinned by:** `TestResolveICMPTargetServesStaleOnResolutionFailure`, `TestResolveICMPTargetStaleBound`, `TestResolveICMPTargetRecoversAfterResolverReturns`, `TestDNSLookupSingleflight`, `TestResolveICMPTargetSweepKeepsStaleWindow`, `TestPingHostDNSFailureMarked`, `TestDoProbeRecordsDNSLossOnRow` (`ping_dns_stale_test.go`).

## allow-unauth-update-gate (api.go `handleSettingsPut`, web/, 2026-11-05)
**Decision:** `allow_unauth_update` (the opt-in that re-allows the in-dashboard self-update button on an auth-off install) is changeable ONLY while an account exists — `PUT /api/settings` 403s the field when `!s.auth.Enabled()`. The stored VALUE is untouched (an install that already has it on keeps working); only the CHANGE is gated. The UI toggle moved from the auth-OFF panel to the auth-ON panel (it is a setup control: set it BEFORE turning auth off), is admin-only, and a save that does not send the field (the general "save alerts" flow) is unaffected.
**Why:** with auth off, `requireAdmin`/`requireAuth` stand down ("auth off = fully open"), so any LAN host could `PUT /api/settings {"allow_unauth_update":true}` and then `POST /api/update` — downloading a binary, overwriting the running one, and restarting the service. The opt-in was meant to be set by an authenticated operator, not by the open network. `auth.Enabled()` is `user_count > 0`, so "no account" ⟺ auth off; the gate therefore requires the operator to create an account first (already needed for any admin config) before flipping the toggle.
**Pinned by:** `TestSettingsPutRejectsAllowUnauthWhenAuthOff` (`settings_alert_filter_test.go`).

## alert-settings-snapshot (alerts.go, probe.go, api.go, 2026-11-05)
**Decision:** the alert hot path (gate + delivery) reads ONE typed settings snapshot (`alertSettings`) held in `atomic.Pointer`, loaded at worker start and swapped atomically after every successful `PUT /api/settings` commit (the maintenance-mode change in the same handler commits in its own tx, then the same call reloads). The gate fields (maintenance, scope, filter, realert_min) AND the resolved delivery destinations (provider URL + Telegram chat_id) are all in the snapshot; the hot path makes ZERO settings queries. On a reload read error the previous snapshot is KEPT (a hiccup never installs a half-read state).
**Why:** `GetSetting` maps a read error to `""`, so a transient DB lock mid-probe read maintenance_mode as "0" (alerts ENABLED) and alert_scope as `""` (scope "all") — a DB hiccup during maintenance fired alerts for every sensor, and each errored probe / alert paid 5–10 single-row settings queries. `activeProviders`' `db.Ping()` + `lastProviders` fallback was a patch over the same root cause. The snapshot keeps the last GOOD state in memory: maintenance stays on, routing stays put, destinations keep their resolved chat_id, and the hot path is lock-free.
**Delivery-time semantics change:** the Telegram chat_id is resolved at SNAPSHOT-LOAD time, not delivery time. A transient chat_id read failure now aborts the load and keeps the last good snapshot — the delivery path always carries the last known-good chat_id (or no provider at all), never an empty one (which Telegram 400s). This is the snapshot-world form of the 2026-10-30 review #3 "never post an empty chat_id" contract. The nil-DB panic source in the m1 done-channel test moved to the `deliverDestinations` seam for the same reason (the `db.Ping()` read is gone from the hot path).
**Pinned by:** `TestTelegramDeliveryFailsClosedOnChatIDReadError` (kept-good chat_id survives a failing reload; `telegram_test.go`), `TestSendWebhookReturnsOnPanickedJob` (job-level panic via the `deliverDestinations` seam; `sendwebhook_panic_test.go`), and the maintenance / realert gate tests that now `reloadAlertSettings()` after a post-construction settings change (`probe_test.go`, `webhook_retry_test.go`).

## sync-sensors-generation (probe.go, 2026-11-05)
**Decision:** `syncSensors` does NO DB reads under `pw.mu`. It captures a per-sensor generation fingerprint (`pw.gens`) BEFORE the config+tag reads, then reconciles under the lock by comparing each sensor's current generation to the fingerprint — a sensor whose generation changed in the read→apply gap is SKIPPED (the `Restart`/`SetPaused` that bumped it owns the re-sync; `Restart` also signals `syncReq` for a fresh pass). `Restart` and `SetPaused` bump the generation; `Remove` deletes it. This replaces the old under-lock `freshStates`/`freshConfig` re-reads.
**Why:** `pw.mu` is the hot lock every `sensorLoop` takes twice per tick (plus `healthz` `ActiveCount` and `LastHTTPStatus`), and the old `syncSensors` held it across `freshStates`/`freshConfig` SQLite reads every 5s. A slow read (a stalled writer holding the DB) stalled the WHOLE fleet up to the 15s `busy_timeout` — every loop's `pw.mu` acquisition (and healthz) blocked behind the read. The generation fingerprint closes the same TOCTOU the under-lock re-reads closed (a config edit landing in the read→apply gap) WITHOUT the DB-I/O-under-lock stall: the bumping op already owns the re-sync, so the in-flight pass just skips the stale sensor. `pw.gens` is nil-map-safe (bare `&ProbeWorker{}` test workers) — `bumpGen` lazily creates it, and the fingerprint copy / `Remove`'s delete no-op on a nil map.
**Pinned by:** `TestSyncSensorsGenerationSkip` (a `Restart` in the gap → the in-flight pass skips the sensor, no stale-config spawn; the fresh pass spawns it), `TestSyncSensorsNoDBUnderLock` (while the config read is blocked on the exhausted pool, `pw.mu` stays acquirable — `ActiveCount` does not stall), both in `probe_sync_gen_test.go`.

## do-probe-status-event-atomic (probe.go `doProbe`, 2026-11-05)
**Decision:** the status `UPDATE sensors SET status` and the `INSERT INTO events` transition row commit in ONE `ImmediateTx`. `rememberStatus` (the in-memory `lastStatus` advance) runs only AFTER the tx commits.
**Why:** the two were separate autocommit statements. If the events INSERT failed after the UPDATE succeeded, `rememberStatus` had already advanced `lastStatus`, so the next tick's `currentStatus` returned the new status, `deriveStatus` saw `oldStatus == newStatus`, and the transition (and its event row) was lost forever — the sensor sat in the new status with no event recording the change. Wrapping both in a single tx makes the pair atomic: a failed INSERT rolls back the UPDATE too, `lastStatus` is not advanced, and the next tick retries the whole transition. The `probeBroken`/loss-driven `deriveStatus` result is unchanged; only the write path is now transactional.
**Pinned by:** `TestDoProbeStatusAndEventCommitAtomically` (`probe_status_atomic_test.go`) — a `BEFORE INSERT ON events` trigger makes the INSERT fail; asserts the status UPDATE was rolled back (status stays at the pre-transition value), `lastStatus` was not advanced, no event row exists, and after the trigger is dropped the transition is retried and lands atomically (status advances + exactly one event). Sabotage-verified: the old non-atomic code fails with `status="warning", want up`.

## probe-series-memory-tiers (stats.go, probe.go, status.go, api.go, 2026-11-05)
**Decision:** `probeSeries` is split into two tiers. `raw` holds per-probe entries for the per-probe window — `max(1h, last-60)` (`rawWindowSecs = 3600`), so a 5s sensor keeps ~721 raw entries, not 17,280. Older non-manual entries are FOLDED into per-minute `minuteBucket{minute,total,lost,sumRTT,maxRTT,hasRTT}` aggregates, kept for the 24h retention. `total24`/`lost24` are incremental counters (O(1) uptime), maintained by `raw24Start` (walks past raw entries that age out of the 24h window while in the last-60 tail) and bucket eviction. `handleSensorGraph` serves BOTH 1h and 24h from memory (`graphPoints` folds the live minute buckets into the requested bucket width + the raw hour) — the per-request SQL aggregate over `probes` is gone.
**Why:** at a 5s interval the single flat series was 17,280 entries/sensor ≈ 276 KB, up to ~2× with slice slack — 200 sensors ≈ 55–110 MB, and only the last hour is ever read at per-probe resolution (the 24h graph uses 15-min buckets, `uptime_24h` needs only counters). The tiered split caps raw at the 1h window and folds the rest into ≤1440 minute buckets (~4.5 KB/sensor), and the in-memory graph removes a 24h SQL scan from every inspector open.
**Manual rows:** "Pulse Now" rows stay in `raw` for the 60-probe inspector but are excluded from buckets, counters, and graph points (a diagnostic click must not move `uptime_24h` or the graph). `warmStats` re-derives the series from the DB on boot, so a restart rebuilds the tiers; the graph serves an empty slice for a sensor absent from the cache (matches a zero-probe window).
**Counter invariant:** an entry is in the 24h window iff it is a live raw entry at index ≥ `raw24Start` OR it is in a live bucket. `raw24Start` decrements on the way out of the window; folding is a no-op (the entry stays in the window via its bucket); a bucket older than 24h is evicted and its `total`/`lost` subtracted. An entry already out of the window (index < `raw24Start`) is DROPPED at fold time, never bucketed — bucketing it would double-decrement.
**Pinned by:** `TestSeriesMemoryBounded` (raw ≤ 721 @ 5s, buckets ≤ 1440, every entry in exactly one tier), `TestGraph24hFromMemoryMatchesSQL` (in-memory 24h graph reproduces the SQL aggregate bucket-for-bucket), `TestSeriesCountersTrackRecount` (incremental counters == brute-force recount across the raw + bucket tiers), `TestSeriesEviction` / `TestRecordProbeMonotonicTs` (raw-tier eviction + monotonic ts). Sabotage-verified: `rawWindowSecs = 3600*100` (no folding) fails `TestSeriesMemoryBounded` with `raw len = 17280`.

## retention-purge-at-startup (probe.go `Run`, 2026-11-05)
**Decision:** `Run` calls `pw.purgeOld(ctx)` ONCE at startup, BEFORE `warmStats` — in addition to the existing hourly retention ticker. The sweep is synchronous (it runs to completion before the select loop), so every boot enforces the 24h retention window.
**Why:** the retention ticker's first fire is 1h after start, so a process that restarts more often than hourly — crash loops, frequent updates — NEVER purged, and the `probes`/`events` tables grew without bound (each restart re-read the ever-growing tables on boot, and the disk filled). Placing the startup sweep BEFORE `warmStats` also shrinks the warm query: the warm read sees an already-trimmed 24h window instead of a stale backlog. The sweep is idempotent and bounded (per-sensor batches of `purgeBatchSize`, short write tx between batches), so the one-time startup cost is a few milliseconds on a healthy DB and is interruptible by the shutdown ctx.
**Pinned by:** `TestRunPurgesAtStartup` (`probe_purge_startup_test.go`) — a paused sensor (no probe loop writes) seeded with 25h-old rows + a 1h-old row; `Run` on a short-lived context must leave 0 old rows and the recent row intact. Sabotage-verified: removing the startup `purgeOld(ctx)` call fails with `old rows after startup = 5, want 0`.

## storm-summary-recheck-before-post (alerts.go `deliverStormSummary`, 2026-11-05)
**Decision:** `deliverStormSummary` re-checks each entry's `currentStatus` immediately before building the body and DROPS any entry now `"up"`. If every entry is dropped, no summary is posted. This is a second filter on top of `flushStorm`'s flush-time filter.
**Why:** the storm summary is a global meta-alert that bypasses the per-sensor ordering gate (F4), so it is NOT ordered with the per-sensor recovery alerts. `flushStorm` filters its queue on status at FLUSH time, but the delivery is async (`launchAlert`) with the post landing later — a sensor that the flush filter KEEPT (it was `"error"` at flush time) can recover in the gap, and its recovery alert (ordered on the per-sensor gate) can post BEFORE the summary that still lists it as `"error"`. The operator then sees "recovered" followed by a storm summary naming the sensor as down. The re-check narrows the race to the instant before the post: `currentStatus` is in-memory (`lastStatus`) for an actively-probed sensor, so it is cheap — no per-entry SQLite round-trip on the hot path. The two filters are complementary: the flush-time filter catches recoveries before the flush (the common case, no wasted async dispatch); the post-time re-check catches the narrow flush→post gap.
**Pinned by:** `TestStormSummaryDropsRecoveredBeforePost` (`storm_test.go`) — a sensor the flush filter kept (it was `"error"` at flush time) that recovers before the post (`lastStatus` + DB row both `"up"`); `deliverStormSummary` (called synchronously) must drop it, so no summary is posted. Complements `TestStormFlushDropsRecovered` (recovery before the flush) and `TestStormFlushUsesInMemoryStatus` (in-memory filter). Sabotage-verified: disabling the re-check (`if false`) fails with `summary lists recovered sensor r10` + `deliveries = 1, want 0`.

## login-throttle-per-username + bcrypt-sem (auth.go, 2026-11-05)
**Decision:** Added a per-username failure/lockout layer (`userFails`/`userLock`) on top of the existing per-IP throttle, and a blocking bcrypt semaphore (`bcryptSem`, capacity `runtime.NumCPU()`) around `CompareHashAndPassword`. The hard-cap wipe (131k per-IP keys) is all-or-nothing: it resets both the per-IP and per-username maps.
**Why:** the per-IP throttle is keyed by source address, so a multi-IP attacker (an IPv6 /48 is 65k distinct /64 buckets) hammering ONE account never exhausts any single IP's budget — the account is unlocked while the KDF is being brute-forced. The per-username counter accumulates failures for that account across ALL sources and locks the account at the same `loginFailMax`/`loginFailWindow`/`loginLockout` cadence. The bcrypt semaphore caps concurrent KDFs at `NumCPU` so a multi-IP burst can't saturate every core; it is BLOCKING (not `select/default` → 429) so under attack the operator's login queues for a free core instead of being rejected. Both the real-hash and dummy-hash (unknown-user) paths go through the semaphore so the timing equalizer keeps its constant time AND its concurrency cap.
**Pinned by:** `TestLoginThrottlePerUsername` (7 failures across 3 IPs → fresh IP + correct pw → 429; different username → 401), `TestLoginThrottleHardCapWipesUserMaps` (hard-cap wipe resets `userFails`+`userLock`), `TestLoginSuccessClearsUserFail` (success resets the account budget), `TestCheckUserLockClearsElapsed` / `TestCheckUserLockActive` (unit-level lockout lifecycle), `TestBcryptSemCapacity` (capacity = `NumCPU`). Sabotage-verified: replacing `checkUserLock(userKey)` with `checkUserLock("__sabotage__")` makes `TestLoginThrottlePerUsername` fail (200 instead of 429).

## bcrypt-sem-full-coverage (auth.go, 2026-11-10)
**Decision:** Every bcrypt KDF now runs under `bcryptSem`, and the acquire is ctx-aware. `acquireBcryptSem(ctx)`/`releaseBcryptSem()` replace the raw channel ops: `VerifyUser` (dummy + real paths), `AddUserMode` and `SetUserPassword` (`GenerateFromPassword`) all acquire it, and a canceled ctx makes the call skip the KDF (`VerifyUser` → `("", false)`, the mutators → `ctx.Err()`). `ctx` is threaded as the first parameter through `VerifyUser`, `CreateSession`, `AddUser`, `AddUserMode`, `SetUserPassword`; the handlers pass `r.Context()`, and a gone client (`r.Context().Err() != nil`) is NOT counted against the per-username failure budget, gets no rejection delay, and (setup mode) refunds its throttle attempt — a disconnect is not a failed password attempt.
**Why:** the finding's two sub-claims were both valid. (1) The documented invariant is "cap CONCURRENT KDFs at NumCPU", but both `GenerateFromPassword` calls ran outside the sem — and `AddUserMode`'s setup mode is the UNAUTHENTICATED bootstrap surface (its own comment calls it an "unlimited bcrypt-CPU endpoint" without the pre-check), so concurrent bootstrap POSTs could drive NumCPU-or-more parallel KDFs. (2) `VerifyUser`'s blocking send parked queued handlers on the sem after their clients disconnected, burning CPU on cost-10 KDFs for responses nobody reads. The queue was self-draining (total CPU bounded by queue × KDF time), so severity was moderate — the fix converts "work for a gone client" into "no work". Ctx cancel only skips work for a GONE client (live clients' ctx is not done), so the timing equalizer, the per-IP/per-username budgets, and the 200 ms rejection delay are all untouched for live traffic.
**Pinned by:** `TestBcryptSemCoversGenerate` (sem full + canceled ctx → `AddUserMode`/`AddUser`/`SetUserPassword` return `context.Canceled` with NO side effects — no account created, no password changed; positive controls prove the live path + no slot leak), `TestVerifyUserCtxCancelSkipsQueuedKDF` (sem full + canceled ctx → returns within 2 s WITHOUT taking a slot — the old blocking send would park until a slot freed). Sabotage-verified: removing the sem acquire from a Generate path makes its canceled-ctx subtest return nil instead of `context.Canceled`; restoring the blocking send makes the queued-KDF test time out.

## userfails-bound (auth.go, 2026-11-10)
**Decision:** Two changes close the unbounded-growth gap the 2026-11-05 layer left in `userFails`: (1) `handleAuthLogin` records a per-username failure ONLY when the account exists (`userExists(userKey)` gate around `recordUserFail`) — a failure for a name with no account protects nothing (the dummy-hash equalizer already hides the distinction from the client), and (2) the sweep/hard-cap trigger in `beginAttempt` now watches BOTH maps: `len(fails) > throttleSweepThreshold || len(userFails) > throttleSweepThreshold` gates the sweep, and `len(fails) > throttleHardCap || len(userFails) > throttleHardCap` gates the all-or-nothing wipe.
**Why:** the sweep/wipe was keyed on the PER-IP map alone, but `userFails` is keyed by the raw request username (no validation on the login path; up to the 1 MiB `maxRequestBytes` body). A small IP pool (e.g. 2 IPs × 6 failures/min — under the 7/60s per-IP budget) rotating random usernames kept `len(fails)` at 2 forever while `userFails` grew ~12 entries/min (up to ~12 MiB/min with 1-MiB usernames) — no threshold ever crossed, OOM in days. After the fix `userFails` is bounded structurally: recording is limited to the (small, admin-gated) account set, and even an unbounded key space can only grow the map to `throttleHardCap` (131,072 ≈ tens of MB) + one 30s sweep interval of growth before the wipe fires. The `userExists` point query runs on the cold failure path (throttled + 200 ms delay), sub-millisecond against the KDF + delay — no timing oracle added. The single-IP-locks-the-account behavior (7 attempts trip BOTH the per-IP and per-username gates) is the 2026-11-05 layer working as designed, not part of this finding.
**Pinned by:** `TestLoginThrottleSweepTriggerWatchesUserFails` (1-entry `fails` + 4 stale `userFails` past the threshold → beginAttempt sweeps), `TestLoginThrottleUserFailsHardCapWipe` (1-entry `fails` + 5 in-window `userFails` past the cap → all four maps wiped), `TestLoginUnknownUserDoesNotRecordUserFail` (5 unknown-user 401s → `userFails` empty; existing-account 401 → recorded). Sabotage-verified: reverting either auth.go hunk fails its corresponding test.

## password-endpoint-userlock (auth.go, 2026-11-10)
**Decision:** `handleAuthUserPassword` (POST /api/auth/users/{username}/password) now runs the SAME per-username failure budget as /api/auth/login: `checkUserLock(user)` gate after the per-IP `beginAttempt` gate (429 + Retry-After, KDF skipped), `recordUserFail(user)` on a wrong current password, `clearUserFail(user)` on success. The two endpoints share the `userFails`/`userLock` maps, so a locked account 429s on BOTH.
**Why:** the endpoint verifies a real password (full bcrypt KDF) but carried only the per-IP throttle — the exact multi-IP bypass finding #11 closed for login. The threat path is the one the handler's own doc names: a holder of a valid session for the account (stolen cookie, unlocked browser, plain-HTTP LAN capture) spraying current_password across many IPs (/64 buckets) — one correct guess sets a new password and drops every other session (account takeover). The session is a bearer token, so one stolen cookie works from any number of sources; the per-IP budget never trips. No `userExists` gate is needed here (unlike the login path): the caller holds a live session, so the account exists by construction and the key is the caller's own name — no unbounded-growth vector.
**Pinned by:** `TestChangePasswordPerUsernameLockout` (7 wrong currents across 3 IPs → fresh IP 429 + Retry-After; correct login from a fresh IP also 429 — shared budget; success clears the budget). Sabotage-verified: removing the checkUserLock gate, the recordUserFail call, or the clearUserFail call each fails the test at its corresponding assertion.

## login-throttle-known-good-exemption (auth.go, 2026-11-10)
**Decision:** the per-username lockout (finding #11) now EXEMPTS a previously-successful IP bucket. `loginSuccess` records the request's throttle bucket in a `knownGood` map (bucket → last-successful-login time), and `checkUserLock(username, ipBucket)` returns "not locked" for any bucket whose `knownGood` entry is within `knownGoodTTL` (the session TTL, 30 days). A new (never-seen) bucket is still subject to the hard lockout. The exemption does NOT touch the per-IP budget (`beginAttempt`), so a known-good IP is still capped at `loginFailMax` fails/60s. `knownGood` is swept by `sweepThrottle` (dropped past `knownGoodTTL`) and reset by the hard-cap wipe (all-or-nothing, like the other throttle maps).
**Why:** the per-username layer exists to stop a MULTI-IP botnet, but as a side effect it let a single LAN host lock the operator out: 7 bad guesses for admin → 429 for 5 minutes, EVEN FOR THE CORRECT PASSWORD (the check runs before the credential check, so a locked account refuses a right password). A single LAN host can repeat this indefinitely — the per-IP budget is also 7/60s, so one host exhausts both layers at once. Exempting a previously-successful IP keeps the operator's own device always able to get through while a new-IP attacker is still hard-locked. The file header's "No per-ACCOUNT brute-force lockout" line was now false and is rewritten to describe the per-account layer + the exemption. The residual case (a new device, a DHCP change — an IP that is not known-good) is recoverable via the CLI: `pulsemon auth-user` runs out-of-band and is not subject to the login throttle. The progressive-delay alternative was considered and not adopted: it would let the KDF run for every attempt (losing the hard lockout's DoS protection) and complicate the constant-time equalizer (the delay would have to apply to both the unknown-user and wrong-password paths to avoid a timing oracle).
**Pinned by:** `TestKnownGoodIPExemptFromUserLock` (a known-good bucket is exempt; a new bucket and the empty bucket are subject), `TestKnownGoodExemptionExpires` (a `knownGood` entry past `knownGoodTTL` is no longer exempt), and the end-to-end `TestLoginKnownGoodIPExemptFromAccountLockout` (operator's IP logs in → known-good; a LAN host hammers the account to the lockout; the operator's IP STILL logs in with the correct password while a new-IP attacker gets 429). Sabotage-verified: removing the known-good check from `checkUserLock` makes `TestLoginKnownGoodIPExemptFromAccountLockout` fail (the operator's login is a 429, not a 200).

## sensor-delete-alert-state (alerts.go `setAlertState`, store.go schema, 2026-11-10)
**Decision:** `setAlertState` now uses the reviewer's guarded upsert (`INSERT ... SELECT id FROM sensors WHERE id = ? ON CONFLICT ...`): for a sensor deleted concurrently, the SELECT yields no row and nothing is written, so alert state can never be resurrected for a deleted sensor. The DELETE handler is unchanged — its single `DELETE FROM sensors` already cascades.
**Why:** the finding's two orphan-row mechanisms were both already closed: (1) the schema declares `ON DELETE CASCADE` on probes, events, sensor_tags AND alert_state, and `store.NewStore`'s DSN enables `foreign_keys(1)` on every connection, so the delete cleans up all child rows atomically (verified — no missing-CASCADE bug); (2) an in-flight `setAlertState` on a deleted sensor failed at the FK check and the `_, _ =` swallowed the error — no resurrection, but the invariant was IMPLICIT (depended on the DSN pragma) and SILENT (error discarded). The guard makes it explicit and self-contained: it holds even on a bare FK-OFF connection, and the statement is atomic (no delete/upsert TOCTOU). The third sub-claim — the per-sensor alertGateConsumer drains ≤8 queued + 1 in-flight alerts for a deleted sensor — is TRUE and accepted by design (documented at `alertGateConsumer`/`Remove`): bounded, one-shot, self-reaping on `alertGateIdle`, no goroutine leak; the alerts were legitimately triggered pre-deletion, and delivering them mid-storm is arguably correct.
**Pinned by:** `TestSensorDeleteCascadesAlertState` (delete → probes/events/sensor_tags/alert_state all 0 rows), `TestSetAlertStateDeletedSensorNoResurrection` (bare `sql.Open` connection, FK OFF: the child row survives the delete, and `setAlertState` leaves that row UNTOUCHED — the old plain INSERT would have updated it via ON CONFLICT; positive control: a live sensor upserts insert-then-update exactly as before). Sabotage-verified: restoring the plain `VALUES` INSERT fails the resurrection test on the FK-OFF connection.

## redirect-ssrf-dns-rebinding (http.go `redirectTargetAllowed` / `CheckRedirect` / `probeDial`, 2026-11-05, re-pinned 2026-11-10)
**Decision:** `redirectTargetAllowed` resolves the hostname and returns the checked IPs alongside the error. `CheckRedirect` records a pin (lower-cased hostname → checked IP) in a per-probe map on the request context; it does NOT rewrite `req.URL`. The transport's `DialContext` (`probeDial` → `probeDialTLS`) dials the pinned IP for that hostname while keeping the URL's hostname for SNI and cert verification. The initial target is NOT pinned (operator's own sensor, admin privilege by design); only cross-host redirect hops are pinned.
**Why:** the old check-then-dial had a TOCTOU window: `redirectTargetAllowed` resolved the hostname and checked the IPs, then the transport resolved the SAME hostname again when dialing. A DNS-rebinding attacker (LAN DNS control) could return a public IP at check time (allowed) and a loopback/link-local IP at dial time (the check never saw it). The fix is the same pattern `webhook.go`'s `dialChecked` already uses — validate the IP at dial time by pinning the dial to the checked address. Pinning at DIAL time (not by rewriting the URL to the IP) is what keeps the hostname for SNI + cert verification: an IP-literal URL would blank the SNI (RFC 6066 §3) and force IP-literal cert verification, breaking DNS-name certs on cross-host hops. Plain-HTTP pinned hops force a fresh connection so a pooled unpinned connection is not reused.
**Pinned by:** `TestProbeHTTPRedirectRebindingClosed` (`review_fixes_test.go`) — a fake DNS-over-UDP responder returns 203.0.113.1 on the first lookup (check passes) and 127.0.0.1 on the second (rebinding); a loopback stand-in server on the rebinding port must NOT receive the request. `TestProbeHTTPCrossHostRedirectKeepsHostname` — a cross-host hop to a DNS-name cert verifies against the hostname (not the pinned IP). Sabotage-verified: unpinning the dial (dial the hostname, not the checked IP) makes the rebinding test dial 127.0.0.1 and mark up.

## sensor-spec-dedup (sensor_spec.go, api.go, probe.go, store.go, 2026-11-05)
**Decision:** Sensor validation (ranges, defaults, cross-field rules) now lives in a single `sensorSpec` struct (`sensor_spec.go`) with `applyDefaults()`, `validate()`, `validateCrossField()`, `clamp()`, and a free `validateSensorRange()` helper. POST uses `applyDefaults()` + `validate()`; PATCH uses `validateSensorRange()` per-field + `validateCrossField()` in-tx; clone uses `clamp()`. The legacy `type=''→'icmp'` normalization (6 read paths) is replaced by a one-time migration in `InitSchema()` (`UPDATE sensors SET type='icmp' WHERE type=''`).
**Why:** the old code had the same ranges, defaults, and type normalization in 5+ places (POST, PATCH, clone, fetchSensors, handleSensorByID GET, syncSensors, PingNow). A drift bug in one copy (e.g. changing a range in POST but not PATCH) would be invisible until the other path was exercised. The `sensorSpec` struct makes the ranges, defaults, and cross-field rules live in ONE place; the migration makes the DB the single source of truth for the probe type, so the read paths no longer need to normalize.
**Pinned by:** existing sensor tests (`TestCloneClampsLegacyParams`, `TestPatchSingleReadValidation`, `TestAPIHTTPTargetValidation`, `TestSensorNameXSSRejectedEndToEnd`, and the full API test suite). The migration is idempotent (a no-op on a fully-migrated DB).

## cert-freshness-conn-reuse (http.go `probeHTTP`, 2026-11-05)
**Decision:** `probeHTTP` sets `req.Close = true` (forcing a fresh TLS handshake) only when the host's cert was last read more than `certFreshness` (10 min) ago. The `certReadTimes` map (keyed by `scheme://host`, the same key the transport uses for connection pooling) records the cert read timestamp after every successful probe with cert data. Redirect hops always force a fresh conn (they're rare, and the redirect target's cert is what we want to capture).
**Why:** the old M5 design forced a fresh handshake on EVERY HTTPS probe to keep the displayed cert expiry fresh. At homelab scale the cost is cheap, but it is unnecessary: the transport's `IdleConnTimeout` is 10 min, so a pooled connection's cert is at most 10 min old. A cert renewal is rare (90 days for Let's Encrypt, a year for a CA cert), so 10 min staleness is negligible. The optimization saves one TCP+TLS handshake per probe for the vast majority of probes (only the first probe to a host, and probes after a 10-min gap, pay the handshake cost). The reported RTT is unchanged (it starts at `GotConn`, which excludes the handshake cost).
**Pinned by:** `TestCertFreshnessReusesConn` (`review_fixes_test.go`) — first probe records the cert read; second probe (immediately after) updates the timestamp; a backdated entry (past `certFreshness`) triggers a re-read. `TestProbeHTTPTLSFreshHandshake` (`http_test.go`) — 3 HTTPS probes produce 2 distinct connections (probe 1 fresh+closed, probes 2-3 reuse probe 2's pooled conn). Sabotage-verified: restoring the unconditional `req.Close = true` makes `TestProbeHTTPTLSFreshHandshake` fail with 3 connections.

## tcp-sensor (tcp.go `probeTCP`, probe.go `probeTarget`, 2026-11-09)
**Decision:** Added a `tcp` sensor type: target is `host:port` (port REQUIRED, 1-65535; host is the same shape `validTarget` accepts for ICMP — IPv4, dotted hostname, bare single-label LAN name). The probe is one-shot: `resolveICMPTarget` (the ICMP path's bounded, cached resolver) then `net.Dialer.DialContext` to the resolved IP literal; up = connect succeeded, RTT = connect time (DNS + TCP handshake, the HTTP TTFB stance — ICMP's echo RTT excludes DNS, TCP's includes it, and the difference is documented, not hidden). The conn closes immediately (a port check is one-shot; a held conn would mask a server that accepts but never serves). No keep-alive, no goroutine, no persistent socket — same shape as `probeHTTP`, simpler (no TLS, no status codes).
**Why:** the ICMP+HTTP model left non-HTTP services (Postgres, SSH, SMTP) unmonitored — an open-but-dead database reads as "host is up" forever. A raw port check is the highest-value in-lane black-box check (recommended over in-cluster metrics, which stay Grafana's job). Resolution reuses `resolveICMPTarget` instead of letting `net.Dial` resolve so (a) a dead local resolver reads as a `dns_error` row, not "N hosts down" — the same stance ICMP and the DNS-storm fix established, and (b) the short-TTL DNS cache with stale fallback is reused (no per-tick DNS for the same hostname). Dialing the IP literal means no second resolution inside `DialContext`. IPv6 is rejected at save time, matching the product's IPv4-only stance everywhere.
**Pinned by:** `tcp_test.go` — `TestValidTCPTarget` (16-case table: port required, range 1-65535, single-label/dotted/IPv4 hosts, IPv6 + whitespace rejected), `TestProbeTCPOpenPort` (live loopback listener: !lost, rtt>0, ip), `TestProbeTCPClosedPort` (refused conn is lost, NOT classified DNS), `TestProbeTCPTimeout` (TEST-NET-1 192.0.2.1 runs out its 400ms budget), `TestProbeTCPDNSFailure` (RFC 2606 `.invalid` → lost + DNS:true + empty IP), `TestProbeTargetDispatchesTCP` (the `probeTarget` dispatch arm end-to-end, http fields stay nil), `TestNormalizeProbeTypeTCP`, `TestSensorSpecValidateTCP` (cross-field: portless/out-of-range/URL-as-tcp all rejected).

## storm-summary-target-mention-safe (alerts.go `stormSummaryMarkdown`, 2026-11-10)
**Decision:** `stormSummaryMarkdown` passes the target through `discordMentionSafe(alertTarget(e.target))`, exactly like `discordCard`/`discordCardRe`. The target stays verbatim w.r.t. `mdEscape` (n4 rule — no backslashes in the URL), and the Telegram (HTML) / SMTP (plain) summaries are untouched.
**Why:** the storm summary is sent to Discord (`case "discord"` in `deliverStormSummary`). The payload carries `allowed_mentions: {parse: []}`, which handles compliant clients — but the codebase's stated stance (comment in the payload builder) is that `discordMentionSafe` is the belt-and-braces layer for bridges/clients that ignore the field. The per-sensor Discord cards already neutralize name AND target; the summary neutralized the name only, so a sensor target like `https://example.com/@everyone` (legal — validTarget accepts arbitrary URL paths) mass-pings the whole channel in a storm summary while the individual cards stayed quiet. One-line asymmetry, same class as the name-neutralization fix (2026-10-24 n2).
**Pinned by:** `TestStormSummaryMarkdownTargetMentionNeutralized` — `@everyone` in a target path and `@here` after userinfo-stripped credentials both render ZWSP-neutralized, no raw mention token survives the markdown, and the plain/HTML summaries stay ZWSP-free. Sabotage-verified: dropping the `discordMentionSafe` wrap on the target fails the test.

## settings-put-snapshot-reload-deferred (api.go `handleSettingsPut`, 2026-11-10)
**Decision:** `handleSettingsPut` defers `s.probeWorker.reloadAlertSettings()` immediately after the settings `tx.Commit()` succeeds (replacing the single explicit call at the handler's end). The two maintenance-mode store calls run through `enterMaintenance`/`setMaintenanceMode` function-var seams (same pattern as `deliverDestinations` in alerts.go) so a test can force the post-commit failure path.
**Why:** the settings tx commits FIRST, then the maintenance-mode tx (its own transaction) runs. If the maintenance tx failed with a 500, the old handler returned BEFORE the explicit `reloadAlertSettings()` — the provider/routing/realert_min changes in the SAME PUT were persisted in SQLite but `pw.alertCfg` stayed on the old snapshot until the next successful PUT /api/settings or a restart. The defer makes every committed save converge memory to the store on every path (happy path, enter-maintenance 500, leave-maintenance 500). `reloadAlertSettings` is idempotent and keeps the last good snapshot on a read error, so the defer is safe on all paths; a failed maintenance tx leaves the DB's maintenance flag as the settings tx committed it, so the reloaded snapshot is consistent with the store.
**Pinned by:** `TestSettingsPutReloadsSnapshotWhenMaintenanceTxFails` (settings_patch_test.go) — both 500 paths: the settings tx commits (realert_min persisted) and the snapshot follows (`pw.realertMin()` reads the new value lock-free) despite the 500. Sabotage-verified: removing the defer (restoring the old end-of-handler call) fails both subtests.

## delete-rows-batched-args-hoisted (api.go `deleteRowsBatched`, 2026-11-10)
**Decision:** the argument slice (`args` + `purgeBatchSize`) is built once per call, above the batch loop, instead of `append(append([]any{}, args...), purgeBatchSize)` on every iteration. `ExecContext` only reads the args, so the hoisted slice is safe to reuse; the defensive copy of `args` is kept (a future caller may pass a slice with spare capacity).
**Why:** a full-table history wipe loops 1.7M/purgeBatchSize (5000) ≈ 340 times, and the in-loop append allocated a fresh `[]any` on every iteration — pure churn on the app's heaviest write path. Measured on the gate box (2-vs-7 batch spread, both with and without -race): the wipe's allocation delta per extra batch was 6.9 pre-fix (database/sql baseline ~5.9 + 1 slice) and 5.9 post-fix; behavior is byte-identical (the slice contents never change).
**Pinned by:** `TestDeleteRowsBatchedArgSliceBuiltOnce` (clear_history_batch_test.go) — Mallocs-counter measurement (GC before each run, re-seeding outside the window) asserts the per-extra-batch delta stays at the driver baseline (threshold 6.50, midway between the measured 5.9 and 6.9). The 2-vs-7 spread is deliberate: at a 2-batch spread the 1-alloc difference is inside the ±1 measurement noise. Sabotage-verified: restoring the in-loop append fails the test at ~6.9. Behavioral coverage (exact totals, filter isolation, empty table) stays in `TestDeleteRowsBatchedFilters` / `TestDeleteRowsBatchedAllAndEmpty`.

## testwebhook-discord-payload-shape (alerts.go `TestWebhook`, 2026-11-10)
**Decision:** `TestWebhook` builds its webhook bodies as `map[string]any`, and the discord test payload now includes `"allowed_mentions": {"parse": []}` — structurally identical to the production delivery payloads (`deliverOne` and `deliverStormSummary` both send `{"content", "allowed_mentions": {"parse": []}}`).
**Why:** the test button is where an operator verifies their webhook config. The pre-fix discord test body was `map[string]string{"content": ...}` — no mention-injection risk (hardcoded text), but a payload shape the production path never sends is a weaker verification: a bridge that chokes on `allowed_mentions` would pass the test button and fail real alerts. The telegram and google_chat test bodies were already shape-identical to their production counterparts; only discord diverged.
**Pinned by:** `TestTestWebhookDiscordPayloadMatchesDelivery` (testwebhook_status_test.go) — captures the test-alert POST body and asserts it decodes to an object with `content` and `allowed_mentions.parse == []`. Sabotage-verified: dropping the `allowed_mentions` field fails the test.

## downafter-retention-bound (sensor_spec.go, api.go, status.go, 2026-11-10)
**Decision:** `validateCrossField` rejects a sensor whose `down_after × interval_s` exceeds the 24h probe-retention window (`retentionSeconds`); the clone path's `clamp()` floors `down_after` to `retentionSeconds / interval_s` (adjust, don't reject — same stance as how `clamp` already floors a timeout that exceeds the interval). The PATCH in-tx cross-field check now reads `down_after` from the row (added to the single-read SELECT, overlaid with the request value) so the rule applies on every write path, mapped through a dedicated `errPatchDownAfterExceedsRetention` sentinel to a 400.
**Why:** `deriveStatus` reaches `error` only on `down_after` CONSECUTIVE losses (status.go), but `purgeOld` keeps just 24h of probes, so the longest observable loss run is `24h / interval_s`. When `down_after × interval_s > 24h` (e.g. interval_s=3600, down_after=30 → 30h), a 100%-dead sensor can never accumulate `down_after` straight losses: it reads `warning` forever (100% window loss ≥ loss_warn) and never `error`. Warnings are never alerted, so a dead host is a silent non-alert — the worst failure mode for a monitor. Rejecting the combination at write time keeps every stored sensor able to actually reach `error`. Rows created before this rule are untouched (validation runs on write); editing one now forces the operator to fix the combination, which is the point.
**Pinned by:** `TestValidateDownAfterRetention` (8-case table: 3600×30 and 1800×49 rejected, the 24h-boundary equality 3600×24 / 1800×48 accepted, small-interval maxes accepted) and `TestClampDownAfterRetention` (clone floors 3600×30→24 and 1800×50→48, leaves 60×100 and 3600×1 untouched, and a clamped spec always passes validate). Sabotage-verified: removing the `validateCrossField` rule makes `TestValidateDownAfterRetention` fail on both rejection cases.

## alert-retry-budget (alerts.go `alertRetryDelays`/`maxAlertRetryAfter`, 2026-11-11)
**Decision:** `maxAlertRetryAfter` 60s → 10s; `alertRetryDelays` KEEP {2s, 10s}. New invariant, stated in-code and pinned: the worst-case in-band delivery job (3 webhook attempts × 10s client timeout + the two in-band sleeps, each `max(alertRetryDelays[i], maxAlertRetryAfter)` per `retryAlert` = **50s**) must stay **under `recoveryRetryDelay` (60s)**.
**Why:** the finding's mechanism verified end-to-end. `alertGateConsumer` drains a sensor's 8-slot FIFO serially, and every in-band retry sleep happens inside that consumer, so one degraded provider sets the queue's drain time: with the 60s Retry-After cap, one 429-with-Retry-After job costs 3×10s + 60+60 = **150s**, the whole queue ~20 min, and completions (24/h) fall BELOW a sustained-error sensor's 1/min re-alert arrivals (scheduleAlertRetry backdates to ~1m) — saturation guaranteed, not incidental. A recovery alert arriving into the full 8-slot buffer is dropped (non-blocking enqueue, by design), and M1's single re-offer fires at +60s — mid-saturation, the consumer has popped ZERO jobs, so the retry hits the same full buffer and the recovery notification is LOST permanently (the exact harm M1 was added to prevent; the finding cites it, correctly). After the cap the worst job is 50s < 60s: completions (72/h) exceed arrivals (60/h), the queue always drains faster than it fills, and the +60s retry always finds room (worst delivery ≈ 60 + 7×50s ≈ 6.4 min, in order). DEVIATED from the suggested {1s, 3s} delays: the 2s/10s shape (worst job 42s without Retry-After) already satisfies the invariant, and 1s/3s would shave the in-band ride-through margin for transient 502 blips (LB failover) for zero additional FIFO health — the 150s shape is driven by Retry-After ALONE, so the cap is the load-bearing change.
**Residuals (accepted, documented):** (1) SMTP tarpit worst case is 3 × (10s dial + 15s conversation) + 12s = 87s/job > 60s — the invariant's arithmetic is webhook-shaped; a tarpitting relay (accepts TCP, sends nothing; a DEAD relay fails fast) needs 8 queued SMTP jobs to reproduce the congestion, and M1's exactly-one-retry contract stays as written (2026-11-10). (2) Wide-storm shape: recoveries bypass the storm budget by design and enqueue directly, so a broad multi-sensor storm + a degraded provider can still fill several per-sensor FIFOs; the structural fix for that is supersede/coalesce-on-arrival inside the gate (drain stale queued jobs when a newer transition arrives — the storm path already dedupes this way, "the older line is stale by definition"), which is a larger redesign of the gate's element type (queued jobs are opaque closures carrying a done channel; removing them without running parks their sendWebhook caller — m1 hazard). Deferred as a product decision. (3) The storm summary has NO outer retry, so rate-limited providers see fewer in-band attempts (3 in ~50s vs 3 in ~3.5 min); it is best-effort and logs on total failure. (4) Lower cap = provider rate-limit windows get re-hit sooner in-band (10s vs 60s); the outer retry re-offers at ~1 min, so total re-hit cadence against a 60s window is ~110s — respected.
**Pinned by:** `TestInFifoRetryBudgetUnderRecoveryRetryDelay` (arithmetic guardrail over the real constants + the 3-attempt shape). Sabotage-verified: restoring `maxAlertRetryAfter = 60 * time.Second` fails with worst = 150s >= 60s.

## login-lockout-429-refund (auth.go `handleAuthLogin`/`handleAuthUserPassword`, 2026-11-11)
**Decision:** the per-username lockout's 429 path in BOTH handlers now calls `refundAttempt(key)` before answering, so a request rejected by `checkUserLock` never charges the caller's per-IP budget.
**Why:** the ordering is deliberate (per-IP gate first so a locked IP gets its fast 429 before the account check), but `beginAttempt` counts the attempt at admission, and the account-lockout return path dropped it without a refund — while `refundAttempt`'s own contract (and the n6 fix it carries) says throttling exists for KDF cost and admissions that never pay it are refunded (the setup-bootstrap paths already honor this; login/password did not). Concrete harm (verified): attacker IP A locks the account with 7 real failures; every fresh-IP client — new device, DHCP change, no known-good exemption (2026-11-10 #4 exempts only IPs with a recent SUCCESSFUL login) — that retries `loginFailMax` times while reading the 429 trips its OWN 5-minute per-IP lockout on requests that ran zero bcrypt KDFs, persisting past the account lockout's expiry. The attacker's single account-lockout therefore also mass-locks the operator's LAN peers; the codebase's documented recovery for a locked operator was the out-of-band CLI (`pulsemon auth-user`), which is a workaround, not a design.
**No auth-strength regression:** the refund applies ONLY where the KDF never ran (account lockout 429). A genuine attacker pays real KDF failures for their lockouts (the beginAttempt-rejection path and the 401 path are unrefunded); spamming the 429 path runs no verification, so unbounded 429s there authenticate nothing, and the n6 arm (refund clears a lockout once the count drops below the threshold) closes the burst-trip shape.
**Pinned by:** `TestLoginThrottleAccountLockoutRefundsFreshIP` (account locked → fresh IP fires loginFailMax+2 attempts, all 429; lockout lifted → correct login from the SAME fresh IP must 200) and `TestChangePasswordLockout429RefundsFreshIP` (same shape on the password endpoint with the bearer session). Sabotage-verified: removing the two `refundAttempt` calls makes both new tests fail at their final assertion (fresh IP self-locked → 429 where 200 is required).

## knowngood-bound (auth.go `beginAttempt` sweep trigger / hard-cap wipe, 2026-11-11)
**Decision:** the opportunistic sweep trigger and the hard-cap wipe in `beginAttempt` now watch `len(knownGood)` alongside `len(fails)` and `len(userFails)` — the same three-way trigger shape `userfails-bound` (2026-11-10) established.
**Why:** the knownGood field comment promised "Bounded by sweepThrottle", but the sweep was keyed on the two maps the attacker does NOT grow: `loginSuccess` deletes the ip from `fails` and inserts it into `knownGood` (30-day TTL = `authSessionMaxAge`), so successful logins from rotating source buckets — IPv6 /64s, or XFF rotation behind a correctly-configured trusted proxy — keep `fails`/`userFails` at ~0, the trigger never fires, and `knownGood` grows for 30 days with no bound. The rate is KDF-gated (one full bcrypt login per entry, sem-capped at NumCPU concurrency), so this is a slow-burn, credential-gated growth (script, or compromised viewer credential) — the memory vector the per-username layer already treats as in-scope; the hard cap (131072 ≈ tens of MB, all-or-nothing wipe that already resets knownGood) is the true bound under a sustained spray, the sweep the routine reclamation.
**Pinned by:** `TestLoginThrottleSweepTriggerWatchesKnownGood` (1-entry fails + expired knownGood entries past the shrunken threshold → beginAttempt prunes them) and `TestLoginThrottleKnownGoodHardCapWipe` (1-entry fails + fresh knownGood past the shrunken cap → all-or-nothing wipe, only ip2's entry survives). Sabotage-verified: removing the `len(knownGood)` term from the trigger fails the first test at the survival assertion; removing it from the cap guard fails the second at `knownGood size = 5, want 0`.

## read-fail-loud (api.go/store.go tag + settings reads, 2026-11-11)
**Decision:** the tag reads on the request path (`AllTags`, `SensorTags`, `SensorTagsFor`) now carry the request ctx and RETURN their errors instead of swallowing to empty, and `settingsPayload` reads every key through `GetSettingErr` — a settings read failure is a 500, never a 200 of defaults. Each caller owns the failure policy: request callers fail the request (`fetchSensors` nil sentinel, `respondInternal` at the three handler sites); background `syncSensors` keeps the 2026-10-24 untagged-routing tradeoff and logs with the same message (store-level logs moved to the caller).
**Why:** the swallow shape made a dead client ctx or transient DB failure render as truth: GET /api/tags answered `{}` ("the fleet has no tags"), and — the dangerous one — GET /api/settings answered CONCRETE DEFAULTS (`alert_scope:"all"`, `realert_min:30`, `maintenance_mode:false`) with a 200. The dashboard's alerts form seeds itself from that payload (`openAlerts()` fills `f-scope`/`f-realert`) and PUTs those fields back on save, so one swallowed read failure plus one innocent form save writes fabricated defaults over the real settings. The ctx half is the same fast-fail contract `TestFix_HandlerDBCallsHonorRequestContext` pins (pool-level; the driver's busy_timeout window is not interruptible — that caveat is pinned there).
**Pinned by:** `TestFix_SettingsAndTagsReadsFailLoudly` (live ctx → 200 with real payloads; canceled ctx → AllTags/SensorTags/SensorTagsFor error + tags GET 500; closed store → settings GET 500, pre-fix renders the 200-of-defaults body) and `TestSensorTagsForLogsQueryFailure` (reworked: store returns the error; syncSensors logs it). Sabotage-verified compile-clean: ctx-ignoring `db.Query` swaps fail all ctx pins; discarding the six settings error-checks fails the settings pin with exactly the fabricated-defaults body.

## oversized-login-guard (auth.go `handleAuthLogin`, 2026-11-11)
**Decision:** `/api/auth/login` rejects overlong credentials — `len(username) > maxUsernameLen` (32) or `len(password) > 72` — with a 400 immediately after decode: BEFORE `strings.ToLower`, the `checkUserLock` map hash, the `userExists` SQL bind, and the per-IP throttle charge.
**Why:** authGate caps every body at 1 MiB (sized for TLS cert uploads), and login decoded before any length check, so an unauthenticated attacker paid the server a 1 MiB alloc + ToLower + map-hash + SQLite index lookup per request with a credential-attempt charge behind it. AddUserMode enforces both bounds at creation (and bcrypt rejects >72), so an overlong pair can never match any account — it is structurally invalid input, the same category as empty credentials: no KDF will run, so it is NOT a credential attempt → 400, uncharged. The setup route already rejects these pre-KDF (AddUserMode sentinels + setup refund); login was the asymmetric half. The reviewer's "charge + delay so it's indistinguishable" variant was rejected: the 400 validation channel is the house's established response to structurally invalid bodies (it reveals nothing about accounts — enumeration lives in the 401 space), and charging it reopens the finding #2 shape (429s that never ran a KDF burning IP budget).
**Pinned by:** `TestLoginOversizedCredentialsRejectedPreDB` (900 KiB name/password → 400 validation, not 401; loginFailMax+2 oversized attempts never 429; 32/72-byte boundaries stay credential attempts (401); users table DROPPED → oversized still 400 while a normal login 401s via the store — the asymmetry pins "guard runs before ANY DB work"). Sabotage-verified compile-clean: removing the guard answers the 1 MiB username with the dummy-KDF 401.

## crossfield-sentinel-errors (sensor_spec.go/api.go PATCH mapping, 2026-11-11)
**Decision:** `validateCrossField` rejections now carry their PATCH sentinel INSIDE the error (`crossFieldError{msg, code}` with `Unwrap`), and the PATCH closure returns the error directly; the existing outer `errors.Is` switch maps it. The old closure re-derived the mapping from `strings.Contains(err.Error(), "URL" / "timeout" / "down_after")`.
**Why:** the substring mapping coupled the API's 400 routing to validation MESSAGE wording: any wording tweak (or a future target message containing one of those words) silently mis-routes the client's 400 — e.g. a timeout rejection answering with the target message. TCP targets were already riding the default branch (no listed substring matches), i.e. the mapping's correctness for that rule is pure fallthrough coincidence. The sentinel code is the rule's identity; it belongs in the error, not in a text scan. `Error()` keeps the exact detailed text, so the POST 400 bodies (client-visible contract, example included) are unchanged.
**Pinned by:** `TestPatchCrossFieldSentinelsNotSubstrings` — five PATCH cross-field cases (http/tcp/icmp target, timeout×interval, down_after×retention, all in sensorBounds so each reaches the cross-field gate) must each 400 with THEIR message; the POST detailed-text pin guards the shared `Error()`. Sabotage-verified compile-clean: stripping the five sentinel codes (plain `errors.New`) lands all five PATCH cases on the closure's outer default → 500, failing every case.

## renewal-cookie-maxage-cap (auth.go `CookieRenewalDue`, 2026-11-11)
**Decision:** the sliding-cookie re-issue lifetime is `min(authSessionTTL, created + authSessionMaxAge − now)`: `CookieRenewalDue` returns the capped lifetime as a third value, the gate re-issues through `setAuthCookieLifetime` with it, and a session at/past the absolute cap gets no renewal at all (the method already refused renewals for unknown/expired sessions; the cap joins that set).
**Why:** the renewal checked only the SLIDING expiry (`!now.Before(s.expiry)`) and stamped a full `Max-Age=authSessionTTL` (7d) cookie. A renewal on day 29.x therefore handed the browser a cookie it believed was a fresh week — while `ValidSession`/`SessionUser` kill the session at day 30. Not a bypass (the server-side cap holds — the finding agrees), but a lying client: a cookie window that outlives server validity by up to a TTL, keeping the dashboard in a "has a cookie, every request 401s" state and re-uploading the dead token on every request until the browser's own expiry. Capped, the browser drops the cookie exactly when the session dies.
**Pinned by:** `TestFix_RenewalCookieCappedByMaxAge` (method-level: day-10 renewal → full TTL, day-29+1h → ~23h cap, past-cap → no renewal; gate-level: real login, aged to day 29, the Set-Cookie on the next request carries Max-Age ≈ 1d, not 7d, same token). `TestFix_SessionCookieSlides`' full-TTL re-issue pin passes unchanged (a young session has 30d remaining > 7d TTL). Sabotage-verified compile-clean: removing the cap answers day-29 with 168h.

## alert-target-last-at (alerts.go `alertTarget`, 2026-11-11)
**Decision:** the alert-card userinfo strip mirrors net/url's parse boundary: the authority runs from after `scheme://` (or after a leading `//` for a scheme-relative URL) to the first path/query/fragment separator, and the cut lands at the LAST `@` in it — not the first.
**Why:** net/url's `validUserinfo` permits a raw `@`, so `https://admin:p@ss@nas.lan/health` probes as user `admin` / password `p@ss`, but the first-`@` cut shipped `https://ss@nas.lan/health` into the Discord/Telegram/SMTP card — a password FRAGMENT leaving the network, which is worse than the documented "API returns targets verbatim" trade-off (DEFERRED.md) because the card is third-party-visible. The guard's `u.Scheme == ""` early-return leaked the scheme-relative form (`//admin:secret@nas.lan/health`) whole; unreachable via validURL (http/https only), fixed as defense-in-depth.
**Pinned by:** `FuzzAlertTarget` — seed baselines pin both leaks (RED-proven against the old code: `"https://ss@nas.lan/health"`, verbatim `//` form), and the fuzz property is the RE-PARSE invariant (output parses with `User == nil` and `Host` preserved), the fuzz-sound form of "output never contains `u.User.String()`": raw containment false-positives on URLs whose host equals the userinfo string (`https://ab:ab@ab:ab/x` legitimately strips to host `ab:ab`). 30s campaign (456k execs) clean.

## structure-and-comment-density (repo-wide, 2026-11-11)
**Decision:** the proposed split into `internal/{probe,auth,alert,api}` with constructor-injected dependencies is REJECTED. The comment-density concern is accepted as a FORWARD-LOOKING style rule: a comment leads with the contract/invariant; incident history belongs in DECISIONS.md and commit messages; in-code provenance tags (date, review ID) stay at one line. The explicit `probeDialTLS` invariant line was added as the exemplar.
**Why (split):** the package vars the review names as the problem (`probeTarget`, `certReadTimes`, `alertGateIdle`, `resolveIPAddrWithTimeout`, plus `bindFatal`/`certFatal`/`reexecFn`/`deliverDestinations`/`smtpConnDeadline`) ARE the test seams — the 139-test-file suite lives in `package main` precisely so it can stub them (the record-seam + fatal-panic-stub house patterns). internal/* + constructor DI forces a rewrite of the entire harness surface for zero behavior change, and a multi-thousand-line behavior-neutral move is exactly the class of "simplifying edit" that finding calls the likeliest source of the next regression. The seams that genuinely separate (db store, probe worker, alert-settings snapshot) are already constructor/field-injected; a single-binary, single-operator, trusted-LAN tool does not pay package-boundary ceremony.
**Why (comments):** the provenance tags are the external-review adjudication ledger — each dated `Security-review note`/`Review note` marks a finding already adjudicated, and DECISIONS.md/DEFERRED.md carry the full narrative the tags point into. Stripping the tags from code re-opens every fixed finding to re-flagging in the next batch (this repo has run 10+ review batches against exactly this ledger).
**Why (t.Parallel):** verified 0/139 test files, not 1 — and the cause is not comment style: probes share a single ICMP socket, `certReadTimes`, the throttle maps, per-test SQLite files, and bind ports, so parallel-safety is a CONSEQUENCE of the DI refactor, not an independent fix. The suite runs ~5.5 min under -race; the parallelism yield does not cover the shared-state audit.
**Fact-check of the named examples:** `uaRoundTripper` (4 lines) and `newHTTPServer` document their contract/timeout rationale, not history; `probeDialTLS` already opened with its zero-bytes contract. Measured non-test density: api.go 2,790 lines/32% comment, auth.go 2,141/45%, alerts.go 35%, probe.go 41%; 155 provenance-tagged comment lines across 33 non-test files (20 strictly date-stamped).
**Pinned by:** none — comment/doc-only change; full -race suite run as the gate per standing rule.

## req-close-fresh-dial (http.go probe client, 2026-11-11)
**Decision:** `req.Close = true` alone never forced a fresh connection — `Transport.getConn` takes an idle pooled conn regardless of `Request.Close`; the flag only keeps the conn OUT of the pool afterwards (verified empirically on Go 1.26: warm pool + flag = zero dials). The probe client now routes EVERY flagged request (stale-cert probe, pinned/HTTPS redirect hop) through `probeFreshTransport` — a clone of the pooled transport with `DisableKeepAlives = true` (pool empty by construction, so every flagged request DIALS) — in `uaRoundTripper.RoundTrip`.
**Why:** two comments claimed the flag forces a fresh conn, and the security half was real: the pool keys on the URL HOSTNAME while the redirect pin map is honored only at DIAL time, so a pinned cross-host hop riding a hostname-keyed idle conn (left by a direct probe of that target, dialed under a DIFFERENT probe's resolution) dials an IP that was never checked by THIS probe's `redirectTargetAllowed` — the DNS-rebinding window the pin map exists to close. The cert-freshness half: the stale-cert re-read landed one probe late (the flag rode the pool, so the "fresh" handshake reported the ORIGINAL handshake's cert). `TestProbeHTTPTLSFreshHandshake`'s 2-conn pin is unaffected (probes 2-3 reuse WITHIN certFreshness, unflagged).
**Test-companion (the review's requested dial-count tests):** `TestReqCloseRoutesFlaggedRequests` (router unit), `TestPinnedRedirectHopDialsFreshConn` (pool pre-warmed with an idle conn for the redirect target; the hop must open a THIRD connection — RED-proven: old code rides the pooled conn, 2 conns), `TestStaleCertProbeForcesFreshDial` (backdated certReadTimes entry; stale probe must re-dial — RED-proven: old code 2 conns). All three sabotage-verified against the un-routed transport.
**Race-gate fix (same change's fallout):** Go 1.26's `getConn` DETACHES the dial ctx from the request ctx, so `TestProbeHTTPRedirectRebindingClosed`'s hop dial to blackholed 203.0.113.1 (probeDialer = `&net.Dialer{}`, no timeout) outlived the 5s probe timeout and raced the test's deferred restores / later tests' `probeDialer` writes. The test now stubs `probeDialer` with a 2s Timeout so the dial failure lands inside the pending-request window and the result delivery synchronizes the dialConn (happens-before) before any global is restored. Full -race suite ok 325.153s.

## probe-write-handle-busy-cap (store.go + probe.go, 2026-11-11)
**Decision:** finding #4 (external review) VERDICT valid: the `dbWriteTimeout` comment claimed probe-path writes carry their own cap, but only PingNow used it — `doProbe`'s INSERT and transition `ImmediateTx` rode the loop ctx (no deadline), so a stalled writer parked a sensor loop for the full 15s busy_timeout per write phase (two write phases per tick), drifting cadence. The review's proposed remedy (a `context.WithTimeout(ctx, dbWriteTimeout)` wrapper) is DECORATIVE: empirically verified on the pinned driver (modernc.org/sqlite v1.29.1, Go 1.26) that a ctx deadline AND a cancel mid-park cannot preempt a write parked in the busy handler — both returned SQLITE_BUSY at 15.05s against a 300ms ctx. The cap that binds a busy-park is the per-connection `busy_timeout` pragma. Fix: a dedicated probe-write handle — `NewStore` opens a second `*sql.DB` on the same file with `busy_timeout = store.ProbeWriteTimeout` (default 8s; var seam for tests) and `MaxOpenConns(1)` — and probe INSERTs, the transition tx (`ProbeImmediateTx`), and the PingNow write (`ProbeExecContext`) run on it.
**Why:** parked writes are now capped by the DRIVER at 8s, and surplus probe writes queue on the single handle conn in database/sql's `Conn(ctx)` pool-wait, which IS ctx-aware — shutdown cancel aborts a probe queued to write (the old comment's "ctx interrupts a parked write" claim was false; the queue path is where ctx genuinely helps). `Store.Close` shadows the embedded `sql.DB.Close` and closes both handles (`errors.Join`). The main pool keeps the tuned 15s write-coalescing knob for API/auth writes. `purgeOld` deliberately stays on the main pool: it is the long-running sweeper that CAUSES stalls and is already ctx-bounded between batches.
**Tests:** `TestProbeHandleCarriesCappedBusyTimeout` (store pkg: the seam reaches the driver's pragma; main pool stays 15000) and `TestDoProbeWritesCappedUnderWriteStall` (main pkg: real stall via `BEGIN IMMEDIATE` on a main-pool conn; capped doProbe returns in ~0.3s — RED-sabotage proof: old main-pool path parked 15.054s; the write-failure contract holds on the capped failure — status/lastStatus not advanced, no event, transition lands on the next tick).

## probe-rows-int-schema (store.go schema, 2026-11-11)
**Finding #5 (external review):** probes rows carry a 36B TEXT UUID sensor_id + 30B TEXT ts, both repeated in `idx_probes_sensor_ts`; est. 150-200 B/probe; proposal: INTEGER surrogate sensor key + epoch-ms ts ("roughly halves storage", speeds purge + warm), optionally a batching single-writer goroutine. **VERDICT: mechanism verified; optimization deferred — fleet not near the finding's own stated threshold.** Measured on zentest (modernc v1.29.1, WAL synchronous NORMAL, 1,728,000 rows = 100 sensors x 24h @5s — the finding's declared worst envelope): current TEXT schema = **183.6 B/row (317.3 MB)** — the 150-200 B estimate is confirmed; INTEGER key + epoch-ms = **57.6 B/row (99.5 MB)** — "roughly halves" is CONSERVATIVE, it is a 3.2x cut. Purge 5000-row batch at 1.7M rows: 57 ms (TEXT) vs 43 ms (INT); warm phase-1 scan of all 1.7M rows: 6.29 s vs 4.06 s.
**Why deferred:** the growth model is capped, not accumulating — 24h retention (purgeOld, SPEC §3) bounds steady-state disk at ~317 MB AT the declared fleet, purge is already batched (largest statement 57 ms), warmStats is a ctx-aware startup scan that runs once before probing, and inserts at that fleet (~20/s) run on the serialized probe-write handle at ~1% of its measured bulk rate. The batching writer goroutine the finding itself flags adds flush-ordering complexity to `recentFromDB`'s cold path for no observed pressure. The migration would rewrite every ts string-compare site (purge cutoffs, warm windows, sparkline SQL), FK cascade targets, the API ts contract, and shipped-DB data — high blast radius for headroom the retention cap already provides. Live fleet: 22 sensors @60s (~32k rows/day); dev box DB 20 MB. REVISIT when fleets approach hundreds of sensors at second intervals.

## purge-tail-exemption (probe.go purgeOld + stats.go warmStats, 2026-11-11)
**Decision:** finding #6 (external review) VERDICT valid. The live raw tier keeps `max(1h, last 60)` probes, and warmStats phase 2 mirrors that with `ORDER BY ts DESC LIMIT 60` — the documented invariant is DB ⊇ live series. But the startup `purgeOld` (finding #9's fix) deletes every probe older than 24h BEFORE warmStats runs, so the tail past 24h can never exist in the DB: a 1h-interval sensor served 60 probes in its inspector window before a restart and ~24 after, and phase 2 could never fulfil its documented purpose ("may still have older history" — it never did).
**Fix (reviewer's option (a), taken over option (b)):** the probes DELETE exempts each sensor's newest `seriesTailProbes` (60) rows: `AND id NOT IN (SELECT id FROM probes WHERE sensor_id = ? ORDER BY ts DESC LIMIT ?)` — served by idx_probes_sensor_ts, ~60 index probes per batch, ≤36 extra retained rows per slow sensor, zero for fast sensors (their tail is inside 24h). Steady state becomes per-sensor `max(24h window, newest 60)` — exactly the union warmStats loads. events take no exemption (transitions are sparse, nothing mirrors a tail). Option (b) (drop the last-60 rule) was rejected: it degrades the inspector for every slow sensor and deletes the documented `max(1h, last 60)` design. The 24h counters, sparkline, and phase 1 all filter `ts >= cutoff`, so the retained tail cannot contaminate aggregates.
**Companion (constant pin):** the bare `60` literals in probeSeries.append, phase 2's LIMIT, and phase 2's slow-sensor condition are now the single const `seriesTailProbes` so the purge exemption, the series tail, and the backfill can never drift apart.
**Tests:** `TestPurgeOldKeepsLast60Tail` (73 rows @1h → exactly the newest 60 survive, oldest survivor is the seeded 59h row; a ≤60-probe sensor keeps ALL rows including a 25h one — per-sensor tail; old events purge; idempotent second sweep) and `TestWarmStatsRebuildsTailAfterPurge` (purge → warmStats → series holds 60: phase 2 revived). `TestPurgeOldMultiBatchPerSensor` + `BenchmarkPurgeOld` survivor expectations updated 50→60 (50 in-window + 10 newest-old tail) with the oldest-survivor pin moved to the 10th-newest old row. RED-sabotage: exemption stripped → 24 kept / 24 warmed (the exact reviewer divergence).

## cert-reload-fingerprint (main.go hotReloadCert, 2026-11-11)
**Decision:** finding #7 (external review) VERDICT valid. The reload change-detector keyed on mtime alone: a failed reload recorded the broken mtimes and retried only on the NEXT mtime change. An in-place writer (acme.sh deploy, `cp >`) that completes within the same coarse mtime tick as the half-written stat (the kernel stamps mtime from the coarse clock, ~1-4ms granularity) leaves the repaired file with an identical fingerprint — the failed reload pins permanently, and an expired old cert is served until restart. Rename-based (`mv`) deploys are unaffected (fresh inode → fresh tick); the exposure is exactly in-place writers.
**Fix (reviewer's remedy, taken):** the fingerprint becomes (certMT, keyMT, certSize, keySize) — size catches the common half-written file (short write → short stat); plus a `certReloadRetry` backoff (10s, var seam for tests): while a failed reload is `due`, the reload is re-attempted after the backoff EVEN when the fingerprint is unchanged, bounding the same-size-same-tick race that size cannot see. Log discipline preserved from the 2026-10-29 NoRespin fix: the failure logs ONCE per fingerprint CHANGE (the backoff re-attempt of the same broken fingerprint stays silent), so a permanently broken pair costs one line, not one per handshake.
**Tests:** `TestHotReloadCertSizeFingerprint` (break at fixed mtime T, repair in place with mtime forced back to T — only size changes → immediate reload; RED under mtime-only pinning) and `TestHotReloadCertBackoffRecoversSameTickSameSize` (broken content padded to the renewal's EXACT byte length, mtime pinned to the same tick, key fingerprint restored: the renewal is invisible to the fingerprint; fast path serves cached inside the backoff, reload lands after it; RED: pinned forever). The existing `TestHotReloadCert` + `TestHotReloadCertNoRespinWhileBroken` pass unchanged (their handshakes land inside the 10s backoff, so no-respin semantics hold).

## api-route-wrapper-parity (api.go routes(), 2026-11-11)
**Decision:** finding #8 (external review) VERDICT valid — the observation was accurate: /api/tags, /api/events (and the user-management routes) carried explicit requireAuth/requireAdmin wrappers with the sessionFrom-contract rationale ("authorization must not rest on authGate having run"), while GET /api/sensors, /sensors/{id}, /history, /graph, POST /ping, and GET /update-check were registered bare and relied on authGate's 401 alone.
**Adjudication:** "wrap them all" taken — the stronger of the reviewer's two options. Dropping the rationale from tags/events would weaken the posture those routes were written for (a handler must be safe on its own: a future gate change, a route registered on a raw mux in a test/refactor, or any code path that reaches the mux without the gate must not silently widen authorization). With the gate in place the wrappers are idempotent — authGate has already verified the session, so requireAuth is one cookie parse + map lookup on the 5s poll. The public exemptions stay exactly the four sessionless-by-definition endpoints: healthz, auth/status, auth/login, auth/logout (wrapping those would BREAK them — logout is reachable without a session by design).
**Fix:** requireAuth on the six bare reads (sensors GET, sensor-by-id GET, history, graph, ping, update-check); routes() now states the global rule.
**Tests:** `TestAPIRoutesAllSessionWrapped` audits routes() at the source level (every /api/ HandleFunc line wrapped, exemptions pinned unwrapped, parser-drift guard) — precedent: delete_confirm_test.go. `TestWrappedReadRoutesDenyWithoutGate` proves the wrappers are live: auth enabled, NO session, mux served DIRECTLY (gate bypassed) → 401 on all eight authed reads. RED: unwrapping GET /api/sensors fails both (audit names it; bare mux serves 200).

## numbered-transactional-migrations (store.go InitSchema, 2026-11-11)
**Decision:** finding #9 (external review) VERDICT valid. InitSchema probed pragma_table_info per step and ran statements one at a time on the pool; the multi-statement steps were never atomic. The tag migration (INSERT … SELECT + DROP COLUMN) survived a mid-step crash only because INSERT OR IGNORE deduped its replay — a load-bearing accident: any future multi-statement step without that trick is a crash-loop (the google_chat step's documented PRIMARY-KEY crash-loop is exactly this class).
**Fix (reviewer's remedy, taken):** PRAGMA user_version with a 12-step numbered history (append-only; never renumber — fleet DBs are stamped by position). Each step runs in its OWN transaction and stamps user_version INSIDE that same tx, so step + stamp commit atomically: a crash mid-step replays the step whole next boot, never half, never stamped-half. Single ALTERs were already atomic (implicit tx); the win is multi-statement steps 1, 9, 10 and the framework for every future one.
**Conversion model (the part the reviewer's sketch omits):** every existing DB — fleet and fresh fixtures — boots pre-versioning at 0, so its first boot after upgrade REPLAYS the whole list. That is only safe because each step keeps its pragma/data guards INSIDE the tx: on an already-migrated (including freshly baselined) DB every step is a no-op; the version stamp then makes all later boots a pure skip (strictly less startup work than the old every-boot probing). MigrateLegacyAuthToken keeps its deliberate log-and-continue deferral semantics (a failed auth migration must never fail boot; the token is kept and retried) and runs as step 11 on Store methods with a read-only stamp tx.
**Ripple:** six tests (store: status-rename x2, legacy-token retry; main: auth legacy-token x2, legacy-webhook) seeded legacy rows after a stamping InitSchema and relied on every-boot migration re-runs. Ported to the new contract by resetting `PRAGMA user_version = 0` before the replay — the exact state a real pre-versioning DB is in.
**Tests:** `TestSchemaVersionStampedOnFresh` (fresh DB replays + stamps head; re-run is a pure skip), `TestTagMigrationReplayFromZero` (legacy tag column re-introduced, stamp reset → copy+DROP lands atomically, tags in sensor_tags, column gone, head restored), `TestMigrationAtomicRollback` (injected mid-step failure → step writes rolled back AND version unstamped; RED: stamping before the step outside the tx fails it — `user_version stamped for a rolled-back migration: 99 != 12`).

## test-gap-audit (finding #10, 2026-11-11)
**Decision:** four-part test-gap finding, itemized adjudication against the LIVE tree:
1. "No dial-count tests for pinning/cert freshness" — **STALE.** #3 (6be93fb) added exactly these: `TestRedirectPolicyClosesEveryHTTPSHop`, `TestReqCloseRoutesFlaggedRequests`, `TestPinnedRedirectHopDialsFreshConn`, `TestStaleCertProbeForcesFreshDial` (redirect_close_test.go / cert_freshness_test.go) count server-accepted connections end-to-end.
2. "No fuzz test for alertTarget" — **STALE.** #1 (d9204b9) added `FuzzAlertTarget` (fuzz_validators_test.go:180) with the re-parse property (output must re-parse with `User == nil` and preserved `Host`). Re-smoked this session: 202,213 execs clean.
3. "No soak/bench of the write path at N sensors" — **VALID gap, filled.** `TestProbeWriteSoakFleetCadence` (gate-resident): 100 concurrent writers × 20 writes through the dedicated probe-write handle — every write must land, zero SQLITE_BUSY (the handle queues in the ctx-aware pool wait, never busy-fails). First run: 2000/2000 rows, 39.7 ms total ≈ 50,000 writes/s. `BenchmarkProbeWrites` (opt-in, with the other fleet benches): one wave = 100 concurrent hot INSERTs = the 100-sensor @5s duty cycle; measured 2.39 ms/wave on zentest ≈ 42,000 writes/s ceiling vs the fleet's 20 writes/s demand — ~3 orders of magnitude headroom, now a repeatable number instead of a one-off scratch run.
4. "Package-global seams block t.Parallel()" — **ACCEPTED, documented tradeoff (DECISIONS → structure-and-comment-density).** The suite is a single-package integration suite: package globals are deliberate test seams (probeDialer, pollFn, certReloadRetry, fetchLatestReleaseFn, …); tests mutate them with deferred restores and share package-level fixtures, so parallel execution races by construction. Parallelizing means the constructor-DI refactor rejected as high-risk, behavior-neutral churn. The gate cost (~5.4 min on zentest, run in background during development) is the accepted price.
**Tests:** items 1–2 verified by re-running the cited tests (fuzz 15 s smoke); item 3 added as above; item 4 is a policy record. Full -race gate green on the combined tree.

## nit-batch-20261111 (nits, 2026-11-11)
**Decision:** all four nits valid, all taken; sabotage-proven.
1. **uaRoundTripper mutation (http.go):** the RoundTripper contract forbids modifying the caller's request, and the wrapper stamped User-Agent in place. Took the reviewer's first option minus the wrapper drop: the stamp moved to probeHTTP — the request's creator — and the wrapper stays as pure transport routing (it is the req.Close fresh/pool router from `req-close-fresh-dial` and cannot be dropped). Redirect hops inherit the header because Client copies the initial request's headers onto every hop (pinned by TestProbeHTTPRedirectHopsCarryUA, which shows Go-http-client/1.1 on the hop when sabotaged). TestUARoundTripperDoesNotMutateRequest pins the contract.
2. **certReadTimes pruning (http.go):** comment claimed sensor-count bounding, but edited/deleted targets accumulated. Prune runs on the cert-read write path under certReadMu: entries older than certFreshness are deleted. Loss-free — the map's only reader treats "stale" exactly like "absent" (both force a fresh handshake) — and write frequency is bounded (once per certFreshness window per host), so an O(live hosts) sweep is free.
3. **Graph lock encapsulation (api.go/probe.go/stats.go):** handleSensorGraph reached into probeWorker.statsMu/statsCache. Added ProbeWorker.Graph(id, bucket, range), which takes the RLock inside the worker; the handler only maps nil -> empty. Parity with the direct graphPoints call pinned by TestWorkerGraphMethodParity.
4. **CI pinning + vuln gate (.github/workflows/):** actions pinned by full commit SHA (checkout v4.4.0 = 11d5960…, setup-go v5.6.0 = 40f1582…; same pins in windows-release.yml), tags kept as provenance comments. govulncheck added as a plain go-install step (no third-party action, keeps the pinned trust chain two entries deep) against the public OSV API.
**Tests:** nits_20261111_test.go (5 tests, RED: prune-loop removal FAILs the prune test; UA-stamp removal FAILs both UA tests with Go-http-client on the hop; Graph stub FAILs parity). Full -race green.
## go-toolchain-127 (go.mod + workflows + Dockerfile, 2026-11-11)
**Decision:** full migration to **go1.27.4** — toolchain + the **`go 1.27.0` language
directive** — with exact pins in ci.yml + windows-release.yml, and the container builder
base `golang:1.26-alpine` → **`golang:1.27-alpine`** (a THIRD Go pin the family-pin drift
hid; the zentest deploy path is `docker compose up -d --build`, so it had to move with the
rest). Deps raised in the same pass: x/net v0.60.0→**v0.62.0**, x/crypto
v0.57.0→**v0.59.0**, x/sys v0.48.0→v0.50.0.
The two knobs stay conceptually separate and were gated separately: `toolchain` decides
which compiler + stdlib ships (security + perf), `go` decides language semantics and the
GODEBUG compatibility defaults (behavior). Toolchain-only first (bbbc42a/6d16f04, green),
then the directive flip.
**Why 1.27.4 over staying on 1.26.11:** Go security-fixes only the two newest majors, so
1.26.x goes out of support at 1.28 (~2027-02) — staying there buys ~3 months and then
forces an unplanned jump. 1.27.4 is 4 patches into its series (released 2026-11-10) and
is the newest security line. Decided pre-tag: v1.1.9 was untagged, so the toolchain was
still an open choice for the artifact lineage (the tag is the immutability boundary).
**Behavior deltas reviewed before the directive flip** (all judged safe here): generic
methods and `encoding/json/v2` are additive — nothing in this change adopts them;
`stdversion` vet now runs by default under `go test`, a guardrail, green as-is; net/http
HTTP/1 `Response.Body` auto-drains on close (our probes `io.ReadAll` before Close, so this
is perf, not behavior); the HTTP/2 server now honors RFC 9218 client priority (knob
`Server.DisableClientPriority` if round-robin is ever wanted).
**Adopted later, not here:** `Server.MaxHeaderValueCount` as a hardening knob beside the
existing `MaxHeaderBytes: 64<<10`.
**1.27 items checked against this codebase:** `asynctimerchan` removal (time channels
always unbuffered) is a **no-op** — go.mod already declares ≥1.23, so the unbuffered
semantics are in force today; matters because the probe/alert/ping loops have 14
ticker/timer select sites, 7 with drop-tick `default:` arms. Runtime: ~1% faster small
allocations, ~+60 KB binary.
**Tests:** gated TWICE on zentest. (1) Toolchain-only, `go` directive still 1.26.0: vet
clean, linux/amd64 + windows/amd64 builds OK (19.4 / 19.9 MB, PE32+ verified), full
`-race` ok (329.441s + 4.248s). (2) Directive flip + dep bumps, in the mig-127 scratch
tree (`go mod tidy`/`./...` cannot run in the deploy dir: `data/` is zen-owned 700):
gofmt clean, vet clean, all three builds OK, full `-race` ok (326.398s + 4.317s),
govulncheck **0 findings** — the x/net + x/crypto raises cleared the 3 module-level
advisories the gate had been tolerating as uncalled.
**Pitfall this migration exposed:** a `govulncheck` built BY go1.26 cannot scan a module
declaring `go 1.27.0` — it dies on stdlib sources with `file requires newer Go version
go1.27 (application built with go1.26)`. CI is immune (setup-go installs 1.27.4 before
`go install govulncheck@latest`), but on the gate box it must be rebuilt:
`GOTOOLCHAIN=go1.27.4 go install golang.org/x/vuln/cmd/govulncheck@latest`. Same drift
class as the family pin — the SCANNER has a Go version too, not just the build.

## settings-apply-path-ctx (api.go, internal/store/store.go, api_context_test.go, 2026-11-13)
**Decision:** `guardSMTPNoCredsOverTLSInTx` and `applyProviderUpdateInTx` take a
`context.Context` as first parameter and `store.SetSettingInTx(ctx, tx, key, value)`
runs `tx.ExecContext`; `handleSettingsPut` threads `r.Context()` through the whole
apply phase (provider applies, routing-field writes). The standalone
`applyProviderUpdate` entry point passes `context.Background()` (no request ctx
exists; its `Begin()` stays). The guard's `stored()` reads are no longer
error-swallowed (`_ =`): `sql.ErrNoRows` keeps meaning "key absent -> empty",
every other read error is RETURNED, so the guard fails CLOSED (500, store
untouched) on a canceled ctx or a transient read failure — previously any read
failure was indistinguishable from "no stored credentials" and the guard passed.
**Why:** the settings PUT apply phase bound ctx at its first two calls
(`BeginTx(r.Context())` + the txlock-pin `ExecContext`) and abandoned it for every
statement after — the exact class the 2026-10-30 review #5 closed at four other
request-path sites (api_context_test.go contract: "a dead ctx means the statement
never runs"). Store integrity was never at risk on a mid-handler disconnect: a tx
from `BeginTx(ctx)` is ctx-bound for its whole lifetime (database/sql cancellation
watcher rolls back, every later op answers ErrTxDone, Commit fails) — the residual
gap was that an unbound call issued between ctx cancel and the watcher goroutine
being SCHEDULED executed its statement (the done-channel check is a race, not a
gate). Bounding every call makes fail-fast deterministic at each call site. The
driver cannot interrupt an in-flight statement (modernc.org/sqlite v1.29.1 ignores
ctx during the busy_timeout wait — empirically pinned in api_context_test.go), so
call-site bounding is the whole available guarantee.
**Pinned by:** `TestFix_SettingsApplyPathHonorsRequestContext`. Sabotage-verified:
reverting the three bodies to `tx.QueryRow`/`tx.Exec` (signatures kept) makes the
canceled-ctx guard answer with the sentinel instead of the ctx error, and
`SetSettingInTx`/`applyProviderUpdateInTx` return nil with the rows WRITTEN — the
canceled-ctx assertions fail.

## disconnect-refund-kdf-split (auth.go handleAuthLogin / handleAuthUserPassword, auth_refund_test.go, 2026-11-13)
**Decision:** the login and change-password disconnect arms (CreateSession/VerifyUser
returned false with `r.Context().Err() != nil`) now refund the per-IP throttle
admission beginAttempt appended — but ONLY for the zero-KDF-cost case: the refund
fires when the callee returned in under `kdfCostFloor` (25ms), the new const that
separates a queued-then-canceled acquireBcryptSem return (µs) from one that paid
the bcrypt KDF (≥50ms at bcryptCost=DefaultCost, and bcrypt is ctx-ignoring).
**Why:** the arms returned without refunding, so client disconnects while queued
on bcryptSem (NumCPU slots saturated — an attacker flood, browser double-submits,
operator timeouts) accumulated toward the 7-failures/60s per-IP lockout at zero
cost: the operator gets locked out by requests that never ran a KDF. The review's
suggested fix (refund on ctx.Err() unconditionally, mirroring handleAuthUsers)
was NOT adopted as written: the login arm mixes two cases the setup path keeps
apart — queued-canceled (KDF never ran) and canceled-DURING-KDF (KDF paid) —
and refunding the paid case hands a scripted attacker an unbounded per-IP
guessing channel (abort mid-KDF → budget refunded → re-spray; recordUserFail and
loginSlowDown are both skipped on that arm, so the account budget and the delay
offer no cap; the global semaphore becomes the only limiter). The setup path
already draws exactly this line ("the in-tx bootstrap race loss DID pay the KDF
— it is deliberately not refunded"); the time-floor is the login-path
equivalent, with ≥2x margin under the paid side (bcrypt cost-10 ≥50ms on any
supported hardware) and ≥4 orders of magnitude over the unpaid side.
refundAttempt's n6 arm covers the edge where the zero-cost appends already
tripped the lockout: the refunds drop the count back under loginFailMax and
clear it.
**Pinned by:** TestFix_QueuedCancelRefundsPerIPAttempt (sem saturated,
2×loginFailMax canceled-ctx requests across both handlers → bucket 0 and the
follow-up live login 200) and TestFix_PaidKDFDisconnectNotRefunded (cancel 20ms
into a real bcrypt → exactly 1 counted admission; passes on both pre- and
post-fix — it is the guard-pin against the over-refund regression).
Sabotage-verified: reverting the two arms to a bare `return` leaves 14 counted
attempts and flips the live login to 429.

## clone-glob-escape (api.go handleSensorClone, clone_name_test.go, 2026-11-13)

**Verdict:** valid — fix adopted (review finding #3 of the 2026-11-13 batch).

**The bug:** `handleSensorClone` enumerates existing clone names with
`SELECT name FROM sensors WHERE name GLOB cloneBase||'-copy*'`.
`validSensorName` is a blacklist, so `[ * ?` are legal name characters.
An unescaped `[` in the base distorts SQLite GLOB: `[b]` becomes a
character class and an unterminated `[` never matches at all — the
taken-name set comes back EMPTY. Every existing clone then collides at
INSERT and burns one of the `cloneMaxAttempts` (5) retries, so the 6th
clone of a base like `nas[01]` permanently died with 409 "too many
clones with this name" while `-copy6`..`-copy100` sat free.

**Why the old comment was wrong:** it claimed metacharacters "can only
distort the match set, never the outcome ... the same contract the old
exact-match loop had." The old loop probed each candidate with an exact
`name = ?` match (metacharacters inert); the 2026-10-22 one-query
rewrite moved the enumeration into a pattern match WITHOUT translating
that guarantee. Over-matching (`*`/`?`) stayed benign; under-matching
(`[`) shifted the failure from "retry advances" (bounded by how many
names a race can take, ~1-2) to "budget exhaustion at clone depth 5".
The pinned 1-clone metacharacter test never straddled the budget, so the
regression stayed invisible.

**The fix:** `globEscaper = NewReplacer("[", "[[]", "*", "[*]", "?",
"[?]")` quotes the base before appending the intentional `-copy*`
suffix. UNIQUE index remains the arbiter for genuine concurrent races.
`]` needs no escape: outside a class it is a literal in SQLite GLOB.

**Proven:** `TestFix_CloneGlobEscapeSurvivesDeepClones` seeds 6 clones
for `a[b`, `nas[01]`, `q*z?x` and demands 201 `-copy7`; reverts to 409
on the sabotage tree for the `[` bases (the `*`/`?` bases pass both
sides, pinning escape-nondisturbance). All existing clone tests pass
unchanged.

## change-password-prekdf-gate (auth.go handleAuthUserPassword, password_change_test.go, 2026-11-13)

**Verdict:** valid — fix adopted as suggested (review finding #5 of the
2026-11-13 batch).

**The gap:** login gained the 2026-11-11 pre-KDF structural gate
(oversized credentials → 400, uncharged, before any KDF/DB work), but
the change-password mirror of the same KDF surface never did:
`req.Password` was validated only INSIDE `SetUserPassword` — after
`VerifyUser` had already paid a full bcrypt KDF on `req.Current` — and a
>72-byte `req.Current` (bcrypt can never verify inputs over 72 bytes, so
it is structurally unmatchable) ran the KDF and answered 401 CHARGED.

**The fix:** the empty-credential block in `handleAuthUserPassword`
gains the two structural arms — `len(req.Password) < minPasswordLen` →
400 `errPasswordWeak`, `len(req.Password) > 72 || len(req.Current) > 72`
→ 400 `errPasswordTooLong` — before `beginAttempt`, same category and
same sentinel text as the paths they replace (the SetUserPassword 400
and the login gate).

**Proven:** `TestFix_ChangePasswordOversizedRejectedPreKDF` pins (1)
all three structural arms answer 400 immediately with `bcryptSem` FULL
— pre-fix they park on the full semaphore for their whole life (the 3s
deadline IS the pre-KDF proof); (2) `loginFailMax+2` structural rejects
with a wrong current_password leave the per-IP and per-username budgets
untouched — pre-fix each ran the KDF, charged both, and the
legitimate change after the loop 429'd; (3) exactly-72-byte current AND
new passwords stay the real path (200, KDF, password actually changed).

## provider-reads-bulk-fail-loud (alerts.go, smtp.go, internal/store/store.go, provider_bulk_reads_test.go, 2026-11-13)

Finding #6: resolveDestinationsFromDB read URLField/telegram_chat_id
fail-loud via getSettingErr but Enabled/HasURL two lines earlier via the
error-swallowing GetSetting; providerStatuses (embedded in the
otherwise-fail-loud settingsPayload) read every provider key through
GetSetting. A transient SQLite failure therefore read as "provider
disabled/unset": the snapshot load SUCCEEDED with a half-read snapshot
(provider silently dropped until the next settings save — there is no
periodic reload), and GET/PUT /api/settings could answer 200 with
enabled:false/has_url:false rows the PUT echoes back.

Fix adopted, upgraded from the suggestion's "use GetSettingErr at those
call sites": every provider key (enabled flags, URLs, chat_id, SMTP
extras) is now evaluated through the settingGet seam on ONE bulk
settings-table read (store.GetAllSettings — single SELECT, errors
propagate). resolveDestinationsFromDB/loadAlertSettings/providerStatuses
all abort on read error (snapshot reload keeps the last-good snapshot;
settingsPayload answers 500), and TestWebhook's SMTP gate + chat_id read
route through the seam fail-loud.

Why bulk over per-key GetSettingErr: (1) atomicity — the settings PUT
commits all its keys in one tx, so one SELECT observes one consistent
commit; 15+ point reads could straddle a concurrent PUT and install a
snapshot mixing pre-/post-PUT keys; (2) one query replaces the point-
query storm on every snapshot reload and every settings GET.

Predicates moved to enabledGet/hasURLGet funcs; the legacy bool
Enabled/HasURL(db) wrappers are kept ONLY for tests (documented as the
swallowing shape, prod callers zero) so ~40 test call sites keep the
compact form. providerExtra became providerExtraGet with a fixed read
order (deterministic failure: a map iteration order must not decide
which key's error surfaces).

Sabotage (behavior-level, compiles): bulk reads' error handling reverted
to swallow-to-empty-map in loadAlertSettings + providerStatuses → all
three pins fail (new snapshot test, new statuses test, and the existing
TestTelegramDeliveryFailsClosedOnChatIDReadError, whose seam-swap moved
from getSettingErr to the bulk seam since snapshot keys are no longer
point-read).

## settings-put-pretx-bulk-fail-loud (api.go handleSettingsPut / storedProviderExtra, settings_pretx_test.go, 2026-11-13)

Finding #7: the settings PUT's pre-tx validation reads used the
error-swallowing GetSetting: effScope (dead-filter guard), the stored
alert_filter fallback, the per-provider storedProviderExtra snapshot, and
maintAlreadyOn (maintenance re-enable pre-check). A transient SQLite
failure silently MISCOMPUTED the guard inputs, and two miscomputations
are destructive in ways the in-tx guards do NOT cover:

- stored alert_scope read as "" → effScope defaulted to "all" → the
  empty-filter guard skipped → PUT persists scope=tags + filter=[] — the
  dead-alert state (all alerting silently off) the guard exists to
  refuse, and it persists in the store after the 200. Sabotage run
  reproduced it verbatim: stored alert_filter = "[]" after a failed
  pre-flight read.
- stored maintenance_mode read as "off" on a re-enable → handler took the
  off→on branch → enterMaintenance took a FRESH snapshot replacing the
  entry-time restore set → sensors paused at maintenance entry lose their
  restore entry and are left paused forever at resume (the documented
  re-snapshot hazard, triggered by a swallowed read).
- storedProviderExtra degraded to {} on read failure: pre-flight
  credentials evaluation weakens; the in-tx SMTP guard remains the
  backstop (sabotage: 400 from in-tx guard where the fix answers 500 at
  pre-flight — store intact either way, hence the status-code pin).

Fix (suggestion's bulk option): ONE fail-loud bulk pre-flight read
(getAllSettings seam) feeds every pre-check — a read failure answers 500
before any write, and all pre-checks observe a single commit of the
settings table (point reads across a concurrent PUT's commit boundary
could mix pre-/post-PUT keys into the guard inputs). storedProviderExtra
(standalone twin) moves to the same seam fail-loud, aborting its own tx
before any write.

Note: the pre-flight map reads replace point reads that each had their
own failure direction (guard-skip vs spurious 400); with the bulk read
the whole phase has ONE failure direction: 500, store untouched.

## maintenance-leave-fails-loud (api.go, internal/store/store.go, maintenance_snapshot_test.go, settings_patch_test.go, api_context_test.go, 2026-11-16)
**Decision:** Leaving maintenance mode now reads the restore-set snapshot INSIDE
the resume transaction — new Store.LeaveMaintenanceFromSnapshot(ctx) mirrors
EnterMaintenanceWithFreshSnapshot: pin the write lock (zero-row UPDATE on
settingsTxLockKey) → SELECT maintenance_active_ids → resume those ids → clear
snapshot + mode flag, all in ONE tx. handleSettingsPut's leave branch is one
seam call (leaveMaintenance) that 500s on ANY failure without touching the
mode flag, the snapshot, the sensor states, or the in-memory pause fast-path.
The old Store.SetMaintenanceMode (caller supplies ids read outside the tx —
the exact shape that made the bug possible) is removed; both transitions now
compute their id set inside their own tx. The enter path gained the same
write-lock pin its SELECT-first tx was missing.
**Why:** the leave path read the snapshot with the swallow-to-"" GetSetting
BEFORE the tx: a transient read failure — or a value that failed to decode
(ids = nil) — yielded an EMPTY restore set, and the leave then resumed
NOTHING, wiped the snapshot, and set maintenance_mode=0. The maintenance
banner vanished, every maintenance-paused sensor stayed paused forever with
alerts silent, and nothing recorded which sensors were in the lost set: the
worst outcome for a monitor, and the same fail-loud class the enter path was
already converted for (EnterMaintenanceWithFreshSnapshot exists for this
reason). An undecodable snapshot is now a hard error with the tx rolled back:
mode stays ON (banner up, alerts gated), the value stays on disk for
inspection, and the retry can succeed. A MISSING snapshot row (pre-rework DB)
stays a clean success — there is no restore set to lose; only a
present-but-undecodable value is fatal. The write-lock pin goes in BEFORE the
in-tx SELECT because a deferred tx that starts as a reader and upgrades after
a concurrent commit fails fast with SQLITE_BUSY_SNAPSHOT (517), which
busy_timeout does not retry — the established pin pattern from this handler's
settings tx.
**Pinned by:** TestLeaveMaintenanceFromSnapshot (enter→leave resumes exactly
the snapshot; p1 user-paused untouched; snapshot cleared),
TestLeaveMaintenanceUndecodableSnapshotFailsLoud,
TestLeaveMaintenanceMissingSnapshotIsNotAnError,
TestSettingsPutReloadsSnapshotWhenMaintenanceTxFails/leave-maintenance-500
(500 + mode stays "1" + snapshot byte-identical),
TestMaintenancePauseResume,
TestFix_MaintenanceAndTagDeleteHonorRequestContext (leave is ctx-bound).
Sabotage-verified: restoring the old read (decode error → ids = nil, no
in-tx read) makes TestLeaveMaintenanceUndecodableSnapshotFailsLoud fail with
"want an error, got nil" and mode/sensor-state assertions expose the wipe.

## comment-convention (all .go, 2026-11-16)
**Decision:** In-code comments state the CURRENT CONTRACT (invariant +
one-line why) only. Review IDs, review dates, and incident narratives are
stripped from code (63 dated citations + the phantom db.go refs removed;
alertGate/enqueueAlert, the maintenance transitions, the probe-client
redirect/TLS guard, blockedSubnets, the auth section header and the
warmStats header compressed to invariant form — enqueueAlert 40 lines →
6). History pointers in comments take the form
`History: docs/DECISIONS.md → <slug>`; the Review ID map at the top of
this file resolves older IDs. Behavior is unchanged: the sweep is
comment-only, gated by comment-stripped token equality of every .go file
before/after, plus the full gofmt/vet/-race gates.
**Why:** dated review narration in comments costs review speed (a reader
must parse history to find the rule), goes stale as DECISIONS.md and git
already carry it, and cites a file (db.go) that no longer exists. The
file header already mandated the contract-only convention; the sweep
brings the code in line with it.
**Pinned by:** comment-stripped token equality (a comment-only sweep must
produce byte-identical code token streams); any future grep for
`(2026-` review citations in non-test .go must find nothing.

## update-check single-flight (update_check.go, update_check_test.go, 2026-11-16)
**Decision:** `handleUpdateCheck` no longer holds `updateCheckMu` across the
10s GitHub fetch. `updateCheckMu` guards state only; cache hits and the
stale-serve path are answered from a snapshot copied out under the short
lock, and concurrent misses coalesce on a `singleflight.Group`
(`golang.org/x/sync/singleflight`, already used by the DNS cache) that
performs the one fetch and updates state at attempt and completion.
**Why:** the old shape had two defects. (1) A real data race: the
?refresh=1 throttle read `updateCheckAttemptAt` before the lock while the
fetching goroutine wrote it under the lock — latent (short-circuit hid it
from serial tests) but detector-confirmed under the new concurrent test.
(2) Head-of-line blocking: one cache-miss fetch serialized EVERY poll
behind up to 10s of network. Single-flight keeps the coalescing property
(N misses = 1 upstream call, the GitHub rate-limit shield) without the
serialization: a slow upstream now blocks at most one goroutine per
flight, and fresh-cache polls sail past untouched.
**Pinned by:** `TestUpdateCheckConcurrentPollsCoalesce` — mixed
normal+refresh concurrent wave (old code = DATA RACE + FAIL, verified
by sabotage), hit-count pin (8 pollers → 1 upstream fetch), and a
latency pin (normal poll during an in-flight slow refresh must return
<150ms).

## smtp-config-in-snapshot (smtp.go, alerts.go, smtp_snapshot_test.go, 2026-11-16)
**Decision:** the SMTP mail config resolves at snapshot-load time into the
delivery `dest` (like the Telegram chat_id), so the alert hot path performs
ZERO settings reads for every provider. `resolveDestsGet` builds the full
`smtpConfig` from the same bulk settings map (fail-loud: a read error
aborts the load and keeps the previous snapshot); `sendSMTPWith` takes the
resolved config. The live form `sendSMTP` (settings Test button, tests)
reads ONE bulk `getAllSettings` and returns the error — never 7
swallow-to-"" GetSetting calls.
**Why:** the per-send live reads were the last violation of the snapshot
design: a transient DB lock mid-send mapped Host to "" →
`errSMTPNotConfigured`, which the retry loop classifies as permanent, so
the in-band retries were skipped and recovery depended on the outer
schedule. A read failure is now either invisible to the delivery (snapshot
already loaded) or a retryable bulk-read error — never a fake
configuration gap.
**Pinned by:** `TestSMTPDestCarriesSnapshotConfig` (dest carries all seven
keys, sabotage = resolver stops attaching → red),
`TestSMTPDeliveryZeroSettingsReads` (delivery succeeds with the DB CLOSED
— sabotage = restore a live read → red),
`TestTestWebhookSMTPSurfacesDBError` (bulk-read failure → "database
error", not "not configured").

## install-sh-sig-verify (install.sh, scripts/release-sig-harness.sh, 2026-11-16)
**Decision:** install.sh verifies the release's detached ed25519 `.sig`
with `openssl pkeyutl`, not just the SHA-256 sidecar. It mirrors
`verifyReleaseSignature` (update.go) exactly: manifest =
`pulsemon-release-v1\n<tag>\n<asset>\n<sha256>\n`, `.sig` = hex-encoded
64-byte signature, keys = the repo's `release_pubkeys` (fetched over TLS
from main; any listed key verifying is accepted, so rotation works),
fail-closed on missing `.sig`, non-64-byte sig, empty key set, fetch
failure, no openssl, no hex decoder — the binary is not installed.
**Why:** the binary and its .sha256 come from the SAME release, so the
sidecar alone verifies nothing against a compromised release/CI token —
exactly the case manifest signing was designed for, and the case the
in-app updater already refuses. A first install must not be weaker than
self-update. Accepted caveat: install.sh itself is fetched from main, so
a FULL account compromise (push to main + release) defeats the pin; the
trust roots are then identical, and that residual is documented, not
hidden.
**Pinned by:** `scripts/release-sig-harness.sh` — extracts the block
verbatim from install.sh and runs it over fixture releases: valid
signature accepted; tampered binary, tag replay (sig made for an older
tag), missing sig, unknown key, truncated sig, unreachable pubkeys, and
comment-only keyset all refused. 8/8 on zentest.

## api-downgrade-opt-out-explicit (update_api.go, update_downgrade_test.go, 2026-11-16)
**Decision:** `POST /api/update` lifts the anti-downgrade floor ONLY on an
explicit `"allow_downgrade": true` body field — the API twin of the CLI's
`--allow-downgrade`. A version pin alone no longer bypasses the guard
(pre-fix the opt-out was `version != "latest"`).
**Why:** the floor exists precisely for the post-rollback window (running
< tag < max_version_seen), and pinning is the natural way to walk INTO
that window; the dashboard never pins (it posts `{}` against the latest
tag), so the implicit rule was a downgrade opt-out that only raw API
clients could reach, invisible to anyone reading the CLI as the reference
contract. Symmetry is the point: a deliberate downgrade now looks the
same from both entry points — an explicit, separately-stated opt-out.
Admin-only route either way; this narrows the blast radius of an
accidental scripted pin, it does not gate trust.
**Pinned by:** `TestUpdateExplicitPinRefusedWithoutOptOut` (pin alone →
409, message names the field, binary untouched),
`TestUpdateExplicitPinWithAllowDowngradeInstalls` (explicit opt-out → full
install path), alongside the existing un-pinned and CLI twins. Sabotage
`allow=true` always → refusal test red; `allow=false` always → install
test red.

## dead-code-sweep (auth.go, smtp.go, alerts.go, http.go, internal/store/store.go, 2026-11-16)
**Decision:** production files carry only live code. Moved to _test.go:
`ValidSession` (the boolean twin of the production `SessionUser` validator)
→ session_validsession_test.go, and the swallow-bool provider wrappers
`smtpHasURL`/`chatEnabled`/`flagEnabled`/`flagHasURL`/`telegramHasURL`
→ provider_predicates_test.go. Deleted (zero callers anywhere):
`Store.SetSensorStates` (superseded by the maintenance-tx paths),
`httpStatusText`, `chatHasURL` (bool wrapper; the *Get predicate stays).
**Why:** "test-suite surface only" functions in production files inflate
the reviewable surface, invite reimplementation drift (SetSensorStates
sat next to the maintenance tx that reimplemented it), and keep the
dead-code detector noisy. The twins in _test.go keep their full doc
comments, so the semantics under test stay documented where they are
exercised.
**Pinned by:** gate convention — `go vet` + full suite; the sweep is
behavior-free (moved functions byte-identical; deleted ones had zero
references repo-wide, verified by grep before removal).

## icmp-demux (ping.go, 2026-11-16)
**Decision:** the compound (seq, destination) pingKey IS the reply
source-check; deliver() has no separate destination check, and
pendingPing carries no dst field.
**Why:** the per-entry `p.dst.Equal(src)` check predates the compound key
and became unconditionally true under it (net.IP.Equal normalizes the same
v4-in-v6 forms mkKey normalizes, so a map hit implies equality) — a dead
branch that read like live protection and sent the next reader hunting
for the case it handled. The key match enforces the same invariant at
lower cost: a stale reply that recycled a seq can only look up the slot
for the destination it actually arrived from.
**Pinned by:** TestDeliverStaleReplyDoesNotEvict and
TestDeliverSameSeqDifferentDsts (both go red on a seq-only key —
sabotage-verified).

## icmp-demux (ping.go, m8 follow-up, 2026-11-16)
**Decision:** a probe's start time is stamped under pendingMu at the
publish point (both the slot-claim insert and the table-full fallback),
not after the lock is released.
**Why:** publishing p into `pending` under the mutex makes it visible to
the reader goroutine, whose `time.Since(p.start)` on a map hit is then
ordered against the stamp by the mutex itself. Stamping after the
unlock left a formally unsynchronized write/read pair (the fdMutex
atomics in the send path made it benign in practice, not in law — the
reader can only exist after the send, which rides fdMutex). Stamping at
insert excludes the slot loop's bookkeeping from the RTT exactly like
the old comment intended; only the unlock + send syscall follow, µs on a
whole-ms display.
**Pinned by:** TestPingStartStampedAtPublish (loopback-style reply
inside send must measure against the stamp, never the zero time) and
TestDeliverRacesPublishStampSynchronized (reader hammer racing the
publish — DATA RACE on the old shape under -race, silent on the fix).

## tls-install-fd-cleanup (tls_settings.go, 2026-11-16)
**Decision:** both temp pair files get `defer Close()` the moment they
exist; `install()` keeps its explicit, error-checked closes (a Close
error there is data loss and must gate the renames). The temp-file
creator is a seam (`tlsCreateTemp = os.CreateTemp`).
**Why:** install() early-returned on tmpCert.Write/Sync and
tmpKey.Write/Sync failures, closing neither file; the caller's cleanup
removed the NAMES (os.Remove), not the descriptors — a leaked fd per
temp per failed PUT. Rare paths, but the handler is admin-triggered and
retried installs compound it. Deferred Close after an explicit Close is
a harmless ErrClosed, so success paths are unchanged.
**Pinned by:** TestTLSInstallWriteFailureClosesTempFDs — seam hands
out read-only temps so the first write fails with EBADF, and the test
diffs /proc/self/fd around the PUT: +2 fds on the pre-fix shape
(sabotage-verified), 0 on the fix.

## nit-round-2026-11-16 (tcp.go, probe.go, alerts.go, stats.go, main.go, web/->frontend/, update_check.go)
**Decision:** six review nits landed at once. (1) tcpProbeResult.Elapsed
doc corrected: the stamp lands AFTER resolveICMPTarget, so Elapsed is the
TCP handshake only — connect-only is the intended measurement (the HTTP
probe keeps the TTFB stance that includes DNS). (2) seriesTailProbes
carries a new comment pinning why slow sensors (status window > 60)
legitimately fall through recentFromCache to SQLite every tick — do not
"optimize". (3) The re-alert hot path reads an in-memory copy of
alert_state (alertMem, write-through from setAlertState, invalidated by
Remove/ResetStatsFor/ResetStatsAll); the DB row stays the durable copy,
re-read on miss. (4) hotReloadCert memoizes the cert/key (mtime,size)
fingerprint for certStatMemo (1s) under its own mutex — two stats per
handshake becomes one stat pair per second of handshake burst; a
replaced pair lands at most 1s late. (5) Tailwind build INPUTS moved
web/ -> frontend/ (Makefile css target updated): go:embed web/* ships
served assets only, so handleStatic can no longer serve tailwind.config.js
/ tailwind.input.css. (6) PULSEMON_DISABLE_UPDATE_CHECK=1 answers
/api/update-check with a canned no-update (zero network); CLI update
paths unaffected.
**Why:** each was a correctness-of-docs or steady-state-waste item:
misleading RTT semantics, a predictable "optimization" trap, a SELECT per
error tick per sensor, 2 syscalls in every TLS handshake, build inputs
public over HTTP, and an unhonored call-home opt-out expectation.
**Pinned by:** TestRealertUsesAlertMemCache (0 DB lookups on steady
error ticks, exactly 1 after invalidation), TestHotReloadCertStatMemo
(frozen memo window serves the cached pair, closed window reloads),
TestUpdateCheckDisabledOptOut (disabled:true, 0 upstream hits) — all
three sabotage-verified red; live zentest: /tailwind.config.js and
/tailwind.input.css = 404 post-move, index + update-check unaffected.

## private-ca-trust (http.go, main.go, README)
**Decision:** HTTPS sensors behind a private CA are supported via
`PULSEMON_CA_FILE`: a PEM bundle loaded once at startup (initProbeCA,
before the probe worker starts) into the probe verification pool
(verifyHTTPCert path (a) Roots). Unreadable file / zero parsed
certificates = fatal startup error. The bundle REPLACES the system
trust paths for probes. The dashboard listener's own TLS is unaffected.
**Why:** verifyHTTPCert accepted only system roots or exact self-signed,
so step-ca-style internal CAs read lost, and self-signed was the only
operator-configurable trust. Go's SSL_CERT_FILE env technically works
in a deployed process (even in FROM scratch: the file IS the store),
but Go caches the system pool at the FIRST TLS verification for the
process lifetime — un-settable after boot, untestable in-process, and
invisible from pulsemon's own surface; an explicit knob is documented,
testable, and fail-loud (see DEFERRED).
**Pinned by:** TestProbeHTTPPrivateCAFile (same probe, both directions:
CA-signed leaf reads lost with no bundle, UP with PULSEMON_CA_FILE set;
zero-cert bundle must fail initProbeCA — sabotage-verified: pool ignored
(Roots nil) turns the UP leg red).

## alert-retry-mem-write-through (alerts.go, webhook_retry_test.go, 2026-11-17)
**Decision:** scheduleAlertRetry backdates the in-memory alert-state copy
(pw.alertMem) WITH the alert_state row — under pw.alertMemMu, only when the
DB UPDATE affected a row and the mem entry still tracks the same status
(mirroring the SQL `WHERE status = ?` guard). Remove already deleted the mem
entry (probe.go) — no change there.
**Why:** setAlertState writes through to alertMem and maybeRealert reads the
mem copy first whenever an entry exists — which is ALWAYS on the
sustained-error path, because the initial alert seeded it. The DB-only
backdate was invisible to the interval check: now.Sub(un-backdated mem.ts)
< realert_min on every tick, so the ~1-minute all-providers-failed retry
never fired.
**Pinned by:** TestScheduleAlertRetryBackdatesMemCopy — (a) mem ts is
backdated with the DB row, (b) a sustained-error tick ~alertRetryAfter later
re-delivers (0 provider hits on the old shape), (c) a recovered sensor's mem
entry is not backdated. Sabotage-verified: dropping the mem write turns (a)
and (b) red.

## reset-alert-states-mem-write-through (alerts.go, webhook_retry_test.go, 2026-11-17)
**Decision:** ResetAlertStates stamps the in-memory alert-state copies
(pw.alertMem) with the same instant as the alert_state rows.
**Why:** maintenance mode pauses every sensor — no probe ticks, no
maybeRealert, no setAlertState refresh while paused. A sensor already in
error for longer than the re-alert interval therefore kept its
pre-maintenance mem.ts in alertMem; the DB stamp was invisible (maybeRealert
reads memory first), and the first post-maintenance tick fired an immediate
re-alert — defeating the suppression contract ResetAlertStates exists for.
**Pinned by:** TestResetAlertStatesStampsMemCopy — (a) mem ts stamped to now
after reset, (b) the first sustained-error tick after maintenance delivers
zero re-alerts (old shape: immediate re-alert). Sabotage-verified: dropping
the mem loop turns (a) and (b) red.

## allow-unauth-update-in-tx-user-count (api.go, settings_alert_filter_test.go, 2026-11-17)
**Decision:** handleSettingsPut re-checks `SELECT COUNT(*) FROM users`
INSIDE the settings write tx (under the `\x00pulsemon-txlock` pin) before
persisting allow_unauth_update; count 0 → 403, deferred rollback leaves the
store untouched. The pre-flight `s.auth.Enabled()` guard stays as the fast
path.
**Why:** Enabled() is a 2s-TTL cache; an out-of-band `pulsemon auth-user
remove` of the last account is invisible to it for up to 2s (documented
tradeoff in auth.go). In that stale-true window auth is effectively off and
requireAuth stands down, so an unauthenticated PUT could persist
allow_unauth_update=1 and then POST /api/update — the exact privilege the
guard exists to block. The count under the write-lock pin is stable: a
concurrent user removal serializes behind the pin and cannot commit between
the count and the setting write.
**Pinned by:** TestSettingsPutAllowUnauthLiveUserCountInTx — seeds the cache
true with a live account, deletes the last user via direct DB write (no
refreshEnabledNow), asserts the PUT is 403 with nothing written while
Enabled() still reads stale-true. Sabotage-verified: dropping the in-tx
count turns the PUT 200 + the value written (red).

## events-feed global ts index (internal/store/store.go, api.go, events_feed_test.go) — REJECTED, decision 2026-11-17

**Finding (external review 2026-11-17 #4):** GET /api/events runs
`ORDER BY e.ts DESC LIMIT n` across the whole events table with no
dedicated index (only the composite (sensor_id, ts) index), so every
dashboard poll forces a full scan + temp B-tree sort; suggested fixes were
`CREATE INDEX idx_events_ts ON events(ts DESC)` or `ORDER BY e.id DESC`.

**Decision: REJECTED — stale: the index the finding says is missing
already exists and serves the query.**
- `idx_events_ts ON events(ts)` is in the base schema (store.go) with a
  comment stating it exists for exactly this query; `CREATE INDEX IF NOT
  EXISTS` runs at every startup, so pre-existing DBs carry it too.
- SQLite serves `ORDER BY ts DESC` with a backward scan of the ASC index.
  EXPLAIN QUERY PLAN (verified on a scratch DB with 500 rows AND the live
  zentest DB): `SCAN e USING INDEX idx_events_ts` + a PK point-lookup for
  the sensors JOIN — no full scan, no `USE TEMP B-TREE FOR ORDER BY`, and
  LIMIT n stops the walk at n entries.
- `ORDER BY e.id DESC` was not adopted: ts is the feed contract (fixed-
  precision TSLayout makes TEXT order == chronological order), and
  switching to insertion order buys nothing while weakening that contract.

**Pinned by:** TestEventsFeedSortUsesTSGlobalIndex — asserts the feed query
plan references idx_events_ts and contains no TEMP B-TREE; dropping the
index in a future schema refactor turns it red.

## alert-target parse-failure redaction (alerts.go, fuzz_validators_test.go, 2026-11-17)
**Decision:** alertTarget no longer depends on neturl.Parse succeeding:
the userinfo strip runs on the RAW string for every input (new
authorityStart/validScheme helpers locate the authority exactly where
net/url would), so a target that fails to parse is redacted with the same
last-'@' boundary as a parseable one. No-authority strings (bare IP,
hostname) are returned unchanged; '@' in the PATH (no userinfo) is
preserved.
**Why:** the old code returned the target VERBATIM when neturl.Parse
failed, and malformed targets with credentials DO fail Parse — verified:
backslash in host ("invalid character in host name"), control character
("invalid control character in URL"), bad percent-escape ("invalid URL
escape"). Any of them (legacy or hand-edited DB rows; the API write path
validates new targets) shipped user:pass straight into
Discord/Telegram/Chat/SMTP cards — the exact leak the function exists to
prevent. The raw-string cut was already the mechanism (it mirrors
net/url's authority boundary, including the last-'@' rule), so removing
the parse gate is behavior-preserving on every parseable input and adds
redaction only where Parse fails.
**Pinned by:** FuzzAlertTarget seeds — backslash host, control char, bad
escape, and scheme-relative parse-failure forms must come back with the
userinfo stripped; path-only '@' must survive. Sabotage-verified:
restoring the `err != nil -> return target` gate turns the four
parse-failure pins red.

## known-good exemption scoped per account (auth.go, auth_test.go, 2026-11-17)
**Decision:** the loginThrottle knownGood exemption is keyed by
(username, IP bucket) — `username + "\x00" + ipBucket` (new knownGoodKey
helper) — instead of IP bucket alone. loginSuccess now takes the username
(all three call sites: /api/auth/login passes the lowercased userKey, the
setup-bootstrap path passes strings.ToLower(req.Username), the
change-password path passes the session user); checkUserLock looks up the
pair. The per-IP fails/lockout clearing inside loginSuccess stays IP-scoped
(it is the per-IP layer, which is correctly IP-keyed). The sweep is
key-agnostic and unchanged.
**Why:** a successful login by ANY account marked the IP bucket known-good
for 30 days, exempting that IP from the per-username lockout for ALL
accounts. On a shared workstation, jump box, or NAT/VPN exit IP, a
compromised low-privilege session gave its IP a permanent pass to spray
admin: the cross-IP account lockout — the layer that exists precisely to
stop a multi-source account spray — was voided for that IP for the whole
TTL (the per-IP 7/60s budget still applied, but it is a rate cap, not an
account lockout). Scoping to (account, IP) keeps the original
self-DoS protection (the operator's own account/IP pair always gets
through) while a success by another account no longer exempts this one.
The \x00 separator is collision-free: usernames match
^[a-zA-Z][a-zA-Z0-9._-]*$ and buckets are dotted/colon address strings,
so neither side can contain \x00.
**Pinned by:** TestKnownGoodExemptionScopedPerAccount — an active admin
lockout + a viewer login from the same IP must NOT exempt admin on that IP
(the pre-fix keying exempts it, turning the test red), while viewer is
exempt on its own IP and admin is exempt on its own known-good IP.
Pre-existing exemption tests updated to the composite key; the
end-to-end operator self-DoS test now asserts the (admin, IP) entry.

## origin gate fails closed on empty host (api.go, csrf_test.go, 2026-11-17)
**Decision:** the authGate Origin arm now rejects when u.Host == "" OR
r.Host == "" (in addition to the parse-error and mismatch cases). A
present-but-hostless Origin (Origin: null parses with an empty host) must
never read as equal to a Host-less request.
**Why:** Origin: null + a Host-less HTTP/1.0 request (legal pre-HTTP/1.1;
the Go server leaves r.Host empty) made EqualFold("", "") evaluate true
and pass the gate — a fail-open corner in the check. Practical
exploitability is low (browsers never send Host-less HTTP/1.0, and
non-browser clients need no Origin to pass the arm at all), so this is
fail-closed hygiene rather than a live-vector fix: the gate's contract is
that an empty host on either side is never a match, and no legitimate
client sends Origin: null + no Host header, so the extra rejection breaks
nothing.
**Pinned by:** TestOriginGateNullOriginEmptyHostRefused — a raw-socket
HTTP/1.0 POST (no Host header) with Origin: null must 403, while the same
request without an Origin header must pass (200), proving the 403 comes
from the Origin arm. The pre-existing TestOriginGateNullOriginRefused
(Origin: null against a normal Host-bearing request) still pins the
common case.

## settings-put log sourced from echo (api.go, settings_alert_filter_test.go, 2026-11-17)
**Decision:** the tail of handleSettingsPut no longer runs three separate
GetSetting reads (realert_min, alert_scope, alert_filter) solely to format
the "settings updated" log line. It builds the response echo
(settingsPayload) first and reads echo["alert_scope"],
echo["alert_filter"], echo["realert_min"] for the log.
**Why:** settingsPayload() immediately re-reads those exact keys (plus the
rest of the payload), so the three pre-log reads were pure redundancy on
every settings save. Sourcing the log from the echo is also a small
correctness improvement: the line now shows the VALIDATED/DEFAULTED values
the alert hot path actually uses (scope "all" when unset, realert clamped
to 0-1440 with default 30, filter count) instead of raw stored strings an
out-of-band edit could have left inconsistent (the old log had no range
check on realert and no default on scope). Behavior change is limited to
the log line; the response echo is unchanged. In the rare post-commit echo
read failure the "settings updated" line is no longer printed before the
500 — the 500 itself is still logged via respondInternal.
**Pinned by:** TestSettingsPutLogUsesEffectiveValuesFromEcho — seeds the
degenerate state the write path can never store (out-of-range
realert_min=9999, unset alert_scope) out-of-band, does a no-op PUT, and
asserts the captured log line is "scope=all filter=0 realert=30m"; the
pre-fix raw-read shape logs "scope= ... realert=9999m" and turns it red.

## alertMem + cookie-renewal coverage gaps — REJECTED, decision 2026-11-17
**Decision:** REJECTED as stale. The finding claims three test-coverage
gaps; all three are already covered by existing, passing tests.
**Why:** (1) "no test exercising scheduleAlertRetry while pw.alertMem is
populated" — TestScheduleAlertRetryBackdatesMemCopy (webhook_retry_test.go)
does exactly the suggested shape: an initial failed alert seeds alertMem,
all providers fail (500), and it asserts maybeRealert delivers one retry
after alertRetryAfter (plus a direct mem-backdate pin and a status guard
that a recovered sensor is not backdated). (2) "no test exercising
ResetAlertStates while pw.alertMem is populated" —
TestResetAlertStatesStampsMemCopy (webhook_retry_test.go) covers it: a
sensor in error 45m (past the re-alert interval) is Reset, and the first
sustained-error tick after must NOT re-alert (0 provider hits), with a
direct mem-stamp pin. Both were added in this batch as the regression pins
for findings #1 and #2, which are precisely the two bugs the finding says
"slipped through" — the gap closed the moment those fixes landed. (3)
"no test verifying CookieRenewalDue when a session approaches the 30-day
authSessionMaxAge boundary" — TestFix_RenewalCookieCappedByMaxAge
(session_cookie_slide_test.go) pins the boundary at method level (day-10
renewal = full TTL; day-29+1h = capped to ≈23h remaining, not the full 7d;
at/past the cap = no renewal) and at gate level (a day-29 Set-Cookie
carries Max-Age ≈ 1d with the same token). All three pass under -race
(verified 2026-11-17). No code or test change; the existing pins are the
rejection's evidence.

## inline audit-history readability — REJECTED, decision 2026-11-17
**Decision:** REJECTED as stale/overstated. The finding claims many
functions in alerts.go/api.go/auth.go carry 15–30 lines of inline audit
history (review dates, external-review numbers, commit hashes, dead-bug
post-mortems) that should move to DECISIONS.md. That description does not
match the current tree.
**Why:** measured across the three files (~2,650 comment lines total):
zero references in the cited "review 2026-10-23" format, zero
"external review #N" references, one commit hash (api.go:1599, a
single-line pin naming where the clone rune-cap invariant was set — a
pointer, not a post-mortem), and three 2026 date references, each a 1–2
line attribution embedded in a 4–5 line comment whose body is an
INVARIANT explanation (alerts.go:681 why production settings reads are
fail-loud `*Get` predicates; api.go:1334 why the two large deletes are
batched — one unbatched DELETE held the WAL write lock and stalled every
probe loop to the 15s busy_timeout; api.go:1599 why clone truncates by
runes not bytes). There is no 15–30 line audit block anywhere. The
codebase already follows the practice the finding asks for: the why-an
invariant-must-hold rationale stays at the point of use, and the detailed
post-mortems live in docs/DECISIONS.md (which is where this batch's nine
decisions were recorded). Stripping the brief attributions would remove
the in-code pins that stop external reviews re-flagging intentional
decisions (the standing convention, e.g. the update-check no-gate and
host-gate pins) for no readability gain. No change.

## static catch-all method guard (api.go, static_serving_test.go, 2026-11-17)
**Decision:** handleStatic now rejects every method except GET/HEAD with
405. The / route is a bare ServeMux catch-all, so POST/PUT/DELETE/PATCH
against any static path (/, /app.js, ...) fell through to the static
handler and returned 200 with the file contents.
**Why:** HTTP hygiene, not a security fix — the assets are public and a
POST serves byte-identical content to a GET, so nothing sensitive is
exposed. But every other handler in the codebase guards its method, and a
static file server answering DELETE with 200 is a broken contract for
proxies, scanners, and anything treating 405 as the "not a resource for
this method" signal. GET/HEAD are unaffected.
**Pinned by:** TestStaticMethodNotAllowed — POST/PUT/DELETE/PATCH / and
DELETE /app.js must 405; GET / and HEAD / must 200.

## sync-reconcile-scale (probe.go `syncSensors`, 2026-11-17)
**Decision:** `syncSensors` keeps its unconditional full reconcile
(every sensor row + batched tag query) on every 5s tick. NO cheap
pre-check is added at this time; this entry records the scaling ceiling
and the exact fix to apply when it matters (external review 2026-11-17
m5).
**Why:** at homelab scale (tens of sensors) the pass is microseconds —
two indexed SELECTs on a table the app already reads constantly — and
the `sync-sensors-generation` design (2026-11-05) already removed the
DB reads from under `pw.mu`, so the pass cannot stall the fleet. A
pre-check only pays off when the table is large enough that the full
pass is measurable, which is not this project's scale.
**The ceiling (when to revisit):** if the project ever targets 1000+
sensors, the fix is a single-row pre-check —
`SELECT COUNT(*), MAX(updated_at) FROM sensors` — run BEFORE the full
pass; skip the pass when the (count, max_updated_at) fingerprint is
unchanged AND no `syncReq` is pending. COUNT (not just MAX) is
required: a DELETE lowers no max. It requires (a) an additive
`updated_at` column migration on `sensors` and (b) stamping it on EVERY
write path — POST/PATCH/clone/state-patch AND `doProbe`'s hot-path
`UPDATE sensors SET status` (a status flip is the most frequent
write; it need not force a re-sync, it only costs one extra pass).
Until then: no code change, no migration.

## login-hourly-budget (auth.go, auth_hourly_budget_test.go, 2026-11-18)
**Decision:** a SECOND, slower per-username limit runs alongside the 60s
rolling budget. `recordUserFail` now also updates a per-account hourly budget
(`userHour map[string]*userHourBudget`); when the in-hour failed-check count
reaches `loginHourFailMax` (30) the account is locked for `loginHourLockout`
(1h) via the SAME `userLock` field the rolling layer uses. The hourly budget
PERSISTS across rolling lockouts: `checkUserLock`'s expiry wipes `userFails`
(the rolling window) but NOT `userHour`, and the window re-anchors by wall
clock with `>=` (so an elapsed 1h lockout never re-locks the account on the
very next fail). The operator is unaffected — their known-good (account, IP)
pair is exempt from the whole per-username layer, and a success clears the
budget (`clearUserFail`).
**Why:** the rolling 7-fails/60s → 5-min lockout only catches bursts. An
attacker pacing 6 guesses/minute stays under the threshold forever — ~8,640
guesses/day/account — which puts a common-list password within days,
contradicting the file's own "must not be a free online password-cracking
target" comment. The hourly budget caps any single account at 30 failed
checks/hour. Persistence across rolling lockouts is the load-bearing detail:
without it, 7-fail bursts every 6 min (~70/hr) would outrun a 30/hr cap.
The known-good exemption (already in the code) is what keeps the stricter
limit from locking out the real operator.
**Pinned by:** TestRecordUserFailHourlyBudgetLocks (30th paced fail → 1h
lockout), TestHourlyBudgetPersistsAcrossRollingLockout (burst + 23 paced =
30 → 1h; the budget survives the rolling expiry),
TestHourlyBudgetSelfResetsAfterWindow (elapsed budget resets to 1, no
re-lock), TestClearUserFailClearsHourlyBudget, TestKnownGoodExemptFromHourlyLock.
Sabotage-verified: deleting the `userHour` update in recordUserFail (or
wiping it in checkUserLock's expiry) turns
TestHourlyBudgetPersistsAcrossRollingLockout red — the 30th fail no longer
locks for an hour.

## password-common-blocklist (auth.go, password_blocklist.go, 2026-11-18)
**Decision:** `AddUserMode` rejects the most common passwords at creation
(new sentinel `errPasswordCommon` → 400, mapped in `handleAuthUsers` for both
the setup and in-app paths and refunded on the setup throttle like the other
no-KDF validation errors). The check is a set lookup (`isCommonPassword`,
case-insensitive) BEFORE the bcrypt KDF. `AddUserMode` is the single choke
point, so the CLI `auth-user add` and the API both enforce it.
**Why:** the 8-char minimum alone still admits "password" and "qwerty123" —
the first entries of any cracking list — so a creation-time floor on the
most-frequent passwords removes the cheapest account-takeover path before the
runtime throttle ever matters. The list is a curated top-N from public breach
corpora (a deterrent, not the security boundary — the hourly login budget is);
it's small, embedded, and O(1) to check, so the unauthenticated setup surface
pays nothing.
**Pinned by:** TestAddUserRejectsCommonPassword (errPasswordCommon, no row
written), TestAddUserAcceptsUncommonPassword,
TestIsCommonPasswordCaseInsensitive, TestSetupRejectsCommonPassword (400, no
row). Sabotage-verified: removing the `isCommonPassword` check in AddUserMode
makes TestAddUserRejectsCommonPassword red (the account is created).

## auth-off-rebinding (api.go, main.go, 2026-11-18)
**Decision:** in the auth-off (operator-disabled, `Bootstrapped() &&
!Enabled()`) branch of `authGate`, the `PULSEMON_ALLOWED_HOSTS` allowlist now
applies to EVERY `/api/` request from a non-allowlisted Host — reads included,
not just the POST/PUT/DELETE/PATCH mutations the old `switch` gated. A
non-allowlisted `/api/` read is 421; `/api/healthz` is served above it (the
container healthcheck must reach it in every state) and the static UI
(non-`/api/`) carries no data. With the allowlist unset the LAN-trust default
stands (fully open). `runServer` (main.go) also logs a startup WARNING when
auth is off and no allowlist is set, naming the exposure.
**Why:** a DNS-rebinding page's whole attack is a same-origin GET — the browser
treats the rebound origin as same-origin, so it reads `/api/sensors` (targets
with `user:pass@` creds) and `/api/settings` (SMTP user, from/to, Telegram chat
ID) with a plain GET. Gating only the mutations left those reads wide open, so
the allowlist — which exists specifically to defend against rebinding — did not
close the data-leak vector. `migrateAuthBootstrapped` puts every older
never-accounts install into exactly this auth-off state. The startup warning
closes the "operator forgot the allowlist" case for the no-allowlist default.
**Pinned by:** TestAuthOffRebindingReadBlocked (GET /api/sensors + /api/settings
from a non-allowlisted host → 421; allowlisted host → 200; healthz → 200 from
any host), TestAuthOffRebindingUnsetStaysOpen (no allowlist → read 200),
TestAuthOffRebindingMutationStillBlocked (POST from a non-allowlisted host →
421, no sensor created). Sabotage-verified: reverting the gate to the old
mutation-only `switch` turns TestAuthOffRebindingReadBlocked red (the
/api/sensors GET returns 200, not 421).

## warmstats-paused-sensors (stats.go, warmstats_paused_test.go, 2026-11-18)
**Decision:** `warmStats` (the startup history warm-load) now loads every ACTIVE
AND PAUSED sensor's 24h probe history (`WHERE state IN ('active','paused')`,
was `WHERE state = 'active'`). Runs once, before probing starts.
**Why:** `recordProbe` starts a resumed sensor from whatever is already in the
in-memory cache, and nothing else ever re-loads a sensor's history from the DB.
So a paused sensor that was paused across a restart (the very likely
maintenance → `update --restart` → resume sequence) resumed with an EMPTY
series: blank 24h graphs, uptime counting only post-resume probes, and an empty
60-probe inspector — while `/history` (a direct DB read) still showed the data,
so the two views disagreed. The raw tier is capped per sensor (max(1h, last 60)
entries), so warming paused sensors too is memory-safe — the extra sensors add
no unbounded growth.
**Pinned by:** TestWarmStatsLoadsPausedSensors (a paused sensor with recent
probes is loaded into statsCache with its full series after a fresh warmStats;
an active-sensor control guards the query edit). Sabotage-verified: reverting
the query to `WHERE state = 'active'` turns the test red (the paused sensor is
absent from statsCache).

## comment-hygiene-stale-fixes (api.go, status.go, auth.go, internal/store/store.go, internal/store/db_test.go, 2026-11-18)
**Decision:** Corrected a batch of comments that had drifted from the code they
describe (a stale cross-reference, a wrong interval default, a mislabeled
column, and three garbled sentences from earlier edits). Comment-only: the code
is byte-identical to the prior tree after stripping comments.
**Why:** In auth and concurrency code a wrong comment is worse than none —
reviewers trust it, and some of these explain why a lock or ordering is safe.
The specific fixes: (1) the clear-history / `deleteRowsBatched` batching
rationale cited "syncSensors' under-lock fresh reads," which probe.go removed
(replaced by a generation fingerprint) — reworded to the real reason (a
whole-table DELETE holds the WAL write lock and stalls probe INSERTs /
concurrent readers); (2) DELETE /api/tags claimed "per-sensor edits stay
operator-scoped," but PATCH is admin-only — corrected to destructive +
fleet-wide → admin surface; (3) `statusWindow` assumed a 15s default interval;
it is 60s; (4) `spike_mult` was called a "(deprecated, unread) compatibility
column" whose seed matches UI defaults (3x) — it is a LIVE dashboard-only
display knob and the UI default is 5.
**Pinned by:** comment-stripped code-token equality vs the prior release (proves
zero behavior change); gofmt/vet/build clean; full `-race` green.

## delete-sensor-batched-cascade (api.go, delete_sensor_test.go, 2026-11-18)
**Decision:** `DELETE /api/sensors/{id}` no longer runs a single
`DELETE FROM sensors` that cascades the sensor's whole footprint in one
statement. It now: (1) checks the sensor row exists (a PK lookup;
`sql.ErrNoRows` → 404), (2) stops the probe loop first via
`probeWorker.Remove`, (3) `deleteRowsBatched`-deletes the two large cascade
tables (`probes`, then `events`) in `purgeBatchSize` chunks, and (4) deletes the
sensor row, whose `ON DELETE CASCADE` clears the small tables (`sensor_tags`,
`alert_state` — a few rows each).
**Why:** A 5s sensor's `probes` table is ~17k rows; the single cascading DELETE
held the WAL write lock across the entire sweep — the exact class of long
lock-holder that `clear-history` and the retention purge were rewritten to avoid
with `deleteRowsBatched` (each statement is its own bounded autocommit, so the
lock is held for milliseconds per chunk, and probe INSERTs / concurrent readers
stay responsive). Stopping the loop first means no new probe/event/alert rows
land mid-delete; if a delete fails and the sensor survives, `syncSensors`
respawns the loop on its next 5s pass (`Remove` only drops the in-memory loop +
state, not the DB row), so a partial delete converges on retry rather than
stranding the sensor with no loop.
**Pinned by:** TestDeleteSensorRemovesCascade (a sensor with probes + events + a
tag + an alert_state row is fully removed — every cascade table empty — and its
loop + ProbeState dropped) and TestDeleteSensorNotFound (a missing id returns
404 and leaves other sensors untouched). These pin the behavioral contract (full
cascade removal, 404, loop stop); the bounded-lock batching is the same
`deleteRowsBatched` idiom already pinned by the clear-history tests, so it is not
re-proven here.

## auth-bootstrapped-latch (auth.go, auth_bootstrapped_test.go, 2026-11-18)
**Decision:** `AuthState.Bootstrapped()` now latches its answer. A one-way
`atomic.Bool` (`bootstrapped`) is set the first time a read sees
`auth_bootstrapped=1`; every later call returns true without touching SQLite.
A not-yet-latched read always re-queries (a `bootstrappedFn` seam defaults to
`db.GetSetting("auth_bootstrapped")`), so an out-of-band `pulsemon auth-user
add` (a separate process writing the setting) is picked up on the next call.
**Why:** `Bootstrapped()` sits on the per-request auth gate (api.go — every
request, static assets included) and on the unauthenticated
`/api/auth/status`. It used to run `GetSetting("auth_bootstrapped")` on every
call. The flag never goes back to false (set by AddUser, never cleared —
including when the operator later disables auth), so caching only the TRUE
value is safe: the latch ratchets false→true and can never mask a real
bootstrap, because a not-yet-latched state always re-queries.
**Pinned by:** TestAuthBootstrappedLatchesTrue (a counting `bootstrappedFn`
seam proves the query stops after the latching read — reads stays at 2 across
further calls) and TestAuthBootstrappedPicksUpCLIAdd (a fresh, un-latched
AuthState observes an out-of-band DB write of the setting on the next read —
the latch never caches false).

## pulse-now-fleet-limit (probe.go, ping_now_fleet_limit_test.go, 2026-11-18)
**Decision:** `PingNow` now acquires a fleet-wide in-flight cap before
probing: a bounded semaphore `pulseSem` (capacity `pulseMaxInFlight` = 8). The
non-blocking acquire returns `errPulseBusy` (→ 429) when the cap is full;
otherwise the slot is held for the probe + write and released by defer. The
per-sensor 2s cooldown is unchanged and is checked after the cap.
**Why:** The cooldown bounds ONE sensor, so a viewer with N sensors could fan
out ~N/2 concurrent outbound probes at once (100 sensors ≈ 50/s), each holding
a request handler for up to the sensor's timeout and writing a probe row. The
shared semaphore caps the total concurrent manual pulses at 8, so a many-sensor
fan-out can't tie up a large handler pool. A manual pulse is a quick
diagnostic, so refusing with 429 (which the UI already handles) is preferable
to queuing.
**Pinned by:** TestPingNowFleetLimit (filling `pulseSem` to its cap makes
PingNow return `errPulseBusy` without probing; freeing one slot lets it
proceed past the cap).

## scale-ceiling (gzip.go, api.go, gzip_test.go, 2026-11-18)
**Decision:** `/api/` responses are gzip-compressed for clients that accept
it. `authGate` wraps the ResponseWriter with a streaming `gzipResponseWriter`
(only for `/api/` + `Accept-Encoding: gzip`); the wrapper supports
`http.Flusher` (so the update-progress and TLS-settings streaming endpoints
keep working) and suppresses `Content-Length` (the compressed size differs, so
the server falls back to chunked encoding). This is the one cheap piece of the
scale ceiling: every open dashboard tab re-pulls the whole uncompressed fleet
every 5s, and the payload grows with sensor count — compressing the JSON cuts
that per-tab, per-poll traffic (~5-10x on JSON).
**Deferred (known ceiling, not a defect at homelab scale):** the two heavier
fixes the external review named for 1000s of sensors are documented here and
NOT implemented — they carry real regression risk for zero benefit at the
current 22-sensor fleet:
- **Per-sensor history locks.** `statsMu` is one `sync.RWMutex` guarding the
  whole `statsCache` map (every probe append + every dashboard read). At
  1000s of sensors + many tabs this serializes the read path; the fix is one
  lock per sensor's series.
- **Batched probe writes.** Each probe writes its own `INSERT` through the
  single-connection probe-write handle. At 1000s of sensors the fix is a
  writer goroutine that batches outcomes and flushes every ~250ms in one
  transaction. This touches the write path's ts-ascending ordering, shutdown
  flush, and the stats-cache lockstep, so it is the riskier of the two.
The `syncSensors` full re-read every 5s is trivially cheap at homelab scale
and would get a `MAX(updated_at)` pre-check only if targeting 1000+ sensors.
**Pinned by:** TestGzipAPIResponses (a gzip-accepting client gets
`Content-Encoding: gzip` + a body that decompresses to the sensor JSON; a
client with no Accept-Encoding gets a raw body with no Content-Encoding; an
explicit `gzip;q=0` is served raw).

## structure-split-rejudicated (repo-wide, 2026-11-18)
**Decision:** the 2026-11-18 external review (finding #9) re-raised the
package split (`internal/{auth,probe/icmp,probe/http,alert,api,update}` +
constructor-injected dependencies) and `t.Parallel`. REJECTED again — the
original decision (→ structure-and-comment-density, 2026-11-11) stands.
**Re-open conditions check (none fired):**
- Test time > 8 min: the full `-race` suite is ~5.7 min (341s) — under the bar.
- Recurring globals `-race` hit: the suite is green (0 failures); no recurring
  globals-related race.
- Second developer: single-developer repo.
**Why (unchanged):** the package-level vars the review names as the problem
(`probeTarget`, `certReadTimes`, the throttle maps, …) ARE the test seams the
single-package suite stubs; `internal/*` + constructor DI rewrites the whole
harness surface for zero behavior change. `t.Parallel` is a consequence of that
refactor (shared ICMP socket, throttle maps, per-test SQLite files, bind
ports), not an independent win.
**Additive gap closed:** the review's "resume after a restart shows the 24h
graph and uptime" test was the one genuine gap — added as an end-to-end test.
The other three suggested tests were already covered (paced-login →
`TestHourlyBudgetPersistsAcrossRollingLockout`; delete-cascade →
`TestDeleteSensorRemovesCascade`) or are a policy call (CI benchmark smoke —
benchmarks are deliberately opt-in per ci.yml).
**Pinned by:** TestRestartRebuilds24hGraphAndUptime (a fresh worker with an
empty cache warms from the DB; Uptime24h ≈ the seeded 90% and the 24h graph is
rebuilt with its loss/reply shape intact).

## unique-constraint-by-code (auth.go + api.go, 2026-11-18)
**Decision:** unique-constraint detection is by SQLite RESULT CODE, not by
driver message text. Finding #10 (external review): four sites matched the
string `"UNIQUE constraint failed: <table>.<column>"`, which breaks silently
if a modernc.org/sqlite upgrade rewords the message.
**Verified against modernc.org/sqlite v1.29.1 (go.mod):** `*sqlite.Error`
exposes `Code() int` (sqlite.go:68); the constant is
`SQLITE_CONSTRAINT_UNIQUE == 2067`, in import path `modernc.org/sqlite/lib`
whose package name is `sqlite3` (the driver imports it as
`sqlite3 "modernc.org/sqlite/lib"`). The result codes are stable ABI; the
message string is not.
**PK vs UNIQUE (verified empirically):** SQLite emits the SAME
"UNIQUE constraint failed: <t>.<c>" message for a UNIQUE-index violation
(`SQLITE_CONSTRAINT_UNIQUE` = 2067, the sensors.name case) AND a PRIMARY
KEY violation (`SQLITE_CONSTRAINT_PRIMARYKEY` = 1555, the users.username
case). The old text match caught both, so the code check must too.
**Change:** one helper `isUniqueConstraintErr(err)` (errors.As to
`*sqlite.Error`, match `Code()` against 2067/1555) replaces all four text
matches:
auth.go (users.username INSERT), api.go POST sensor + PATCH rename + clone
retry (sensors.name). Each site's context makes the sensors.name /
users.username index the only realistically violable constraint (id is a
generated UUID), so the code alone is sufficient; a theoretical id PK
collision now also 409s (benign mislabel, not a crash).
**Pinned by:** TestIsUniqueConstraintErr (a real duplicate INSERT classifies
true; a syntax error, a plain text error carrying the old wording, and nil
all classify false — the plain-text case fails loudly if anyone reverts to
message matching). The existing 409 integration tests (TestFix_M7_PatchDuplicateName409,
clone_name_test, the auth duplicate-user test) now exercise the code path.

## store-data-access-layer (internal/store + api.go, 2026-11-18)
**Decision:** finding #11 (external review) — `Store` embeds `*sql.DB`, so
every handler writes raw SQL; the full-sensor column list + its 12-field scan
were copy-pasted 3×; and the store methods were inconsistent about context
(`RemoveUser` hid a `context.Background()` while `UserCount`/`GetSetting`
took none). BOUNDED fix applied; the full data-access-layer refactor is
deferred as a known ceiling.
**Done (bounded, behavior-preserving):**
- Dedup: `sensorCols` const + `scanSensorRow(sc sensorScanner, *Sensor)` in
  api.go now serve all three full-sensor SELECTs (fetchSensors,
  handleSensorByID, handleSensorClone). Adding a sensors column is a one-place
  edit (list + scan) instead of a three-site copy-paste.
- Context: `Store.RemoveUser` and `AuthState.RemoveUser` now take a
  `context.Context` (the caller's request context reaches the DELETE +
  last-admin promotion; the CLI passes `context.Background()`), so no store
  method hides a Background context. The consistency RULE is documented:
  methods that span a transaction (RemoveUser, ImmediateTx, SetSettingInTx)
  take a ctx; single autocommit helpers (GetSetting, SetSetting, UserCount,
  UserHash, SetUserPassword) take none (short, called from handlers +
  background + CLI + tests).
**Deferred (known ceiling):** un-embedding the field (private `db *sql.DB` +
named methods for every production raw-SQL site) so handlers *can't* write
raw SQL. Blast radius measured: 13 raw-SQL sites in api.go, promoted-method
use across 7 production files, and 70 of 165 test files call `db.QueryRow` /
`db.Exec` directly (tests assert state by querying the DB, which the embedded
field makes trivial). That churn is a large, high-risk, behavior-preserving
refactor not justified for a single-dev homelab tool; the embedded field is a
deliberate test-simplicity tradeoff.
**Pinned by:** the existing RemoveUser tests (TestRemoveUserNonexistentReportsNotFound,
TestAuthRemoveLastUserProtected, TestRemoveUserConcurrentNeverZero,
TestIsAdminInvalidatedOnPromotion) now pass a ctx; the sensor fetch/clone
tests exercise the deduped `sensorCols`/`scanSensorRow` path.

## review-nits-batch (api.go, auth.go, ping.go, tcp.go, tls_settings.go, update_api.go, 2026-11-18)
**Decision:** four small external-review nits, all behavior-preserving:
(1) the 429-with-Retry-After block was copy-pasted 5× in auth.go;
(2) `timeout_ms` meant different things per probe type — TCP/HTTP included the
DNS lookup in the budget, ICMP did not, so a 30s ICMP Pulse Now could run ~5s
longer and outlast the server's 30s WriteTimeout (client got nothing);
(3) `probeTCP` didn't guard a nil IP from `resolveICMPTarget` (an IPv6 literal
in a hand-edited row dialed `":port"` = localhost);
(4) the JSON decoders never called `DisallowUnknownFields` (a misspelled PATCH
field was silently dropped when a valid one was present) and `respondWithJSON`
dropped `Encode` errors.
**Done:**
- (1) `respondThrottled(w, wait, msg)` in api.go (next to `respondWithJSON` /
  `respondWithError`) derives `Retry-After` by ceiling to whole seconds (min 1)
  and answers 429; all five auth.go throttle/lockout sites now call it. The
  per-site messages are unchanged.
- (2) `pingHost` wraps its ctx in `context.WithTimeout(ctx, timeout)` at the
  top, mirroring `probeTCP`/`probeHTTP`, so the DNS lookup and the reply-wait
  are bounded TOGETHER by the probe timeout. `e.Ping` already honors
  `ctx.Done()`, and `dnsLookup`'s `DoChan` select returns on the caller's ctx,
  so the bound propagates to both phases (the shared singleflight call keeps
  running in the background, but the caller stops waiting at `timeout`).
- (3) `probeTCP` returns a clean loss (`no IPv4 address for <host>`) when
  `resolveICMPTarget` yields a nil IP, mirroring `pingHost`'s existing check.
- (4) all 9 production `json.NewDecoder` sites now call `DisallowUnknownFields`
  (api.go ×4, auth.go ×3, tls_settings.go, update_api.go). Verified safe: every
  frontend payload in web/app.js is a strict subset of the Go struct fields.
  `respondWithJSON` now logs `Encode` errors (the status line is already
  written, so it can't change the response — it's observability only).
**Why (4 is a contract change, handled deliberately):** strict decode turns a
silent no-op into a 400. That's the right call for a single-client API (the
frontend is the only producer, and its payloads are field-exact), and it's what
the finding asked for. `update_api.go` keeps its `err == nil && body.Version
!= ""` tolerance so a malformed update body still falls through to "latest".
**Pinned by:** nits_20261118_test.go — TestRespondThrottledSetsRetryAfter
(Retry-After ceiling), TestPingHostBoundsDNSToTimeout (1s-slow resolver on a
200ms probe returns a DNS loss in <800ms; drains the singleflight call so the
stub-swap cleanup doesn't race the shared-call goroutine),
TestProbeTCPIPv6LiteralIsCleanLoss, TestPatchSensorRejectsUnknownField
(misspelled field = 400, valid field = 200). Full `-race` suite green.

## shared-engine-init (ping.go, healthz_icmp_test.go, 2026-11-19)

**Decision:** `SharedEngine` memoizes the one-shot open under
`sharedEngineMu` (write lock + nil-check guard) instead of `sync.Once`;
`EngineMode`/`EngineDead` read the state under the read lock and no longer
participate in the init (the `Do(func(){})` join is gone). `getSharedConn`
and `pingHost` are unchanged — the contract "nil error ⇒ non-nil engine"
is now guaranteed by the memo itself.

**Why:** The no-op `Do(func(){})` join consumed the Once whenever a reader
won the startup race — `runServer` starts the probe worker (which warms
the engine via `getSharedConn`) in a goroutine CONCURRENTLY with
`startListener`, so a `GET /api/healthz` landing in that window left
`(sharedEngineInst == nil, sharedEngineErr == nil)` permanently: the next
`SharedEngine()` returned `(nil, nil)` and `getSharedConn` panicked on
`e.rawConn` (server crash on boot; `pingHost` panics on `e.Ping`). The
same poisoned state had already bitten the test suite (a re-zeroed Once
consumed by a later test's join). The mutex memo keeps the exact-once +
cached-failure semantics with no consumable join left to win.

**Pinned by:** TestEngineReadsBeforeInitDoNotConsumeInit (reads in the
fresh state, then SharedEngine must still open — fails on the (nil, nil)
return the old join shape produced), TestSharedEngineConcurrentInit
(32-goroutine reader/writer hammer under -race; asserts no (nil, nil) and
no engine+error pair). Sabotage-verified: restoring the `Do(func(){})`
join makes TestEngineReadsBeforeInitDoNotConsumeInit fail with
"SharedEngine returned (nil, nil) — the read consumed the one-shot init".

## legacy-token-startup-step (internal/store/store.go, main.go, legacy_token_test.go, auth_test.go, setup_mode_test.go, 2026-11-19)

**Decision:** The legacy `auth_token` → admin-user conversion is no longer a
versioned migration — slot 11 is a no-op (number preserved), and
`MigrateLegacyAuthToken` runs as an idempotent STARTUP step on every boot
(`startupAuthMigrations` in main.go, right after `InitSchema`; also in the
`auth-user` CLI path). The migrated 'admin' is inserted with `is_admin = 1`
directly (the step runs after slot 12, so it no longer rides slot 12's
promotion), and its n>0 path runs the oldest-user promotion to guarantee an
admin exists (zero-admin installs are forbidden). `migrateUserAdminColumn`
(slot 12) now runs on the step's tx, so column + promotion + version stamp
commit atomically. `migrateAuthBootstrapped` bails while `auth_token` is
non-empty OR unreadable (fail closed, not open).

**Why:** `MigrateLegacyAuthToken` returns nil on a deferred DB failure
(UserCount/INSERT error) to retry next boot, but `applyMigration` treats nil
as success and commits `PRAGMA user_version = 11` (+12). Every later boot
skips the migration forever, and `migrateAuthBootstrapped` (0 users + probe
history) stamps `auth_bootstrapped = 1` — a token-protected install with no
runtime token consumer booted fully unauthenticated; one transient DB error
on the upgrade boot was enough. `TestLegacyTokenMigratesOnRetry` masked the
defect by resetting `PRAGMA user_version = 0` by hand. Slot 12's two
statements also ran on pool connections, so the ALTER could commit
independently of the step's stamp, leaving a half-migrated schema on a
failed step. A deferred pass must stay retryable, which is impossible while
it is versioned.

**Pinned by:** TestDeferredLegacyTokenMigrationRetriesNextBoot (replay
defers → next boot's startup step completes; sabotaged old shape fails with
"token not cleared after the retry"), TestMigrateUserAdminColumnAtomicWithStamp
(a failing slot-12 statement rolls back the whole step — no column, stamp
stays 11; sabotaged pool-conn shape fails with "is_admin column survived a
failed slot-12 step"), TestAuthBootstrappedBailsOnPendingToken (the latch
must not stamp over a pending token; sabotaged no-bail shape fails with
"bootstrapped latched on a token-pending install"),
TestStartupAuthMigrationsCompletesPendingToken (boot sequence migrates +
clears + latches, idempotent — no duplicate admin on a second boot).

## watchdog-prev-and-scope (update.go, update_api.go, update_detach_linux.go, update_detach_windows.go, install.sh, update_restart_test.go, 2026-11-19)

**Decision:** The post-restart watchdog is spawned from `<exe>.prev`
(the known-good previous binary) when it exists, falling back to `<exe>`
when it does not (first update from a pre-.prev release — nothing to roll
back to, but the spawn must not fail for lack of a binary). On systemd
with a known bus, the spawn is wrapped in `systemd-run [--user] --scope`
(path resolved from fixed system locations via the testable
`systemdRunPath` var, "" when absent → plain detach) so the watchdog
lives in an independent transient cgroup. The install.sh-generated unit
now sets `KillMode=process` as belt-and-suspenders. Command construction
is factored into `buildWatchdogCommand(exe, bus)` so the contract is
pinned without starting a process.

**Why:** `spawnUpdateWatchdog` ran `exec.Command(exe, ...)` after
`installBinary` had already swapped `exe` to the NEW binary — a
wrong-arch binary or an init() crash failed the spawn and the restart
proceeded with no guardian at all. Separately, a plain Setsid detach
leaves the watchdog in pulsemon.service's cgroup and the unit (no
`KillMode=`) defaults to `KillMode=control-group`, so `systemctl
restart` killed the watchdog with the service — auto-rollback was dead
in exactly the failure modes it was built to recover from.

**Pinned by:** TestBuildWatchdogCommandPrefersPrevBinary (old shape
fails: "watchdog binary = <exe>, want the previous binary"),
TestBuildWatchdogCommandFallsBackToExe, TestBuildWatchdogCommandSystemdScope
(user bus → `--user --scope` prefix, system bus → `--scope`, unknown bus
→ plain binary, no wrapping). Sabotage-verified: with
buildWatchdogCommand restored to the old exec.Command(exe, ...) shape,
TestBuildWatchdogCommandPrefersPrevBinary fails ("want the previous
binary ... (the new one may be the broken one)") and
TestBuildWatchdogCommandSystemdScope fails ("want prefix
[/usr/bin/systemd-run --user --scope ...]").

## gzip-lazy-pool-unwrap (gzip.go, api.go, gzip_test.go, 2026-11-19)

**Decision:** `gzipResponseWriter` now (1) lazily initializes its
compressor on the first body write from a `sync.Pool` (a fresh
`gzip.NewWriter` allocates ~800 KB of deflate state per /api/ response),
(2) implements `Unwrap() http.ResponseWriter` so `http.ResponseController`
(handleUpdate's 90s SetWriteDeadline) and `http.MaxBytesReader`'s
requestTooLarge connection-close reach the real connection, (3) bypasses
gzip entirely for bodyless statuses (1xx/204/304 — no trailer, no
Content-Encoding), (4) is excluded from POST /api/update (handleUpdate's
synchronous performRestart SIGTERMs the process before the deferred gzip
Close can write the trailer), and (5) advertises `Vary:
Accept-Encoding` with case-insensitive encoding matching. The
MaxBytesReader body bound now wraps `r.Body` BEFORE w is wrapped in the
gzip writer (the hook's writer is the authoritative close path).

**Why:** the old shape allocated a fresh compressor per 5s dashboard
poll (GC churn), silently dropped the 90s update write deadline
(ErrNotSupported without Unwrap → 30s WriteTimeout cut ~60s self-updates),
wrote a 20-byte gzip footer after 204 No Content / 304 / HEAD (protocol
violation), and left a truncated gzip trailer on the update 202
(performRestart killed the process before the trailer —
ERR_CONTENT_DECODING_FAILED in the browser). MaxBytesReader was also
constructed with the gzip wrapper as its writer, so the 413
connection-close hook could not reach the connection.

**Pinned by:** TestGzipControllerReachesInnerWriter (SetWriteDeadline
through the wrapper reaches the inner writer),
TestGzipBodylessCarriesNoTrailer (204/304: zero body bytes, no
Content-Encoding), TestGzipNormalResponseDecodes,
TestGzipWriterPooledAndReused (same compressor instance round-trips the
pool), TestAcceptsGzipCaseInsensitive ("GZIP" qualifies, "GZIP;q=0"
declines), TestAPIUpdateResponsesAreNotGzipped (update identity + Vary on
/api/healthz), TestOversizedBody413ClosesConnection (413 closes the
connection — counting listener sees a second conn). Existing
TestGzipAPIResponses (finding #8) still passes. Sabotage-verified: with the
old behavioral shape restored (no Unwrap, no bodyless bypass, /api/update
gzipped, body bound after the wrap), TestGzipControllerReachesInnerWriter
fails ("feature not supported"), TestGzipBodylessCarriesNoTrailer fails
("Close: ... does not allow body" — the 20-byte trailer on a 204),
TestAPIUpdateResponsesAreNotGzipped fails (Content-Encoding: gzip on
/api/update), and TestOversizedBody413ClosesConnection fails (the 413
never closes the connection).

## tls-selfsigned-gate (http.go, http_test.go, cert_shapes_test.go, tls_selfsigned_policy_test.go, 2026-11-19)

**Decision:** The self-signed allowance in `verifyHTTPCert` (branch b) is now
gated to homelab-shaped targets: it is skipped when (1) the target URL
carries userinfo (`https://user:pass@host` — `probeHTTP` carries a
`tlsUserinfoKey` context flag to `probeDialTLS` → `verifyHTTPCert`) or
(2) the target is a public (globally routable) IP literal
(`isPublicProbeIP`: RFC1918 / loopback / link-local / 0/8 / ULA are
private; hostnames are out of scope). Refusals name the specific rule and
the remedy (install a CA-signed cert, or pin the cert/CA via
PULSEMON_CA_FILE, which branch (a) honors). The signature is now
`verifyHTTPCert(presented, host, hasUserinfo)`.

**Why:** An on-path attacker (ARP/DNS spoof on a LAN segment) minting a
self-signed cert for the target takes milliseconds and passes the exact-SAN
check. `probeDialTLS`'s pre-request verification exists precisely so an
untrusted cert never sees the request — including the
`Authorization: Basic *** header derived from a `user:pass@` target's
userinfo. But branch (b) accepted the minted cert for EVERY https sensor,
so the MITM threat model was negated exactly where the credentials ride:
the attacker passes the SAN check, receives the Basic auth header, and the
sensor reads UP. For a status-only private sensor the same attack is an
availability spoof at worst, so the homelab self-signed convenience
stays there; a self-signed cert on a public IP is not an operator's device
in the first place (the homelab pattern is private targets), so it is
refused too — pin it via PULSEMON_CA_FILE.

**Pinned by:** TestVerifyHTTPCertRefusesSelfSignedWithUserinfo (same
private-IP self-signed cert: accepted without userinfo, refused with),
TestVerifyHTTPCertRefusesSelfSignedPublicIP (public IP refused, private
control accepted), TestIsPublicProbeIP (the public/private classification,
incl. 172.16/12 edges, IPv4-mapped IPv6, ULA), TestProbeHTTPSUserinfoRefusesSelfSigned
(end-to-end: `https://user:pass@` probe of a matching self-signed server is
a LOSS with the Authorization header NEVER reaching the server; the
no-userinfo control stays UP). All pre-existing verifyHTTPCert call sites
updated to the 3-arg form (`false` — they test credential-less targets).
Sabotage-verified: with the branch-(b) gate removed (old policy),
TestVerifyHTTPCertRefusesSelfSignedWithUserinfo,
TestVerifyHTTPCertRefusesSelfSignedPublicIP, and
TestProbeHTTPSUserinfoRefusesSelfSigned all fail (the minted cert is
accepted and the Basic auth header reaches the server).

## common-password-change-gate (auth.go, auth_hourly_budget_test.go, password_change_test.go, 2026-11-19)

**Decision:** The common-password blocklist now applies to password
CHANGES, not just creation. `SetUserPassword` returns
`errPasswordCommon` for a listed password (mirroring `AddUser`'s
creation-time check, same order: weak → common → too-long),
`handleAuthUserPassword` pre-rejects a listed new password with 400
BEFORE beginAttempt and before the current-password KDF (structural
rejects are uncharged — same category as the min-length pre-rejection),
and the handler's error mapping routes `errPasswordCommon` to 400 (it
previously fell through to `respondInternal` → 500).
`TestSetupRejectsCommonPassword`'s payload was replaced: it carried a
3-char password that failed minPasswordLen before ever reaching
isCommonPassword (a false green — the blocklist contract was untested),
and it now uses "password123" (on the list, clears the 8-char floor)
and asserts the errPasswordCommon sentinel in the 400 body.

**Why:** A user created under the hardening rule could change their
password to "password" in the very next request — the creation-time
check was a formality. The API contract (common → 400, not 500) was
untested because the only test hit the length check first and asserted
status only, not the sentinel. The pre-throttle placement keeps the
endpoint's invariant: structurally doomed requests never run the KDF on
req.Current and never charge the per-IP / per-username throttle.

**Pinned by:** TestSetUserPasswordRejectsCommonPassword (AuthState:
"password" and "password123" refused with errPasswordCommon, old
password still verifies, the new one does not),
TestChangePasswordRejectsCommon (HTTP: 400 + errPasswordCommon sentinel
for both, never a 500; old password unchanged; an unlisted password of
the same shape succeeds — deterrent, not a wall),
TestSetupRejectsCommonPassword (fixed payload + sentinel assertion).
Sabotage-verified: with the change path ungated (old code),
TestSetUserPasswordRejectsCommonPassword fails (SetUserPassword("password")
= nil) and TestChangePasswordRejectsCommon fails (200 {"ok":true} on a
change to "password"); TestSetupRejectsCommonPassword stays green (it
pins the setup path, which was never broken).

## maintenance-transition-ordering (api.go, internal/store/store.go, probe.go, alerts.go; 2026-11-19)

**Decision:** Two parts. (1) `EnterMaintenanceWithFreshSnapshot` now
re-checks `maintenance_mode` INSIDE its write-locked tx (after pinning
the lock): if the mode is already "1" it returns `(nil, nil)` — a no-op
enter that leaves the winner's snapshot untouched. (2) The settings PUT
handler now orders each maintenance transition explicitly and the
handler-exit `defer reloadAlertSettings()` is demoted to an idempotent
re-read:
- enter: DB commit → `reloadAlertSettings()` → `SetPaused(id, true)` →
  `ResetAlertStates()`
- leave: DB commit → `ResetAlertStates()` → `reloadAlertSettings()` →
  `SetPaused(id, false)`

**Why:** `maintAlreadyOn` is a pre-tx read, so two back-to-back
`PUT /api/settings {"maintenance_mode":true}` requests (a UI
double-click) both see "0" and both run the enter tx; the second
pauses 0 sensors (the first already did), marshals `nil` as `"null"`,
and overwrites `maintenance_active_ids` — leaving maintenance then
resumes NOTHING and the whole fleet is stranded paused. The pre-tx
read can never be made authoritative (the read and the pause are not
atomic), so the check moved under the write lock where the serialized
enter sees the committed state. The ordering fix closes the stale
snapshot window on both sides: pre-fix the alert-snapshot swap ran
only in the handler-exit defer, so on enter, in-flight probes finishing
after the commit fired alerts under a stale `maintenance:false` (an
alert during a maintenance the operator just asked for), and on leave,
a fast sensor recovering between the resume and the handler exit read a
stale `maintenance:true` from the snapshot and dropped its recovery
alert permanently (the alert timers were reset, so the next tick would
not re-alert either). With the explicit order, the gate (snapshot)
changes before the loops can observe the new pause state on both
transitions. The deferred reload is kept: plain (non-maintenance) PUTs
and the maintenance-tx 500 returns still rely on it.

**Pinned by:** TestEnterMaintenanceAlreadyOnIsNoOp (store: a second
enter while mode is ON returns nil, the snapshot stays the original 2
ids — not "null" — and leave resumes both),
TestConcurrentEnterMaintenancePreservesSnapshot (HTTP end-to-end,
interleaving forced through the enterMaintenance seam so BOTH PUTs
pre-read "0": second enter runs against the committed mode, snapshot
survives, leave restores the full fleet), TestMaintenanceTransitionOrdering
(worker observation hooks: the first reloadAlertSettings precedes the
first SetPaused flip on BOTH enter and leave). Sabotage-verified:
with the in-tx re-check removed, both snapshot pins fail (the second
enter overwrites the snapshot with "null"); with the old handler
ordering restored (pause/resume before the reload), the ordering pin
fails on both transitions.

## sensor-delete-deleting-state (api.go, probe.go, delete_sensor_test.go, 2026-11-19)

**Decision:** `DELETE /api/sensors/{id}` marks the row `state = 'deleting'`
BEFORE `probeWorker.Remove(id)` and the batched cascade deletes. The
transient state is excluded from every reader that could resurrect the
sensor: `syncSensors` still selects `state IN ('active','paused')`,
`PingNow` rejects it with the `errSensorDeleting` sentinel (mapped to 409
by the ping handler), the dashboard list query filters it out, and the
maintenance/ActiveSensorIDs paths already excluded non-active states. If a
cascade step fails, a compensating `UPDATE` restores the pre-delete state
(captured at the existence check) so a surviving sensor is never stranded
in `deleting` — no loop, invisible to sync, pulses refused — with no path
back. The `syncSensors` vanished pass now calls the same full-cleanup
helper as `Remove` (`removeSensorState`): loops, sensors, spawnedIDs,
wasPaused, gens, lastPulse, statsCache, alertOrderGates, and alertMem.
`deleteRowsBatched` is a var (seam) so the post-mark failure path is
testable.

**Why:** `Remove(id)` ran while the row was still `state = 'active'` for
the whole cascade window (seconds — a 5s sensor carries ~17k probe rows
across the two batched deletes). A 5s `syncSensors` tick (or a `syncReq`)
landing in the window saw the sensor as active and RESPAWNED the loop
`Remove` had just dropped: the respawned loop wrote new probe/alert rows
for a sensor mid-deletion, repopulated `statsCache`, and logged FK
errors once the sensor row finally vanished. When the row did disappear,
`Remove` was not re-run, and the vanished pass only deleted
`pw.loops[id]` + `pw.sensors[id]` — leaking `statsCache[id]` (~57 KB),
`spawnedIDs`, `wasPaused`, `gens`, `lastPulse`, `alertOrderGates`, and
`alertMem` for the process lifetime. The mark closes the whole window in
one write (autocommit, before `Remove`), and the shared cleanup helper
makes the vanished pass a real cleanup instead of a partial one. The
compensation matters because the mark makes a cascade failure
recoverable only via the restore — a stranded `deleting` row would be a
silent dead sensor.

**Pinned by:** TestSyncSensorsIgnoresDeletingSensor (a row in
`deleting` gets no loop/ProbeState from a sync pass, control sensor
spawns), TestPingNowRejectsDeletingSensor (PingNow returns
errSensorDeleting, HTTP 409, zero manual probe rows written),
TestVanishedSensorCleanupReleasesAllMaps (full footprint seeded in all
eight maps + loop cancel; after row deletion + sync pass, every map is
empty and the cancel fired), TestDeleteSensorRestoresStateOnBatchedDeleteFailure
(cascade failure injected through the deleteRowsBatched seam: 500, state
restored to 'active', the mid-window state observed by the cascade is
'deleting', and the sensor respawns on the next sync pass).
Sabotage-verified: with syncSensors made to see 'deleting' rows, pin 1
fails; with the vanished pass reverted to the partial
cancel/delete-loops/delete-sensors cleanup, pin 3 fails; with the
PingNow rejection removed, pin 2 fails; with the handler's mark removed,
pin 4 fails (mid-window state is 'active').

## sqlite-scalability-container-hazards (internal/store/store.go, internal/store/sqlite_tuning_test.go, internal/store/legacy_token_test.go, probe.go, stats.go, Dockerfile, 2026-11-19)

**Decision:** `dsnWithPragmas` now emits
`busy_timeout → journal_mode(WAL) → synchronous(NORMAL) →
foreign_keys(1) → temp_store(MEMORY) →
journal_size_limit(67108864) → cache_size(-8000)`, and migration 13
replaces `idx_probes_sensor_ts(sensor_id, ts)` with the covering
`idx_probes_sensor_ts_cov(sensor_id, ts, rtt_ms, manual)` (fresh DBs get
the covering index straight from the base schema; the migration's
CREATE/DROP guards make replay a no-op). The Dockerfile documents why
the scratch image's missing /tmp makes `temp_store(MEMORY)` load-bearing.

**Why:** (1) The driver executes `_pragma` params in DSN order, and
`journal_mode(WAL)` is the only one that WRITES (mode flip + -wal/-shm
creation). With journal_mode first, a lazy pool connection — and the 30s
-healthz-http probe, which opens its own connection every check — that
landed while another connection held the write lock ran the mode switch
with busy_timeout = 0 and failed immediately with SQLITE_BUSY.
(2) The FROM-scratch image runs as uid 1000 with no /tmp and a
non-writable /; without `temp_store(MEMORY)` (modernc compiles with
TEMP_STORE=1 = FILE), any query spilling a temp B-tree fails with
SQLITE_CANTOPEN. (3) Without `journal_size_limit`, a large delete
(clear-all-history, a multi-million-row purge) checkpoints into a WAL
that stays at its hundreds-of-MB high-water mark on disk for the process
lifetime; 64 MiB caps it. (4) The old (sensor_id, ts) index served the
range but not the SELECT list: warmStats Phase 1 (~1.7M rows at 100
sensors / 5s), Phase 2, and every recentFromDB/history read paid a
random table B-tree lookup per row for rtt_ms + manual (~6.3s on the
live fleet against the default 2 MiB page cache, which
`cache_size(-8000)` raises to 8 MiB per connection).

**Pinned by:** TestDSNPragmaOrderPinsBusyTimeoutFirst (busy_timeout
strictly precedes journal_mode in the DSN; all seven pragmas present),
TestPragmasReachEveryPooledConnection (pool-connection read-back:
temp_store=2/MEMORY — the C enum, where 0 is the compile-time FILE
default — journal_size_limit=67108864, cache_size=-8000),
TestPragmasReachProbeHandle (the second handle carries temp_store too),
TestProbesIndexCoveringFresh (fresh DB: the covering index exists with
the exact 4-column order, the old index is gone, and EXPLAIN QUERY PLAN
serves the warm-stats query from COVERING INDEX idx_probes_sensor_ts_cov),
TestProbesCoveringIndexMigration (a DB stamped at version 12 with the
old index boots through InitSchema into the covering index, old one
dropped, version at the head). legacy_token_test's replay assertion
moved from a hardcoded 12 to schemaVersionHead (a new head is expected).
Sabotage-verified: old DSN order → pin 1 fails; stripped DSN → pins 2-3
fail; old index + no migration 13 → pin 4 fails; migration 13 without
the DROP → pin 5 fails.

## cert-readtimes-keepalive-refresh-and-per-probe-scan (http.go, cert_reuse_test.go, cert_freshness_test.go, nits_20261111_test.go, update_check_test.go, 2026-11-19)

**Decision:** `probeHTTP` now records
`certReadTimes[hostKey]` ONLY when the probe's final connection was
freshly dialed (`httptrace.GotConn` `Reused == false`, captured in the
existing trace closure alongside `connAt`/`resolved`). The stale-entry
scan moved from every write to at most once per `certFreshness` window,
gated by a new `certReadLastPrune` timestamp under the same
`certReadMu`. `certFreshness` became a var (was const) so tests can
shrink the window and exercise the force-fresh cadence in seconds.
`TestCertReadTimesPrunedOnWrite` now sets the prune-window precondition
explicitly (window elapsed) and restores `certReadLastPrune` in
Cleanup, making it order-independent. The dangling duplicate
`TestCertFreshnessReusesConn` comment at the end of update_check_test.go
(test body lives in cert_freshness_test.go) was removed, and that test's
step-2 comment now states the real behavior: probe 2 dials fresh on the
pooled transport because probe 1's conn was on the no-reuse transport.

**Why:** (1) A keep-alive reuse reports the cert from the pooled conn's
ORIGINAL handshake — no new TLS data exists to record. Overwriting the
timestamp with time.Now() on every successful probe meant that for any
sensor polling faster than certFreshness/IdleConnTimeout (10 min),
`time.Since(lastRead)` never exceeded the poll interval, `req.Close` was
never set, the pooled conn never recycled (a fast poller keeps it from
ever going idle), and a renewed or expired cert stayed stale for the
connection's whole lifetime — in practice, indefinitely. Recording only
on a real handshake makes the gate mean "the cert was last seen from a
handshake at most certFreshness ago," which is the property the display
and verifyHTTPCert both depend on. (2) The prune walked the entire
certReadTimes map under the global certReadMu on every HTTPS probe —
O(hosts) per probe, a scaling bottleneck as the fleet grows. Stale
entries carry no information (the only reader treats "stale" exactly
like "absent" — both force a fresh handshake), so window-granularity
pruning is loss-free and the map stays bounded by live sensor hosts.

**Pinned by:** TestCertReadTimesNotRefreshedOnKeepAliveReuse (probe 3
reuses the pooled conn — proven by the server seeing exactly 2 distinct
connections over 3 probes — and the certReadTimes entry is bit-for-bit
probe 2's timestamp, not advanced), TestCertFreshnessForcesHandshakeUnderContinuousPolling
(window shrunk to 150ms via the certFreshness seam: 4 distinct
connections must appear within a 5s budget of ~40ms polling; pre-fix
only 2 ever appear and the gate never fires), TestCertReadTimesPruneThrottledToWindow
(elapsed window → the write scans and prunes the stale ghost and
advances certReadLastPrune; fresh window → the write skips the scan and
the ghost survives). Sabotage-verified: forcing `reused = false`
(pre-fix write shape) → both behavioral pins fail (the polling pin burns
its full 5s budget); unthrottled per-write scan (pre-fix prune shape) →
the throttle pin fails.

## alert-state-hotpath-probe-handle-and-cache-warmth (alerts.go, probe.go, internal/store/store.go, alert_state_hotpath_test.go, alert_state_test.go, webhook_retry_test.go, nitround_pins_test.go, tsformat_test.go, 2026-11-19)

**Decision:** `setAlertState` takes a ctx and runs its guarded upsert on
the capped probe-write handle (`ProbeExecContext`, busy_timeout =
store.ProbeWriteTimeout = 8s) instead of the main pool (busy_timeout
15s), and stamps `alertMem` only when `RowsAffected() > 0`.
`maybeRealert` takes a ctx; on a cache miss a VALID `alertStateSelect`
read now stamps `alertMem` (so the miss happens at most once per sensor
per process), and only `sql.ErrNoRows` seeds `alert_state` — any other
db error returns without touching state. `certReadTimes`-style seams:
`store.NewStoreForTest(db, probeDB)` wraps already-opened handles
WITHOUT NewStore's pragmas (the FK-OFF no-resurrection test builds a
Store whose probe handle is the raw pragma-less connection, since
setAlertState now writes through the probe handle). All setAlertState /
maybeRealert call sites thread the loop ctx (probe.go doProbe ×2,
alerts.go ×4, test suites ×17).

**Why:** (1) setAlertState is on the probe hot path (doProbe state
transition + every sustained-error tick via maybeRealert); on the main
pool a stalled writer parked the sensor loop for 15s on top of the 8s
probe INSERT / 8s status-transition caps (up to ~31s of one tick under
contention). The capped handle is the codebase's established answer to
modernc's non-preemptable busy-handler. (2) Pre-fix, a cold alertMem
(fresh process) re-read alert_state from SQLite and, on the early-return
paths (alert-once-only, interval not elapsed) never wrote — so a
steady-state errored sensor queried SQLite on EVERY tick for the whole
re-alert interval. Stamping the in-memory copy on a valid read makes the
durable read happen once per sensor per process. (3) Treating ANY
db error like a missing row seeded alert_state with "now": a transient
BUSY/I/O blip reset the re-alert clock and suppressed an imminent
re-alert. Only a genuinely missing row has no state to preserve. (4)
Stamping alertMem on a RowsAffected=0 upsert (guard matched no sensor
row — concurrent delete) left a ghost in-memory entry for a deleted
sensor; the durable no-resurrection guard (review 2026-11-10 #3) now has
its memory-side counterpart.

**Pinned by:** TestSetAlertStateRoutesCappedProbeHandle (the main pool
is closed while the probe handle stays open: setAlertState still lands
the durable row and stamps memory — a main-pool write would fail),
TestSetAlertStateDeletedSensorNoMemGhost (no sensors row → no durable
row AND no alertMem entry; live-sensor positive control stamps),
TestMaybeRealertPopulatesAlertMemOnCacheMiss (cold cache + durable row
inside the interval: exactly 1 SELECT on the cold tick, the entry is
stamped, steady ticks do 0 SELECTs), TestMaybeRealertTransientDBErrorDoesNotSeed
(a BUSY-shaped error seeds no row and stamps no memory; a restored real
read with a genuinely missing row DOES seed). Sabotage-verified:
main-pool write → pin 1 fails; unconditional stamp → pin 2 fails; no
cache warming → pin 3 fails; any-error seeding → pin 4 fails.

## storm-summary-caps-maintenance-gate-and-moved-on-filter (alerts.go, storm_test.go, storm_summary_limits_test.go, 2026-11-19)

**Decision:** the storm-summary path now (1) is gated on
`pw.alertsEnabled()` in BOTH `flushStorm` (after the queue drain) and
`deliverStormSummary` (belt-and-braces at the post boundary: launchAlert
queues the job, it does not run inline, so maintenance can flip in the
gap), (2) drops every queued entry whose sensor no longer holds the
entry's state — `currentStatus(id) != e.state` — not just `== "up"`, and
(3) renders per provider under THAT provider's content cap
(`discordContentMax` 2000 / `telegramTextMax` 4096 / `googleChatMax`
4096, vars) via `truncateSummaryLines`: lines that no longer fit are
replaced by a "… and N more" footer, and the header keeps counting ALL
sensors. SMTP is uncapped (0). Caps are measured in runes of the FINAL
(rendered/escaped) body — what the provider counts.

**Why:** a rack/router outage is exactly the scenario storm coalescing
exists for, and pre-fix the summary was lost in that scenario by all
three defects at once: (1) ~20–25 downed sensors exceed Discord's
2,000-char content limit and ~45–50 exceed Telegram/Google Chat's 4,096;
over the limit the provider returns a non-retryable HTTP 400 and drops
the WHOLE message — the operator's only outage alert vanished silently
(delivery just logged "failed on all providers"). A capped, slightly
lossy body gets delivered; an uncapped body gets lost. (2) The
individual alerts that fill the queue are each gated at launch, but
maintenance can begin AFTER an entry is queued (the flush fires up to
stormWindow later), so the summary was the one alert class that could
fire during maintenance mode. (3) The `== "up"` filter kept sensors that
had PARTIALLY recovered (error -> warning): their partial-recovery card
was already delivered individually (stormAdmit exempts recoveries from
coalescing), so the operator got a card saying "X partially recovered"
and, behind it, a summary saying "X: up → error". The same
contradiction applies to a sensor that degraded further (entry
"warning", now "error": the newer error alerted individually, the older
warning line is stale). A vanished sensor (read error) is still kept —
the storm that took it down should name it.

**Pinned by:** TestStormSummaryCapsPerProvider (40-sensor body sized to
straddle the two caps: the Discord render is ≤2,000 runes with an exact
"… and N more" footer and a header that still counts 40; the Google
Chat render is the full list with no footer; the Telegram HTML render is
capped on the ESCAPED output; SMTP is uncapped), TestStormFlushSilencedInMaintenance
(queued rack-outage shape + maintenance on at flush time → zero
deliveries), TestStormSummarySilencedInMaintenance (maintenance on in
the flush→post gap → zero deliveries), TestStormFlushDropsMovedOnSensors
(partial recovery dropped, degrade-to-newer-error dropped, still-down
control kept), TestStormSummaryDropsMovedOnBeforePost (same contract at
the post boundary). Sabotage-verified: up-only filter → both moved-on
pins fail; caps ignored → caps pin fails; each maintenance gate proven
individually sufficient in a 2-gate matrix (flush on / deliver off →
flush pin passes and the direct pin fails; flush off / deliver on →
both pass; both off → flush pin fails).

## webhook-ssrf-dialer-flaws (webhook.go, webhook_ssrf_dial_test.go, 2026-11-19)

**Decision:** four SSRF/dialer fixes in the webhook path: (1)
`dialChecked` now returns an explicit `no IP address for host` error when
the resolver SUCCEEDS with an empty answer — the old shape returned
`(nil, nil)`, which panicked at the first conn dereference (smtp.go's
`conn.SetDeadline`, net/http inside the transport); `dialCheckedCleartext`
already carried this guard. (2) `validateWebhookURLNoDNS` strips trailing
dots (`strings.TrimRight(host, ".")`) BEFORE the .local/.localhost suffix
checks — the FQDN form ("printer.local.", "localhost.") is the same name
to DNS, so the dot was a pure save-time filter bypass of the only check
keeping mDNS names out of the http-relay path. (3) The save-time http
gate now requires ALL resolved answers to be private — the same rule
`dialCheckedCleartext` enforces at dial time. The old any-private gate
accepted mixed-A-record hosts at save that then failed EVERY delivery
("resolved to a public address"): save-time and dial-time gates must
agree. (4) `embeddedIPv4`'s ff ff 00 00 layout now ALSO requires the
first 8 bytes to be zero — that is what the `::` in `::ffff:0:a.b.c.d`
expands to. A genuine ULA/GUA with `ffff:0000` in bytes 8-11 and a
non-zero prefix (e.g. `fd12:3456::ffff:0:a9fe:1`) is a legitimate IPv6
destination; pre-fix its trailing 32 bits were judged as IPv4, so a
trailing quad in a blocked IPv4 range (169.254/16, 0/8, …) produced a
false "blocked address" on a perfectly good literal. Both embedded
layouts keep working, and the blocked-trailing-quad detections
(`::ffff:0:169.254.0.1`, `::169.254.0.1`, `::ffff:0:127.0.0.1`) are
unchanged.

**Why:** (1) is a crash on a poisoned/empty resolver answer — the
dialer contract is "conn OR error", never a bare nil conn. (2)+(3) are
save-vs-send inconsistencies: (2) lets a name the save-time check
deliberately rejects reach delivery (where the blocklist on the
mDNS-resolved private answer lets it THROUGH — the suffix check is the
only gate for that class), and (3) lets a URL save that can never
deliver, which looks like a pulsemon bug to the operator. (4) is a
false positive on legitimate IPv6 literals — the zero prefix is part of
what makes the layout an embedded form, not just the ff ff 00 00 bytes.

**Pinned by:** TestDialCheckedEmptyResolverResult (empty-but-successful
resolver answer → explicit no-IP error, nil conn),
TestValidateWebhookURLTrailingDot (dotted .local/.localhost rejected in
both schemes, multiple dots, undotted controls, and positive controls
for ".local" inside a name), TestValidateWebhookURLCleartextAllPrivate
(mixed A records over http rejected at save; all-private http accepted;
same mixed name over https accepted), TestEmbeddedIPv4ZeroPrefixRequired
(both embedded layouts still recognized; ULA/GUA with ffff:0000 in
bytes 8-11 + non-zero prefix → no embedded view and no false block;
blocked trailing quads in the real embedded forms still blocked).
Sabotage-verified: each of the four fixes individually reverted → its
pin fails; tree MD5-verified restored.

## self-updater-flaws (update.go, update_linux.go, update_windows.go, update_check.go, selfupdater_test.go, 2026-11-19)

**Decision:** three self-updater fixes: (1) The .prev backup in
`installBinary` moved into a platform function `backupBinary`: Linux
HARDLINKS (dst never disappears, so a power loss between backup and swap
cannot boot an install with NO binary; rename fallback for filesystems
without hardlink support), Windows RENAMES the running .exe aside (NTFS
permits hardlinking a RUNNING exe — the old shared code path's
os.Link(dst, prev) SUCCEEDED, leaving dst mapped, and swapBinary's
rename of the new binary OVER the locked dst then failed with
ERROR_ACCESS_DENIED, killing every Windows live update; renaming the
running exe aside is the one move Windows allows on a locked .exe).
(2) The /api/update-check failure backoff now measures its suppression
window from `updateCheckAttemptAt` (set at flight start — advances on
failures) instead of `updateCheckAt` (the last SUCCESS): after the
30-minute cache expires, the success age is always ≥ TTL, so the old
`time.Since(updateCheckAt) < updateCheckFailTTL` test was dead code and
every 5s dashboard poll re-fetched during an outage, walking into
GitHub's 60 req/hour limit. The suppression is now an early check that
serves the stale result — or a 503 when there is no cache — and
cold-cache failures set `updateCheckFailed = true` too, so an outage
from first boot cannot hammer api.github.com either. (3)
`pulsemon sign verify <file> <tag> <asset>` (4-arg manifest mode) no
longer falls through to the legacy raw-bytes check when the manifest
check fails (`if !verified` → `else`): a legacy raw-bytes .sig is
uninstallable by the manifest client and unbound to the tag/asset, so
the fall-through let an unbindable or tag-replayed signature pass
release CI. 2-arg legacy mode is unchanged (raw-bytes is the only form
for pre-manifest releases).

**Why:** (1) is a hard break of Windows self-update — the NTFS
hardlink-on-running-exe behavior makes the shared code path
fundamentally wrong for that platform, and the swapBinary doc comment
already described the rename-aside scheme the code was no longer doing.
(2) is quota exhaustion on the worst possible schedule (a real outage):
the backoff existed but could never fire in the shape that matters,
and the cold-cache hole made first-boot outages worse. (3) weakens the
release-pipeline authenticity gate: the whole point of the manifest
form is the tag/asset binding, and a silent fall-through to the
unbound form defeats it.

**Pinned by:** TestBackupBinaryLinuxHardlinks (both names exist after
backup, same inode — a rename scheme would leave dst missing),
TestUpdateCheckColdCacheFailureBackoff (cold 503s suppress the next
poll with NO upstream hit), TestUpdateCheckFailureBackoffAfterStaleCache
(dead-code killer: the failed attempt happens after the cached success
aged past the failure window — the next poll must NOT re-fetch),
TestSignVerifyManifestModeRejectsLegacySig (raw-bytes .sig fails 4-arg
verify), TestSignVerifyManifestModeAcceptsManifestSig (happy path),
TestSignVerifyTagReplayRejected (v0.4.4-bound sig fails v0.4.5 verify),
TestSignVerifyLegacyModeAcceptsRawSig (2-arg mode unchanged).
Sabotage-verified: each of the four fix vectors individually reverted →
its pin fails; tree MD5-verified restored. Windows side compile-checked
via GOOS=windows cross-build.

## tls-upload-delete-race-and-data-dir-hardening (tls_settings.go, main.go, main_linux.go, main_windows.go, tls_race_test.go, 2026-11-19)

**Decision:** (1) A package-level `tlsSettingsMu` now serializes the
disk/DB/restart critical section of both /api/settings/tls handlers —
the POST install (temp writes, pair re-validation, the two renames,
port persistence, restart scheduling) and the DELETE (source check +
removals + restart scheduling). Validation stays OUTSIDE the lock (pure
in-memory work); the lock is held only for state mutation. Two test
seams ride along: `tlsRemoveTemp` (the failure-path remover, recorded
by tests) and `tlsInstallBetweenRenames` (a no-op hook between the key
and cert renames so a test can pause the install mid-window). (2) The
install-failure cleanups now Close the temp files BEFORE removing them
(previously the deferred Close ran after the `os.Remove` return). (3)
`runAuthUser` calls a new platform helper `hardenDataPath(dbPath)`
before opening the store: on Linux that is `syscall.Umask(0o077)` +
`hardenDataDirFiles` (the same contract as `ensureDataDir`, minus
directory creation — the store only opens files in an existing data
dir), on Windows it is a documented no-op (no umask; the data dir ACL
is the installer's). (4) Windows `ensureDataDir` now operates on
`dbPathFromEnv()` (PULSEMON_DB-aware — the old code hardcoded
`defaultDBPath()`), refuses relative paths (the old comment claimed the
path "is always absolute", which only covered the default), and returns
the `os.MkdirAll` error instead of swallowing it.

**Why:** (1) Concurrent admin clicks (POST/DELETE) interleaved a
DELETE's `os.Remove` with a POST's `os.Rename`, leaving a mismatched
certA+keyB pair — or a half-installed single file — on disk, which is a
certFatal at the next boot, and each concurrent request also scheduled
its own restart. (2) On Windows, `os.Remove` on a still-open file is a
sharing violation: the removal silently fails and the `.key.pem.tmp*`
residue — PRIVATE KEY material — is left on disk. (3) `auth-user add`
before first boot (or while the service is stopped) ran before
`ensureDataDir`, so the store was created under the process's default
umask: 0644 world-readable pulsemon.db/-wal/-shm holding bcrypt hashes
and webhook/SMTP secrets on multi-user Linux hosts. (4) A
PULSEMON_DB override on Windows was never honored by the dir bootstrap
(the DB's parent was never created), a relative PULSEMON_DB would have
planted the secret-holding database in the process CWD, and a
non-creatable data dir failed later with an opaque store error instead
of a loud startup one.

**Pinned by:** TestTLSConcurrentInstallAndRemoveStayConsistent
(deterministic barrier round: the install is paused between the key and
cert renames via tlsInstallBetweenRenames while a DELETE runs in the
window — unlocked code leaves exactly one of cert.pem/key.pem behind;
locked code's DELETE blocks on the mutex and removes the complete pair
— plus 15 randomized PUT/DELETE race rounds asserting the on-disk pair
always loads via tls.X509KeyPair),
TestTLSInstallFailureClosesTempBeforeRemove (injected read-only temp
files make the install's Write fail; the recorded remover proves each
temp file is CLOSED before it is removed — on an open file, Windows
leaves the residue — and no .tmp files survive),
TestAuthUserHardensDataDirBeforeFirstBoot (Linux: with a 0o022
interactive umask, `pulsemon auth-user add` on a fresh PULSEMON_DB must
leave pulsemon.db at 0600, not 0644). The umask now set by the
auth-user CLI path is process-global, which exposed a latent
umask-dependency in two pre-existing mode-exact fixtures
(TestInstallBinaryPreservesModeAndNeverLosesDst,
TestFix_M4_InstallKeepsPrev: `os.WriteFile(dst, …, 0750/0755)` is
umask-filtered, so under a leaked 077 the fixture was 0700 and the
preservation assertion misfired) — both fixtures now Chmod to pin the
exact mode. Sabotage-verified: each of the three fix vectors
individually reverted → its pin fails; tree MD5-verified restored.
Windows side compile-checked via GOOS=windows cross-build
(ensureDataDir/hardenDataPath cannot be test-run on the Linux gate
box).

## frontend-ops-auth-ui-fixes (web/index.html, web/app.js, web/test/frontend.test.mjs, 2026-11-19)

**Decision:** Four frontend rules now in force (external review 2026-11-19 F16):

- `#f-tls-port` ships with NO hardcoded `value=` in index.html, and
  `renderTLSStatus()` seeds it UNCONDITIONALLY (`port.value = t.port || 443`)
  on every settings fetch. The old `if (port.value === '')` guard was dead
  code behind the HTML `value="443"` default, so the box always read "443"
  no matter what port the server had stored.
- `saveAlerts()` now sends EVERY configured provider in `body.providers` —
  a blank URL box is omitted from the payload (the server's nil-url "keep
  stored" semantic, api.go `applyProviderUpdateInTx` `if url != nil`), while
  a typed value replaces it. The old `.filter(p => input.value.trim() !==
  '')` dropped any provider whose box was blank — which is exactly how
  `renderProviderList()` renders a MASKED bot token (`urlVal = masked ? ''
  : p.url`) — silently discarding the provider's extra-field edits.
- SMTP `username`/`password` are read with new `valRaw()` (no `.trim()`):
  the server stores credentials RAW because a leading/trailing space is
  part of the SMTP AUTH value. `val()` keeps trimming every other field.
- `doLogin()` now `await refreshAdminState(); refresh();` after
  `startPolling()`: that call is idempotent and no-ops on a re-login in the
  same tab, so its state refreshes never ran again and `meIsAdmin` stayed
  stale across role switches. `renderUpdateUI()` gates the header pill on
  `meIsAdmin` too — it opens the Settings modal, which the server 403s for
  non-admin sessions (settings READ is gated), and the 10-minute update
  poll used to re-show the pill to viewers.

**Why:** Cert renewal on a custom port (e.g. 8443) silently re-saved 443
(EACCES on non-root Linux); Telegram chat_id edits were lost on every save
that didn't re-paste the masked bot token (and SMTP credential edits were
trimmed before they reached the wire); after a same-tab role switch the
admin surface stayed visible to a viewer — or hidden from a fresh admin —
until a manual reload, and viewers saw an update pill that opens a modal
their session can't read.

**Pinned by:** `web/test/frontend.test.mjs` (Node `node --test`, loads the
REAL app.js into a vm sandbox with a DOM shim; no Go involved):
- `TLS port box: index.html ships no hardcoded 443 default` — static HTML
  pin (the id must exist, the `value="443"` attribute must not).
- `TLS port box: renderTLSStatus seeds it from the server port (custom
  port survives)` — stale "443" in the box + `t.port 8443` → box ends
  "8443".
- `TLS port box: falls back to 443 when the server reports no port` —
  positive control (the `removeTLSCert()` render shape).
- `saveAlerts: masked-URL providers stay in the save and keep their extra
  edits` — blank (masked) telegram URL box + edited chat_id → provider
  present, `chat_id` preserved, `url` key ABSENT; SMTP username/password
  with edge spaces arrive untrimmed; a typed (discord) url is still sent.
- `doLogin: re-login in the same tab re-resolves admin state (role
  switch)` — admin→viewer→admin logins in one tab; `meIsAdmin` must
  follow the session each time (boot arms the pollers first, so every
  login is the re-login path).
- `renderUpdateUI: the update pill is gated on meIsAdmin` — pill hidden
  for a viewer, shown for an admin with an available update, hidden for
  everyone when up-to-date (positive control).
Sabotage-verified: each of the four fix vectors individually reverted →
its pin fails (port vector fails 3 pins, the others 1 each); tree
MD5-verified restored.

## patch-scan-error-404-vs-500 (api.go, patch_sensor_scan_error_test.go, 2026-11-19)

**Decision:** The in-tx sensor read in `PATCH /api/sensors/{id}` now
classifies scan errors explicitly: `errors.Is(err, sql.ErrNoRows)` →
`errPatchSensorGone` (404); every other error (SQLITE_BUSY, canceled
context, I/O) is returned raw and reaches `respondInternal` — the only
logged-500 path. The read itself gained a `patchScanHook` test seam (nil
in production) that transforms the scan error before classification, so a
non-NoRows failure is exercisable without a real DB fault. The separate
`RowsAffected()==0 → errPatchSensorGone` check on the UPDATE is unchanged
(it is a genuine gone-detection, not an error collapse).

**Why:** Before the fix, ANY scan error returned `errPatchSensorGone`, so
a transient SQLITE_BUSY, a canceled request context, or a disk I/O failure
was reported to the client as 404 "sensor not found" and never reached the
service log — the operator saw a phantom missing sensor and no error to
diagnose.

**Pinned by:** `TestPatchSensorScanErrorIs500Not404` (4 subtests):
- `missing row is still 404 (positive control)` — the genuine gone path.
- `clean patch is still 200 (positive control)` — the healthy path.
- `injected non-NoRows scan failure is 500, not 404` — `patchScanHook`
  substitutes a SQLITE_BUSY-style error on an EXISTING sensor; asserts 500
  (not 404) and the generic "internal error" body (raw DB text must not
  leak to the client). The run's service log shows the injected error
  landed in `respondInternal`'s log line.
- `injected ErrNoRows stays 404` — the classification branch itself.
Sabotage-verified: the classification reverted to the old
`return errPatchSensorGone` shape (seam kept) → the 500 pin fails; tree
MD5-verified restored.

## respawn-stagger-hash-not-clamp (probe.go, respawn_stagger_spread_test.go, resume_firsttick_test.go, 2026-11-19)

**Decision:** `firstTickPhase` no longer CLAMPS a respawned sensor's
first-tick phase to `respawnFirstTickCap` — it HASHES it into the cap
window: `resumed && interval > cap` → `staggerPhase(id, cap)`, which is
uniform over [250ms, cap+250ms) and deterministic per id. First spawns
keep the full staggered phase (untouched), and a sub-cap interval is
never re-hashed (its already-small stagger stands).

**Why:** The clamp `if phase > cap { phase = cap }` landed every resumed
sensor whose staggered phase exceeded 1s (~98% of 60s sensors) on the
EXACT same 1.000s instant, so a bulk maintenance-resume of hundreds of
sensors was one synchronized write burst against probeDB
(MaxOpenConns(1)) — the constant's own "lands across ~1s" comment was
false. The hash preserves the same upper bound (resume delay ≤ cap+250ms)
while spreading the burst across the window.

**Pinned by:** `TestFirstTickPhaseRespawnSpread` — 200 resumed 60s
sensors must produce ≥100 distinct first-tick phases, all within
[250ms, cap+250ms) (pre-fix: 6 distinct, one of them a 195-sensor herd at
exactly 1.000s), plus per-id determinism.
`TestFirstTickPhaseFirstSpawnUnchanged` — positive controls: first
spawns keep the full stagger; sub-cap intervals are not re-hashed.
`TestFirstSpawnKeepsFullStagger`'s exact-cap assertion (which pinned the
old clamp) was updated to the window contract.
Sabotage-verified: the clamp body restored → the spread pin fails
("collapsed to 6 distinct phases"); tree MD5-verified restored.

## stats-24h-counters-decay-to-now (stats.go, stats_decay_test.go, 2026-11-19)

**Decision:** `statsFor` decays the incremental 24h counters to the read's
`nowUnix` before calling `computeSensorStats`: local copies of
total24/lost24, subtracting the leading live minute buckets
(`minute < nowUnix-retentionSeconds`) and the leading live raw entries
(`ts < nowUnix-retentionSeconds`, manual rows skipped) from
`raw24Start`. The series fields are untouched — the decay is read-only
under RLock; the next `append` re-anchors the real counters.

**Why:** The counters are maintained in `append()` anchored at the
NEWEST probe's ts, so a sensor whose last probe is old (paused >24h,
hourly cadence between ticks, just warmed from the DB) carried a count of
[newest-24h, newest] into a read anchored at now — violating
`computeSensorStats`' documented "ts >= nowUnix-86400" contract and
disagreeing with `graphPoints("24h")`, which is anchored at
`time.Now()`. A sensor paused 30h reported the 24h uptime from 30h ago.
Steady state (nowUnix ≈ newest) leaves an empty decay band — zero
iterations per poll — so the cost is bounded by the sensor's age gap.

**Pinned by:** `TestStatsForDecays24hUptimeToNow` — a full 24h 5s sensor
(17,280 entries, oldest 6h all losses, 75.0% at the newest anchor) must
read 75.0% steady, 100.0% when now is 20h later (oldest 4h left the
window), and 0 when now is 30h later (every probe is >24h old — matching
an empty 24h graph); pre-fix all three reads returned 75.0%. Its final
check pins the read-only contract (a decayed future read must not mutate
the series — an in-place variant would also race appends under RLock).
`TestStatsForDecaysSlowSensorDrift` — an hourly sensor read 30m after its
newest probe drops the age-24h loss entry: 96.0% → 100.0%.
`TestStatsForDecaySkipsManualRows` — 54 manual rows in the decay band
must be skipped (they were never counted): 90.0%, not 88.24%.
Sabotage-verified: the pre-fix passthrough restored → all three pins
fail.

## throttle-edge-cases (auth.go, auth_test.go, auth_throttle_edge_test.go, stats_decay_test.go, 2026-11-19)

**Decision:** Four auth throttle / bootstrap edge cases fixed (review
finding #20):

- **(a) Bootstrap known-good keying.** A successful bootstrap now records
  the operator's known-good exemption under the BARE `throttleKey(ip)`
  bucket — the same key `checkUserLock` looks up — instead of the
  `"setup|"+ip` admission bucket, whose suffixed knownGood entry could
  never match. The dedicated `"setup|ip"` bucket is closed out by an
  explicit `clearIPThrottle` on bootstrap success (loginSuccess's own
  fails/lockout clear lands on the bare key it was passed).
- **(b) Per-map hard-cap wipe.** The `beginAttempt` emergency wipe no
  longer resets all six maps when any one exceeds `throttleHardCap`.
  Each layer now fails open on its own cap: `len(fails) > cap` wipes
  fails+lockout; `len(userFails) > cap` wipes userFails+userLock;
  `len(knownGood) > cap` wipes knownGood. `userHour` is never wiped
  (account-bounded like the rest of the per-username layer). The old
  all-or-nothing wipe let a per-IP spray (the most common wide attack)
  clear an ACTIVE 30/hr account lockout and its hourly budget
  mid-attack.
- **(c) Sentinel-precise setup refund.** The setup path refunds the
  `"setup|ip"` admission only for rejections that paid NO bcrypt KDF
  cost (`setupNoKDF`: the validation sentinels, the early bootstrap
  pre-check, and a client that left while queued on the bcrypt
  semaphore — `context.Canceled`/`DeadlineExceeded`). An in-tx
  bootstrap race loss (`errBootstrapped`) DID pay the KDF (bcrypt runs
  to completion and ignores ctx) and is deliberately NOT refunded, even
  when the request's ctx is already canceled: refunding the paid case
  would hand a scripted attacker an unbounded per-IP guessing channel
  (abort mid-KDF → budget refunded → re-spray).
- **(d) Per-user throttle purge on account removal.** `RemoveUser` now
  calls `purgeUserThrottle` (drops userFails/userLock/userHour entries
  and the `username\x00`-prefixed knownGood exemptions), and `Disable`
  calls `purgeAllUserThrottle` (all four per-username maps reset).
  Without the purge a RE-CREATED username inherits the old account's IP
  exemptions and failure debt.

`stats_decay_test.go` carries a one-line gofmt 1.27.4 comment-alignment
fix (pre-existing from the stats commit).

**Why:** (a) the operator's only per-username exemption was dead on
arrival — a spray landing in the gap between bootstrap and first login
would lock them out of their own new account; (b) the hard cap exists to
bound memory under a wide spray, and an IP spray is the common wide
spray, so its cap reset must not also disarm the account layer it has no
claim over; (c) the refund contract is "throttling is for KDF cost", and
the old `r.Context().Err() != nil` check refunded a disconnect that had
already paid the cost; (d) throttle state is in-memory and keyed by
name — it does not die with the account row.

**Pinned by:** `TestBootstrapSuccessExemptsBareIP` — a fresh install
whose account is spray-locked mid-bootstrap must record the exemption
under the bare-IP key (and not the `"setup|"` key), and a login from
that IP during the account lockout must succeed via the exemption.
`TestLoginThrottleHardCapWipePreservesUserMaps` (rewritten from the
all-or-nothing pin) — a per-IP overflow wipes the per-IP layer only; an
active account lockout, its hourly budget, and a known-good exemption
must survive. `TestLoginThrottleUserFailsHardCapWipe` and
`TestLoginThrottleKnownGoodHardCapWipe` (rewritten) — a per-username or
knownGood overflow wipes its own layer only; the per-IP layer survives
with both entries intact. `TestSetupNoKDFRefundPredicate` — the
refund set is exactly {ctx cancel/deadline, pre-check, validation
sentinels}; `errBootstrapped`, `errUserExists`, and db errors are
excluded. `TestSetupCtxCancelBeforeKDFRefunds` — a client that leaves
while queued on the semaphore (KDF never ran) still refunds the setup
bucket. `TestRemoveUserPurgesThrottle` — a removed user's userFails /
userLock / userHour / knownGood entries are all gone and another
user's knownGood survives. `TestDisablePurgesAllUserThrottle` —
Disable leaves zero per-username entries. Sabotage-verified: (a)
reverted to the `"setup|"` key → `TestBootstrapSuccessExemptsBareIP`
fails on the missing bare-IP entry; (b) reverted to the all-or-nothing
wipe → `TestLoginThrottleHardCapWipePreservesUserMaps` fails with
"an IP-spray hard-cap wipe cleared userFails".

## updater-buffering-redaction-decode (update.go, update_api.go, update_sig_test.go, update_manifest_test.go, update_edge_test.go, 2026-11-19)

**Decision:** Three updater fixes: (a) `verifyDownloadedAsset` streams
the digest ONCE via `fileSHA256` (32 KiB buffer) and passes it to
`verifyReleaseSignature` — the up-to-512 MiB asset is no longer read
into RAM, and the binary is no longer hashed twice in memory; (b)
fetch failures of the `.sig`/`.sha256` assets are marked with the
`errReleaseFetch` sentinel and redacted to a generic 502 at the API
layer (the error text embeds upstream asset URLs / DNS / proxy detail),
while verification VERDICTS (bad/missing signature, SHA mismatch,
missing sidecar asset) stay surfaced verbatim — operator-actionable
with no upstream detail; the CLI path shows the full error either way;
(c) `handleUpdate` decodes the request body UNCONDITIONALLY (4 KiB
cap; only `io.EOF` means "no fields"), so a chunked body
(ContentLength -1) is no longer silently dropped and malformed JSON is
a 400 BEFORE `allow_downgrade` is consulted — a truncated body can no
longer partially apply the downgrade opt-in.

**Why:** (a) a low-RAM SBC must not page the entire binary in just to
hash it, and the two in-memory `sha256.Sum256` passes were pure waste;
(b) the old 502 comment claimed "carries no upstream detail", but the
fetch-failure paths embedded `HTTP %d for <url>` and raw `client.Do`
transport errors in the body; (c) `if r.ContentLength > 0` skipped
chunked bodies entirely (a pinned chunked request was treated as
"latest"), and `json.Decoder` applies fields as it parses, so a
truncated `{"allow_downgrade":true,...}` left the flag set even when
the decode error was silently discarded.

**Pinned by:** `TestVerifyDownloadedAsset_StreamsSinglePassDigest` —
the streamed digest equals the in-memory reference on a multi-chunk
payload. `TestUpdateAPIVerifyFetchFailureRedacted` — a `.sig` served
by a dead upstream (error text carries 127.0.0.1:PORT) yields a
generic 502 with no address in the body and nothing installed.
`TestUpdateAPIVerifyVerdictStillSurfaced` — the SHA-mismatch verdict
stays verbatim in the 502 body. `TestUpdateAPIChunkedBodyHonored` — a
chunked (ContentLength -1) version pin reaches the tags fetch (502)
instead of the "latest" shortcut (200).
`TestUpdateAPIMalformedBodyRejectedBeforeFlags` — a truncated body
carrying `allow_downgrade:true` is a 400 with no install/restart.
Sabotage-verified: removing the `errors.Is(err, errReleaseFetch)`
branch → `TestUpdateAPIVerifyFetchFailureRedacted` fails with the
dead upstream's 127.0.0.1:PORT in the 502 body; restoring the
`ContentLength > 0` gate → `TestUpdateAPIChunkedBodyHonored` fails
with 200 up-to-date (the chunked pin was dropped).

## db-ctx-torn-reads-resources

Finding #22 (2026-11-19/20 local). Five fixes:
- `applyMaintenanceTx` now takes ctx and runs every step via
  `ExecContext` — a dead request context aborts a maintenance
  transition instead of parking it on the write lock.
- `settingsPayload` reads ONE `GetAllSettings` row-set instead of six
  separate `GetSettingErr` queries (each on its own pool connection):
  a concurrent PUT /api/settings can no longer interleave the reads
  and mix pre-/post-update values in one payload; one round trip.
- DELETE /api/tags: the pre-SELECT sensor_id → DeleteTag pair was a
  TOCTOU window (a sensor gaining/losing the tag in between staled the
  probe-loop respawn list). It is now one `DELETE ... RETURNING
  sensor_id` via `DeleteTagReturning` — the respawn list is exactly the
  rows removed, by construction.
- `NewStore` closes `db` when the `SELECT 1` probe fails (the pool was
  real; the failure path leaked the handle).
- `InitSchema` fails loudly when `user_version > schemaVersionHead` —
  a DB stamped by a NEWER binary is no longer silently accepted by an
  older build whose migration list cannot read its schema.

Pins: `internal/store/ctx_resources_test.go` (ctx-aware maintenance
transition, DeleteTagReturning exact-row contract, newer-version
refusal, probe-failure error path) and `settings_snapshot_test.go`
(payload values from the single row-set). (d)'s `db.Close()` has no
observable state on `*sql.DB`, so it is verified by inspection; the
probe-failure test pins the error path itself.

## platform-transport-script-edge-cases

Finding #23 (2026-11-19/20 local). Seven fixes across platform, transport,
and install-script edge cases:
- `ping_windows.go` closed its Winsock socket with `windows.Close(fd)` (a
  handle/pipe-end close) instead of `windows.Closesocket(fd)`. Both the
  Bind-error path and `winDgram.close()` now call `Closesocket`.
- `readerRestartDelay` (ping.go, ping_linux.go, ping_windows.go) and
  `recoveryRetryDelay` (alerts.go) were read INSIDE the spawned goroutine
  (`time.After(<var>)` in the `go func()` body), violating the repo's -race
  capture rule: tests swap the package var and restore it, but the goroutine
  outlives the restore, so the read raced the write. Each site now captures
  `delay := <var>` before `go func()`.
- `smtp.go` ran the STARTTLS probe in `case "auto"` even when the conn was
  already implicit-TLS (auto+465), and had no fail-closed default for an
  unknown `tls_mode` (it fell through to plaintext). `wantsStartTLS()` is
  now the switch's predicate (auto+465 → false, so no nested STARTTLS on the
  already-encrypted wire), and an unknown mode returns
  `smtp: unknown tls_mode` before any plaintext send.
- `hostAllowed` used `net.SplitHostPort` on the allowlist entry, which
  rejects a bracketed no-port value — so `PULSEMON_ALLOWED_HOSTS=[::1]`
  never matched `Host: [::1]:9299` (only the bare `::1` form worked).
  `splitHostPortLenient()` now strips brackets, so both forms match.
- `authGate`'s Origin check compared only the host, so an `http://` page on
  the same host passed against the (https) dashboard. It now also compares
  the Origin scheme against `requestScheme(r)` (https over direct TLS or a
  trusted proxy reporting `X-Forwarded-Proto: https` — the same rule as
  cookieSecure), so a same-host scheme mismatch is refused.
- `runRestartCommand` ran the BLOCKING `restartSystemdService()` before
  checking `isSystemdManaged()`, so a systemd-managed process called
  systemctl on itself (a self-restart that hangs on its stop phase). It now
  checks `isSystemdManaged()` first and takes the detached-helper branch
  (helper spawn failure is reported, not fallen through). The TLS settings
  response reported `"restarting": true` even on Windows (where
  `requestRestart()` never restarts); it now reports `autoRestarts()`
  (win=false, linux=true). The Windows SCM `WaitHint` was 10000ms — shorter
  than the 30s shutdown drain — and is now 40000ms.
- `install.sh` created `API_JSON` (mktemp) BEFORE the EXIT trap existed (a
  grep/sed failure under set -e leaked the temp file), did not validate
  `$VERSION` before interpolating it into download URLs, and omitted
  `--proto '=https' --tlsv1.2` on the GitHub curls. TMP+trap now come first
  with API_JSON under TMP, `$VERSION` is validated as `vX.Y.Z[-pre]` before
  URL use, and the four hardcoded GitHub curls pin https/TLS1.2+. The
  `Dockerfile` copied the CA bundle from EOL `alpine:3.20`; it now copies it
  from the builder stage (golang:1.27.4-alpine).

Pins: `smtp_tls_mode_test.go` (wantsStartTLS matrix incl. auto+465→false,
unknown-mode fail-closed e2e, auto-plaintext positive control),
`host_allowed_test.go` (bracketed-IPv6 match + splitHostPortLenient
contract), `restart_command_test.go` (systemd-managed takes the helper
branch, external caller blocks, helper failure reports; autoRestarts
linux=true), and `csrf_test.go` (TestOriginGateSchemeMismatchRefused + the
proxy-preserved-host test now exercises a trusted proxy + X-Forwarded-Proto).
install.sh / Dockerfile are pinned by `bash -n`, the release-sig-harness
extraction (confirmed unaffected), and the VERSION regex (valid tags
accepted; path-traversal / spaces / no-v refused) on the gate box.
Sabotage-verified: reverting the hostAllowed reqHost capture →
TestHostAllowedBracketedIPv6 fails; reverting the auto+465 guard →
TestWantsStartTLSMatrix fails. GOOS windows cross-build clean
(`GOOS=windows go build .`).

## frontend-poll-layout-thrash

Finding #24 (2026-11-19/20 local). Three frontend (web/app.js) fixes:
- Double-poll of the inspector: two 5s `setInterval` callbacks both drove
  `loadInspector()` — the refresh interval (`refresh()` → `pollRender()` →
  `loadInspector()`) AND a separate interval that called `loadInspector()`
  directly. With an inspector open that was 2x the inspector requests every
  5s. The redundant direct interval is removed; the 5s refresh is the single
  source (pollRender already loads the inspector when one is open).
- `refresh()` had no in-flight guard: a slow first refresh (its 3 api() calls
  still pending) let the next 5s tick start a second concurrent refresh — 6
  requests in flight, and the later one's sensors/events could land over the
  earlier (interleaved data). `refresh()` now sets `refreshInFlight` at entry
  and clears it in `finally`; a call while in flight returns immediately.
- `layoutSparklines()` interleaved layout reads (`getComputedStyle(c)` +
  `c.clientWidth`) with style writes (`b.style.width`) INSIDE the per-card
  loop, so each card's read forced a synchronous reflow of the previous
  card's writes — N full layouts per render with 100+ sensors (visible jank).
  It is now a read pass (gather every container's snapped bar width up front)
  followed by a write pass (apply all heights + widths), collapsing the N
  per-card reflows to one. The device-pixel FLOOR math and the CSP-safe
  `data-h` height mechanism are unchanged.

Pins: `web/test/poll_layout.test.mjs` (Node vm harness loading the REAL
app.js): `polling: one 5s tick drives exactly one loadInspector call` (fires
every armed 5s callback and counts loadInspector invocations — 2 with the
duplicate interval, 1 after), `refresh: a second call while the first is in
flight is dropped` (a gated fetch counts api() calls — 6 without the guard, 3
with, plus a positive control that the guard clears after settle), and
`layoutSparklines: every layout read precedes every style write`
(instrumented getComputedStyle/clientWidth/style track read/write order — the
interleaved old shape writes before a later read, the split shape does not).
Gated on the box (Node 22): poll_layout 3/3 and the F16 regression
(frontend.test.mjs) 6/6 (no breakage). Sabotage-verified: each of the three
fixes individually reverted → its pin fails; tree MD5-verified restored.

## testing-benchmark-gaps

Finding #25 (2026-11-19/20 local). Closed the testing/benchmark gaps the
review flagged — the paths where every Major/Critical fix above slipped
through. Each listed gap was verified against live code FIRST; three turned
out to be already covered and were dropped as duplicates rather than re-added:
- `SetUserPassword` common-password rejection → already `TestSetUserPasswordRejectsCommonPassword`
  (auth_hourly_budget_test.go): tests "password" AND "password123", asserts
  `errPasswordCommon`, verifies nothing changed.
- concurrent `EnterMaintenanceWithFreshSnapshot` → already
  `TestConcurrentEnterMaintenancePreservesSnapshot` (maintenance_test.go), a
  stronger double-click race driven through the HTTP handler with a
  parked-enter seam.
- gzip 204/ResponseController/MaxBytesReader, storm summary limits, SMTP
  TLS/STARTTLS mode matrix, SharedEngine concurrent init → already covered by
  the existing suites (gzip_test.go, storm_summary_limits_test.go,
  smtp_tls_mode_test.go, healthz_icmp_test.go).

Genuinely missing, now added (all gated on the box, `-race`; no production
code changed — test-only finding):
- `BenchmarkPurgeOld` guarded `b.N = 1` (a fixed-shape 1.5M-row 30-day delete
  can't loop on b.N without re-seeding; the guard makes it a clean single-shot
  instead of meaningless at the default ~100 reps). ~1.41s/op on the box.
- `BenchmarkWarmStats` — the heaviest DB read path (two-phase 24h load:
  covering-index scan for all sensors + slow-sensor LIMIT 60 backfill). Seeded
  100 sensors × 5000 probes (~500K rows, all in-window) via `NewProbeWorker`
  (the series cache must be initialized — a bare `&ProbeWorker{}` nil-maps).
  ~742ms/op on the box.
- `TestEngineModeDeadBeforeSharedEngine` (engine_mode_dead_test.go):
  EngineMode()/EngineDead() are safe to read BEFORE the shared engine inits
  (a /api/healthz poll can land first) and flip to "dead" once the one-shot
  open fails — both take only the read lock, never the init.
- `TestInitSchemaMigration11RetryWithoutReset`
  (internal/store/schema_migration11_retry_test.go): a retry of the migration
  sequence at the 11 boundary restores the head WITHOUT resetting
  user_version to 0 (the pre-versioning escape hatch is not the normal
  recovery path).
- `TestSendSMTPCredentialsPlaintextRefused` (smtp_auth_flow_test.go): a relay
  advertising NO STARTTLS + NO AUTH — credentials over a plaintext wire are
  refused. The guard fires AFTER the dial + EHLO, so a live in-process relay
  + a plain `smtpDial` override are needed (the production dial blocks
  loopback by design).
- `TestUpdateCheckTTLExceedsFailTTLOutageBackoff`
  (update_check_realistic_ttl_test.go): the REALISTIC production ordering
  updateCheckTTL (30m) > updateCheckFailTTL (1m). The existing
  TestUpdateCheckStaleOnFailure uses the INVERSE (1ms/1h) to stay fast, which
  hides the interaction: an expired success must probe (not be suppressed by
  its own age), and the resulting failure is backoff'd by the SHORTER FailTTL
  measured from the ATTEMPT time, not the success time.
- `TestGzipHeadResponse` (gzip_test.go): a HEAD request through the gzip
  wrapper COMPLETES (a body-less response must not leave the gzip writer
  blocked) — the other bodyless verb alongside the 204/304 already pinned.
- `TestVerifyReleaseSignatureRejectsLegacyRawSig` (update_sig_test.go): a
  LEGACY raw ed25519 signature over the binary bytes (pre-manifest format)
  from a TRUSTED key is REJECTED — the verifier binds the signature to the
  manifest (tag + asset + sha256), not the raw bytes, so accepting the raw
  form re-opens a replay hole.

Gated on the box (Go 1.27.4): gofmt + `go vet` clean; all 6 new tests + the
store test pass under `-race`; both benchmarks run at -benchtime=1x.
Sabotage-verified: keying the update-check failure suppression off
`updateCheckAt` (success) instead of `updateCheckAttemptAt` (attempt) flips
`TestUpdateCheckTTLExceedsFailTTLOutageBackoff` red (hits=2, want 1).

## nits-20261120-query-webhook-ui (store.go, main.go, webhook.go, api.go, web/index.html, web/app.js, nits_20261120_test.go, web/test/frontend.test.mjs, 2026-11-20)

Six small nits from the review (the 7th — the api.go file split — is its own
entry). Each verified against live code first. The query rewrites are
behavior-identical (same rows, same order), so their pins are the EXISTING
store/bootstrap suites; the two behavioral fixes (webhook transport, PATCH
error text) and the three UI items get new pins.

- `SensorTagsFor` (store.go): `ORDER BY tag` → `ORDER BY sensor_id, tag`.
  The `(sensor_id, tag)` PK B-tree serves the sort directly (no temp B-tree
  sort); per-sensor output is identical because tags within a sensor were
  already alphabetical.
- `AllTags` (store.go): `COUNT(DISTINCT sensor_id)` → `COUNT(*)`. The PK makes
  each `(sensor_id, tag)` unique, so within a `GROUP BY tag` group each
  sensor_id appears exactly once — the DISTINCT was a no-op dedup pass.
- `migrateAuthBootstrapped` (main.go): `SELECT COUNT(*) FROM probes` →
  `SELECT EXISTS(SELECT 1 FROM probes)`. Existence, not a count — short-
  circuits on the first row instead of scanning the whole table.
- `webhookTransport` (webhook.go): now a Clone of `http.DefaultTransport`
  (inherits IdleConnTimeout 90s, MaxIdleConns 100, MaxIdleConnsPerHost 2,
  TLSHandshakeTimeout 10s) with two overrides — `Proxy: nil` (DefaultTransport
  uses ProxyFromEnvironment; webhook egress must never route through an
  ambient proxy) and `DialContext: dialChecked`. A bare `&http.Transport{}`
  left the idle limits at 0 (unbounded idle conns).
- PATCH target error (api.go): `errPatchTargetInvalid` now returns
  `patchErr.Error()` — the `*crossFieldError` carries the probe-type-specific
  message (TCP: "host:port with an explicit port"; ICMP: "IPv4 address or
  hostname"). The old hardcoded ICMP text mis-told TCP targets what to fix.
- UI polish: `#f-interval` `min="1"` → `min="5"` (matches backend
  `minIntervalS=5`); the Escape key handler now calls `closeAlerts()` (the
  Alerts modal was the one overlay it didn't close); `clear-activity-btn`
  added to `applyAdminVisibility()`'s hide list (a viewer can't clear the
  activity log).

New pins (gated on the box): `TestWebhookTransportHasBoundedIdleLifetime` +
`TestPatchTCPInvalidTargetGetsTCPMessage` (nits_20261120_test.go) and three
Node pins in web/test/frontend.test.mjs (f-interval min, Escape→closeAlerts,
viewer hides clear-activity-btn). The Node harness gained a `fire()` helper so
the document keydown listener is now exercisable.

Gated on the box (Go 1.27.4): gofmt + `go vet` clean; the new nits tests +
the store tag suite + the bootstrap suite pass; `node --test` 9/9.
Sabotage-verified: reverting the transport clone, the PATCH message, or the
`closeAlerts()` call each flips its pin red.

## api-split-settings-put-breakdown (api.go, api_middleware.go, api_sensors.go, api_settings.go, validation_bounds_test.go, 2026-11-20)

Review nit (2026-11-20): `api.go` had grown to ~3,086 LOC / 70 top-level
declarations, and `handleSettingsPut` was a ~400-line function. Both hurt
readability. Keeping `package main` (see the package-layout decision), the
file is now split by domain and the settings-PUT handler is broken into
focused helpers. Pure readability refactor — NO behavioral change; the pin
is the full test suite (gated on the box).

Split (mechanical declaration move, lossless — 2,958/2,958 non-blank lines
preserved, verified):
- `api.go` (~296 LOC): the `Server` struct, `NewServer`, shared types, the
  `respondWith*` / `requestBodyErr` response helpers, `Mux()` + route table,
  `normalizeProbeType`, `handleStatic`.
- `api_middleware.go` (~434 LOC): `authGate`, `hostAllowed` +
  `parseAllowedHosts` / `splitHostPortLenient`, `unauthMutateAllowed`, the
  CORS + rate-limit middleware.
- `api_sensors.go` (~1,532 LOC): sensor CRUD, `handleSensorByID` (PATCH),
  clone, ping, history, graph, events, tags, `validSensorName` / `cleanTags`,
  `setSensorTagsInConn`, `deleteRowsBatched`, the PATCH sentinels.
- `api_settings.go` (~982 LOC): `settingsPayload`, `handleSettingsGet` /
  `Put` / `Test`, provider validation (`validateProviderUpdate*` /
  `applyProviderUpdate*`), `guardSMTPNoCredsOverTLSInTx`, `extraFields`,
  maintenance enter/leave.

Each file carries its own import block, trimmed to what it uses (the compiler
is authoritative — a regex pre-pass over-matched on identifiers in
comments/strings, and the 5 residual unused imports were removed by hand).
The `//go:embed web/*` directive stays with `var content embed.FS` in
`api.go`.

`handleSettingsPut` breakdown (401 → ~90 lines, a short orchestration):
- `settingsPutReq` / `settingsPutProvider`: the request body is now a named
  type (was an inline anonymous struct), so the "nil = keep the stored value"
  contract is documented in one place.
- `validateSettingsPut`: the validate-everything-before-any-write phase
  (allow_unauth pre-guard, alert_scope / realert_min / alert_filter cleaning,
  the pre-flight `getAllSettings` snapshot, the dead-alert guard, per-provider
  stored-state + `validateProviderUpdate`). Returns the snapshot + stored
  extras the apply pass reuses, so validation and apply evaluate the same
  state.
- `applySettingsTx`: the ONE-transaction apply (write-lock pin, provider
  writes, routing fields, the in-tx allow_unauth user-count re-check, commit).
- `applyMaintenanceTransition`: the post-commit maintenance enter/leave
  (snapshot + pause / resume ordering).
The maintenance-entry 400 pre-check stays inline in the handler (it's the
derived "no active sensors to pause" gate and seeds `maintIDs`).

Also fixed a latent regression from the #29 PATCH-message change:
`TestPatchCrossFieldSentinelsNotSubstrings` (review 2026-11-11 #7) still
expected the old ICMP "IPv4 address or hostname" text for a TCP target
without a port. #29 made `errPatchTargetInvalid` render the
probe-type-specific message, so that case now expects "target must be
host:port with an explicit port". The test's core (400 routed to the target
sentinel, not a 500) is unchanged. This was missed because the #29 gate was
targeted, not the full suite.

Gate (Go 1.27.4, the box): gofmt + `go vet` clean; the FULL `go test -race`
suite passes (`ok pulsemon`); `node --test` 9/9. No new pin (behavior is
unchanged — the existing settings/PATCH suites are the pin).

## windows-signing-offline (windows-release.yml, release_pubkeys, update.go, 2026-11-20)

**Decision:** the Windows `.exe` is now signed OFFLINE on the trusted release
host, the same way as the Linux binaries. `windows-release.yml` builds and
uploads the exe + `.sha256` + installer UNSIGNED (the "Sign the Windows
binary" step and its `RELEASE_SIGNING_KEY` secret reference are removed; the
secret is deleted from the repo), and the cut flow gains a step after the
workflow goes green: download the published `.exe`, `pulsemon sign release
<exe> <keyfile> vX.Y.Z pulsemon-windows-amd64.exe`, `pulsemon sign verify`,
then `gh release upload vX.Y.Z <exe>.sig`. A release is NOT Windows-complete
until that `.sig` is uploaded (clients are fail-closed until then). The
signing key now lives ONLY on the release host (600-perm file) and never in
GitHub, so the `install.sh` "lives OUTSIDE GitHub" comment is true again.
**Key rotation (same finding):** the first key (2026-10-29, `c412b899…`) sat
in the `RELEASE_SIGNING_KEY` repo secret from v0.4.0 (2026-10-30) until this
change. It is replaced by the 2026-11-20 key (`31449645…`), added to
`release_pubkeys` as a second line per the rotation model. **Bootstrap order
(do not skip):** the NEXT release (R1) is signed with the OLD key — every
installed client embeds only the old pubkey, and a `.sig` is a single 64-byte
signature (no dual-sign in one asset), so a new-key signature would be
refused by all of them. R1's binary carries BOTH pubkeys, so the release
AFTER it (R2) is signed with the NEW key and verifies on every client that
took R1. A client stranded on a pre-R1 version refuses R2 via self-update
and is recovered with a manual `install.sh` run (it fetches the pubkeys
live from main, which has both keys). The old pubkey is retired in a LATER
release once the fleet is off it, and the old PRIVATE key is destroyed after
R2 ships — it must be kept until R1 is cut (backup on the release host:
`release-signing-key.hex.2026-11-20`).

**Why:** with the key in a repo secret, the authenticity root was compromised
in exactly the scenario it exists to survive. `windows-release.yml` ran on
ANY `v*` tag push and on `workflow_dispatch` from ANY branch with a free-text
`version` input, so anyone with push access (a leaked token is enough) could
run it on a branch with their own code and have CI sign a trojaned
`pulsemon-windows-amd64.exe` for any tag — Windows self-update would install
it. Because `release_pubkeys` is a shared SET with no key-to-asset binding, a
modified workflow could also print the key and sign Linux assets — permanent
exposure of every client until rotation. The anti-downgrade floor does not
help (the attacker picks the tag). A GitHub Environment + required reviewers
only raises the bar (an admin token can also edit branch protection, and the
key is still visible to every job on the runner); a per-platform key with
asset binding is the most work and still leaves a key in CI. Signing offline
removes the exposure class entirely and matches the Linux path; the cost is a
few manual steps per release by the sole release operator.

**Pinned by:** no new pin (workflow + docs + embedded key-set change; the
signing/verification behavior is already pinned by `update_sig_test.go` and
`update_manifest_test.go`, and `TestVerifyReleaseSignature_Rotation` pins the
two-key bridge — a sig from either embedded key verifies). Standing checks:
the `pulsemon-release` skill's release checklist (a release is not
Windows-complete until the offline `.sig` is uploaded and verifies with the
5-arg manifest form) and the grep gate `! grep -rn
'secrets.RELEASE_SIGNING_KEY' .github/` (the workflow must not reference the
secret again — a plain-text mention in a comment is fine).

## windows-setup-sig (windows-release.yml, docs, 2026-11-23)

**Decision:** (external review H7) the Inno Setup installer
`pulsemon-setup-<ver>.exe` is now part of the OFFLINE ed25519 `.sig` flow,
alongside `pulsemon-windows-amd64.exe`. After `windows-release.yml` goes
green, the cut flow signs BOTH Windows assets offline on the release host
(manifest form — the manifest message is asset-name-agnostic, so NO Go
change is needed; the installer's asset name is `pulsemon-setup-<ver>.exe`),
verifies both with the 5-arg `sign verify`, and uploads both `.sig` files.
A release is not Windows-complete until BOTH `.sig` files are uploaded.
**Authenticode is deliberately NOT adopted:** it is a paid code-signing
certificate that buys a SmartScreen trust signal for end users; pulsemon is
a single-operator homelab tool whose only installer user is the operator
running their own GitHub release, and the `.sig` already covers the actual
threat (a GitHub/repo compromise republishing a trojaned installer + its
`.sha256`). Revisit only if pulsemon ships outside the LAN.

**Why:** the installer was the ONLY release asset with no authenticity
anchor — its `.sha256` sidecar is worthless against the exact threat the
`.sig` exists for (a compromised GitHub republishes the file AND its
checksum) — and it is the highest-trust artifact in the set: running it
plants an auto-start service. The self-update path (bare exe) was already
fail-closed signed; the fresh-install path (installer) was the gap. Cost is
~zero per release: two extra `sign` invocations on the release host, and
`sign verify <file> <tag> <asset>` works on any file (embedded
`release_pubkeys`, no private key needed) — which doubles as the documented
verify-before-run step for a fresh box (download the installer + its `.sig`
+ any release binary, verify, then run the installer).

**Pinned by:** the `pulsemon-release` skill's checklist (13 assets; the
installer carries `.sha256` + `.sig`; step 4b signs BOTH Windows assets) and
the `windows-release.yml` header comment. No Go change: the manifest
verifier in `update.go` is asset-name-agnostic, and the updater only
consumes the bare exe, so the installer's `.sig` is a manual pre-run check,
not client-enforced.

## viewer-target-redaction (api_sensors.go, target_redaction_test.go, 2026-11-20)

**Decision:** `GET /api/sensors` and `GET /api/sensors/{id}` now run the
stored target through `alertTarget` (the alert cards' raw-string last-'@'
userinfo cut) when the caller is a NON-ADMIN session — a viewer sees
`https://user:pass@host/` as `https://host/`. Admins and auth-off installs
(the trusted-LAN single-operator mode, where `requireAdmin` stands down)
get the raw target. The redaction is VIEW-ONLY: the DB row is untouched,
and the edit modal is admin-only, so a masked value can never be saved
back — the reason target masking was previously declined for the shared UI
does not apply to this read path.
**Why:** the settings reads are admin-only, but the sensor reads are open
to every session and returned the stored target verbatim — a viewer
account could read the credentials an operator stored in an http target,
which is exactly the data the admin-only settings gate exists to keep from
lower-trust accounts. Reusing `alertTarget` keeps ONE redaction rule for
both consumers (parse-failure safe, last-'@' boundary, path `'@'`
preserved); non-URL targets (bare IP, `host:port`) have no authority and
come back unchanged.
**Pinned by:** `TestViewerTargetRedaction` — viewer list + by-id get the
stripped form, the tcp target is unchanged, the admin gets the raw target
on both paths, and the DB row is byte-identical after the viewer reads.
Sabotage-verified: removing the `viewerTarget` call from either GET path
turns the viewer assertions red.

## embed-explicit-list (api.go, embed_surface_test.go, 2026-11-20)

**Decision:** the dashboard embed is an EXPLICIT file list, not
`web/*`. The wildcard pulled `web/test/*.mjs` (the frontend test
harness) into the release binary, where `handleStatic` served it at
`/test/...` — the app's test files shipped on every dashboard. The list
covers the shipped surface exactly: `index.html`, `app.js`, `styles.css`,
`theme.js`, the five icon files, and `web/vendor` (fonts + icon CSS —
intentional; the `.woff2` Content-Type case in `handleStatic` exists for
it).
**Why:** `//go:embed` has no exclude syntax, so the wildcard is the
only way it can ship a directory nobody asked for; an explicit list
fails the build if a listed file disappears and ships nothing else.
**Pinned by:** `TestEmbedSurfaceExcludesTests` — the two test files are
unreadable from the embed FS, every real asset (incl. `web/vendor/`)
is readable, and no `test` entry sits at the `web/` root of the FS.
Sabotage-verified: restoring `web/*` turns the pin red.

## install-pubkeys-proto-pin (install.sh, 2026-11-20)

**Decision:** the `release_pubkeys` fetch — the one `curl` in install.sh
whose URL is overridable (`PULSEMON_PUBKEYS_URL` test hook) — now carries
`--proto '=https' --tlsv1.2` for https URLs, matching every other
download in the script. The pin is applied by a `case` on the URL
scheme, because the test hook serves fixtures over `file://`, which a
hardcoded `=https` restriction would break.
**Why:** the default URL is https (raw.githubusercontent.com), so the
production path gets the same proto+TLS floor as the asset/digest/sig
downloads; an override to a non-https URL is a local test-harness act
and is not held to the public-internet floor.
**Pinned by:** the DECISIONS entry + `grep` — the `case` arm sets the
pin for `https://*` and the `curl` consumes `$PUBKEYS_PROTO`; the
`file://` hook stays un-restricted (breaking it breaks the install
harness, which would be loud, not silent).

## target-query-redaction (alerts.go, target_query_redaction_test.go, fuzz_validators_test.go, 2026-11-20)

**Decision:** `alertTarget` now cuts the query AND fragment of a URL
target, in addition to the userinfo. A `?token=…` in the target is a
credential carrier exactly like `user:pass@` (the same shape
`webhookMasked` treats as secret), and it used to go verbatim into every
alert card (Discord/Telegram/Chat/SMTP) and to viewer sessions
(`viewerTarget` reuses `alertTarget`). The cut is unconditional — a
redaction that promises "safe for a third-party channel" cannot prove a
query param non-secret, so the param-key heuristic is rejected as
bypassable (`?t=…`).
**Why:** only `user:pass@` was redacted; the query string was the
companion leak channel. The authority boundary stays exactly net/url's
(first `/?#` — a raw `?`/`#` cannot sit inside userinfo per RFC 3986,
so `https://user?x:pass@host/` is host `user` + a query that gets
cut, not a lenient userinfo). Non-URL targets are untouched; `@` in
the PATH survives; the raw-string (no `neturl.Parse` dependency)
discipline is unchanged, so parse-failure rows still get stripped, not
shipped.
The local-journald surface (`ping.go` dns re-resolution log) still
carries the raw target — accepted: it is a local root-readable log on a
trusted homelab box, the same channel `user:pass@` already occupies.
**Pinned by:** `TestAlertTargetQueryRedaction` (11 table cases: token
query, token-only, userinfo+query, fragment, query+fragment, no-query
unchanged, path-`@` survives, lenient-userinfo `?`, bare IP/host:port)
and the extended `FuzzAlertTarget` property (any clean-host URL comes
back with no userinfo AND no query/fragment; host preserved; output
still parses). Same pass also REPAIRED five table-test literals in
`fuzz_validators_test.go` that a prior session's redaction layer had
committed as `***`-passwords (raw-@, pct-escape, control-char, and
bad-escape variants) — the last-`@` boundary pin now tests the shape it
claims to test.

## windows-service-vsa (installer/pulsemon.iss, main_windows.go, listener_windows.go, ping_windows.go, update.go, update_windows.go, restart_helper_windows.go, restart_helper_stub_linux.go, update_rollback_linux.go, update_rollback_windows.go, main.go, 2026-11-23)
**Decision:** the Windows service now runs as the least-privilege virtual service account `NT SERVICE\Pulsemon` — the installer's `sc create` carries `obj= "NT SERVICE\Pulsemon"` (the SCM materializes the VSA at create time; no local account, no password), the data-dir ACL grants the VSA `(OI)(CI)(M)` (the explicit SYSTEM grant is removed on every install) and the app-dir ACL grants the VSA `(OI)(CI)(M)` for self-update. `pulsemon restart` and every update-flow restart drive the SCM natively via `golang.org/x/sys/windows/svc/mgr` (`restartWindowsServiceFn` = Stop + wait-for-Stopped + Start; no `powershell -Command "Restart-Service"` child process). The in-dashboard update SELF-RESTARTS on Windows (supersedes the 2026-10-19 no-auto-restart decision, reopened 2026-11-23 because VSA + native SCM made it cleanly feasible and zendev-testable): `performRestartWindows` branches on `isWindowsService()` — the dying service detaches a `__restart-helper` child from the NEW binary (SCM binPath, quoted-stripped) and then issues its own SCM Stop; the helper (same VSA token, the SCM grants a service full control of its own service) waits for the stopped state (90s bound, logging to `<datadir>\pulsemon-restart.log`) and starts the service. External callers (console `update --restart`, the rollback watchdog) get the synchronous stop→start. The watchdog's rollback stops the service before the rename on Windows (`rollbackBinaryFile`, platform-split) because a running service locks the .exe; `wdOldProcTimeout` is raised to 45s on Windows (the clean drain is bounded ~30s + SCM grace). The datagram boot retry is hardened (10 attempts, growing 500ms base ≈ 22.5s worst case).
**Why:** running as NT AUTHORITY\SYSTEM gave the monitor process full system rights it never used — ICMP already goes out over an unprivileged SOCK_DGRAM socket (ping_windows.go), everything else is a DB file + outbound HTTP. A VSA is a real, auditable identity with no credentials to manage, and the upgrade path is free because the installer already deletes + recreates the service registration on every install (the SCM display-name-cache fix) — a pre-VSA LocalSystem registration is replaced by the `obj=` create on the next install. The raw-socket fallback (SOCK_RAW) is unreachable under a VSA (it needs elevation), so the boot-time dgram retry is the effective last line for ICMP — hence the hardening. The app-dir (M) grant for self-update is deliberate: a compromised service can replace its own binary (inherent to self-update); the update flow verifies sha256 + ed25519 signature BEFORE the swap, so the grant adds no network-facing surface. The helper-before-stop ordering is the invariant: the helper is the only process that can start the service back after the updater exits.
**Installer bugs caught by zendev live QA (2026-11-23, commit e384862):** (1) the data-dir icacls ran with the VSA name BEFORE `sc create` - the `NT SERVICE\Pulsemon` SID does not exist until the service is registered, so the grant silently failed and fresh installs would have shipped the data dir with ProgramData's inherited ACL (BUILTIN\Users RX on the DB, the M1/F30 regression); the data-dir ACLs now run in `GrantDataDirAcls` after the create succeeds. (2) Neither icacls applied the grant to pre-existing files (no `/T`): on the upgrade path the old DB carries no VSA entry (crash loop - the VSA could not open it) and the .exe (copied before the app-dir grant) was unrenamable by self-update; both grants (and the SYSTEM /remove) now carry `/T`.

**Pinned by:** `TestInstallerRegistersVSA`, `TestInstallerIsASCII`, `TestWindowsRestartUsesNativeSCM`, `TestIcmpHintNoLocalSystem`, `TestDgramBootRetryHardened`, `TestWindowsSelfRestartHelper`, `TestWindowsRollbackStopsServiceFirst` (source-level pins, run on the Linux gate box) + `TestRunRestartCommandNativeSCM`, `TestRunRestartCommandFailure`, `TestDetectRestartWindows`, `TestPerformRestartWindowsServiceBranch`, `TestPerformRestartWindowsExternalBranch` (windows-tagged seam pins — compile-gated via `GOOS=windows go vet` on the box, behavior verified on the QA box). Sabotage-verified: dropping `obj=` from the .iss, restoring the powershell exec, or shrinking the retry constants reds the matching pins.

## reauth-destructive-account-ops (auth.go, auth_test.go, auth_reauth_test.go, auth_error_status_test.go, csrf_test.go, tail_hardening_test.go, remove_user_notfound_test.go, admin_gate_test.go, tag_admin_gate_test.go, target_redaction_test.go, web/app.js, web/index.html, web/test/auth_reauth.test.mjs, 2026-11-23)
**Decision:** every destructive account operation — `POST /api/auth/users` (the authenticated admin-add path), `DELETE /api/auth/users/{username}`, and `POST /api/auth/disable` — now requires the SESSION's OWN current password, verified by a single shared helper `Server.reauthCurrentPassword` (extracted from `handleAuthUserPassword`, which now calls it too). The check mirrors the login credential gate exactly: empty/>72-byte input is a 400 that is NOT charged to the throttle (no KDF ran); the check runs through the per-IP login throttle (`beginAttempt`) AND the shared per-username failure budget (`checkUserLock`), so a session holder spraying `current_password` from many /64 IPs locks the account exactly like a login spray, and a locked account 429s on every reauth surface and on login; a wrong password pays the same constant rejection delay and counts against the account budget; a correct one clears the caller's failure streak. Ordering: `requireAdmin` (401/403) → body decode (400) → reauth (400/403/429) → the operation's own guards (404 unknown user, 400 last-user, 500 db). The setup-mode bootstrap stays open (no session exists by definition); an intentionally-disabled install's refused unauthenticated add still 403s at the admin gate before any body is read.
**Why:** external review L1 (2026-11-23): a session cookie is a bearer token — stolen cookie, unlocked browser, replayed curl. Against the pre-fix handlers, such a holder could add a backdoor admin account (persistence that survives password rotation and every recovery short of a reinstall — the sharpest primitive), disable auth (a silent posture downgrade: the dashboard goes open to the network, and with `allow_unauth_update` set, self-update follows), and delete accounts (erasing the real owner's account is the clearest takeover tell). The password-change endpoint already enforced current-password reauth for exactly this threat model; the other three destructive endpoints did not, so the threat model was applied inconsistently across one surface. The invariant now: the operator's password knowledge beats a stolen cookie on every account-level operation. One shared helper (not three inline copies) so the throttle semantics — the part that is easy to get subtly wrong (refunds, per-IP vs per-username buckets, the disconnect KDF-cost split) — can never drift apart across the four surfaces.
**Pinned by:** `auth_reauth_test.go` (`TestReauthMissingCurrentPassword` 400-per-endpoint, `TestReauthWrongCurrentPassword` 403 + no state mutation per endpoint, `TestReauthLastUserGuardOrdering` reauth→guard ordering, `TestReauthThrottle` 7-wrong-spray → 429 on the shared per-IP bucket, `TestReauthBootstrapUnaffected` bootstrap open + next add gated) and `web/test/auth_reauth.test.mjs` (add-user POST carries the current password, remove-user and disable-auth open the password modal and send no destructive call until it verifies, bootstrap create sends NO current_password, the add-user box ships an `autocomplete="current-password"` input). The UI re-uses the account modal in a confirm mode (current-password field only) for delete/disable; the add-user form gains a "Your password" field. Sabotage check: removing the `reauthCurrentPassword` call from any of the three handlers reds the missing/wrong/throttle pins; reverting the UI modal reds the frontend pins.

## windows-upgrade-safety (web/app.js, web/index.html, web/test/conn_banner.test.mjs, installer/pulsemon.iss, update.go, update_api.go, restart_helper_windows.go, internal/store/store.go, store_backup_test.go, update_preupdate_test.go, restart_helper_windows_test.go, upgrade_safety_test.go, 2026-11-23)
**Decision:** four independent hardenings so a Windows upgrade can never again look (or be) a sensor wipe. (1) The dashboard shows a "waiting for the pulsemon server" banner while `refresh()` cannot reach the API (the 5s poller is the retry; the banner is its visible half) — a page loaded during the service-down window of an upgrade no longer renders the silent "no sensors" empty state that reads as data loss. (2) The installer polls `http://localhost:9299/api/healthz` (PowerShell, up to ~15s) and opens the browser only once the service answers; a TLS install (no plain-HTTP port) falls back to the old open-after-timeout behavior. (3) The in-dashboard/CLI self-update writes `pulsemon.db.preupdate` — a consistent `VACUUM INTO` snapshot (`Store.BackupTo`, valid while serving, no service pause) — BEFORE the binary swap; the Windows `__restart-helper`, after starting the service, polls healthz for the live sensor count and, if it DROPPED below the backup's count, takes the update lock, stops the service, restores the backup DB (removing the stale -wal/-shm first so they cannot replay over the snapshot), rolls the binary back to `.prev`, and restarts on the known-good pair. (4) The installer makes the same `pulsemon.db.preupdate` copy (plain `FileCopy`, valid because the service is stopped) in `PrepareToInstall` before the .exe overwrite and on the uninstall path.
**Why:** zendev QA (2026-11-23) showed the v1.1.19 in-dashboard self-update "wiping" the sensors: the DB file's CreationTime (10/11/2026) proved it was never deleted — the installer's `OpenDashboard` fires in `ssPostInstall` ~4s before the service binds its port, the first `fetch('/api/sensors')` hits a dead port, and the UI renders the empty state until the next 5s tick. Zero data loss, maximum scare. The display fix (items 1+2) removes the scare on both upgrade paths (installer + self-update, since the browser tab hits the same dead port); items 3+4 are belt-and-suspenders: a genuine data-losing update (corrupt swap, bad migration, a future code path deleting rows) is now detected by count comparison and auto-restored, on every Windows upgrade path, with the restart log (`pulsemon-restart.log`) as the post-mortem audience. The verifier deliberately does NOT act on unverifiable states (no backup, no usable healthz): the update watchdog already owns the "service did not come up" case (binary rollback), and double-acting risks clobbering a healthy install. Restore fires only on a DROPPED count — sensors added during the window (count went UP) are not loss.
**Pinned by:** `web/test/conn_banner.test.mjs` (banner shown on a dead-server page load, hidden on the next successful refresh, text escalates after 3 failures, positive control; sabotage-verified), `upgrade_safety_test.go` (`TestInstallerDashboardHealthzGated`: HealthzAlive polls before the ShellExec open; `TestInstallerPreStopDBBackup`: FileCopy to pulsemon.db.preupdate in PrepareToInstall AND the uninstall path), `internal/store/store_backup_test.go` (`TestStoreBackupToSnapshotIsConsistent`: the VACUUM INTO snapshot is standalone and excludes post-backup writes), `update_preupdate_test.go` (`TestBackupDatabasePreUpdateMakesConsistentCopy` via PULSEMON_DB, `TestBackupDatabasePreUpdateNoDBIsBestEffort` — no DB = no panic, no file, update proceeds, `TestSensorRestoreDecision` — the pure decision core: drop=restore, intact/added/no-backup/unavailable=no-restore), `restart_helper_windows_test.go` (windows-tagged: intact=no action, data-loss=stop+restore+rollback+start, no-backup=skip, unhealthy=no double-act; compile-gated via `GOOS=windows go build`/`go vet` on the gate box, executable on a Windows host). Sabotage-verified: removing the banner wiring from `refresh()` reds 4/5 frontend pins; the .iss pins red when the poll or the FileCopy is dropped.

## windows-recovery-restart (update_windows.go, main_windows.go, update.go, update_rollback_windows.go, installer/pulsemon.iss, main.go, windows_service_test.go, windows_service_win_test.go, update_watchdog_verify_test.go, 2026-11-23)
**Superseded for the update flow (2026-11-24):** the in-service restart half — exit(3) → 7031 → SCM recovery action — is removed from the update path; see `windows-update-staged`. What survives from this entry: the installer's recovery action (now a crash safety net only), the external (elevated console) synchronous stop→start path, the VSA ACE (for QUERY rights), and the watchdog's `verifySensorsIntactWatchdog` data-integrity guard.
**Decision:** the Windows in-dashboard self-update no longer tries to make the VSA stop/start its own service — it delegates the restart to the SCM's RECOVERY ACTION. The design: (1) the installer's `sc failure ... actions= restart/10000/restart/30000/restart/60000` (already present) is now LOAD-BEARING for the self-update, not just crash insurance; (2) `performRestartWindows`' in-service branch calls `selfRestartViaRecoveryFn`, which first verifies the recovery action is configured (`recoveryActionConfiguredFn` reads HKLM\...\Services\Pulsemon\Recovery with plain KEY_READ — a missing action means the update is REFUSED with a clear error, because the update would strand the monitor stopped with no one to bring it back), then closes the handler's stop channel to run the SAME clean drain a Stop control triggers (bounded 45s, matching `wdOldProcTimeout`), then `os.Exit(updateExitCode=3)` WITHOUT reporting Stopped — the SCM records an unexpected termination (7031) and runs the recovery action: restart, now on the NEW binary. services.exe (SYSTEM) does the starting, so the VSA needs no SCM rights for any of it; (3) the `__restart-helper` child process (`s.Start()` from the VSA token) and its `main.go` dispatch case are RETIRED — `restart_helper_windows.go`, `restart_helper_stub_linux.go`, `restart_helper_windows_test.go` deleted; (4) the sensor-integrity verification MOVES from the retired helper into the SHARED watchdog: `runWatchdog`'s healthy path now calls `verifySensorsIntactWatchdog(db, prev, dst)` (update.go), which compares the live healthz sensor count against `pulsemon.db.preupdate` and, on a drop, restores the backup DB + rolls the binary back + restarts — with a SAFETY GATE the helper never had: the service is RUNNING when the healthy path runs, and a DB restore under a live writer corrupts the data, so the restore proceeds only when the service is stopped (`serviceStateFn`: Windows = SCM QueryServiceStatus with the VSA's proven query right, Linux = systemctl is-active); a running service is stopped first (`stopForRestoreFn`), and a DENIED stop (the VSA case) means nothing is touched and `pulsemon-watchdog.log` carries exact manual-restore instructions; (5) `rollbackBinaryFile` (Windows) treats the stop as best-effort (the VSA lacks SERVICE_STOP) — the rename is the authoritative check, since a crash-looping service releases its image lock between recovery attempts; (6) the service handler's drain channels are exposed as package vars (`serviceStopCh`/`serviceDoneCh`) so the in-service update path can drive the identical clean drain a Stop control runs; (7) all SCM calls in `update_windows.go` use the raw `windows.OpenSCManager`/`windows.OpenService` with per-call minimal masks (the `svc/mgr` import is gone — `mgr.Connect()` requests SC_MANAGER_ALL_ACCESS, which the VSA's SCManager DACL denies). The `GrantServiceSelfAccess` ACE (CCLCSWLOCRRC) is kept for the VSA's QUERY rights (the update flow's state checks) with its comment corrected: the DACL-granted START/STOP are run-time denied by mandatory integrity enforcement.
**Why:** zendev live probing (2026-11-23, from the service's OWN token — sdace/svcprobe) proved the previous architecture's core assumption false: the service object's DACL DOES grant the VSA START|STOP (CCLCSWLOCRRC decodes to 0x220136, which includes them), yet `OpenService` with START or STOP is access-denied. The denial is mandatory-integrity enforcement — the service object carries a higher integrity label than the VSA's Medium-integrity token, and the UI policy blocks write-type rights across that gap regardless of the DACL. Every grant path was exhausted: SDDL via `sc sdset` (1336 for useful masks with the 8-part VSA SID + SACL), binary `SetServiceObjectSecurityW` (the VSA can't even OpenSCManager with ALL_ACCESS), account swap to `.LocalSystem` (sc.exe 1057 for all syntaxes; direct registry edit = SCM cache desync = instant 7031 crash with no log). The VSA will NEVER hold SERVICE_START on its own service object through any supported mechanism — so the process that starts the service must be one that isn't the VSA. The SCM itself is: its recovery action is executed by services.exe, needs no rights from the service, was already configured by the installer, and was already proven live on zendev (the 7031 events during diagnostics showed "corrective action will be taken in 30000/60000 milliseconds: Restart the service"). A clean self-stop is NOT the trigger (recovery fires on unexpected termination, not clean stop), hence the deliberate failure-exit: drain first (so no probes/alerts are killed mid-flight), then exit(3) unreported. The watchdog gaining the sensor verification (with the state-gated restore) is strictly stronger than the helper: it runs under the update lock, it has the binary paths in hand (no registry lookup), it logs to a file (the detached process has no stderr), and its restore can never corrupt a live DB.
**Pinned by:** `windows_service_test.go` (`TestWindowsRecoveryRestart`: the in-service branch uses `selfRestartViaRecoveryFn` + `recoveryActionConfiguredFn` + `os.Exit(updateExitCode)`, no `s.Start()`, no `__restart-helper` anywhere, the .iss carries the `sc failure`/`restart/` recovery action, main.go does NOT dispatch the retired subcommand, runWatchdog's healthy path calls `verifySensorsIntactWatchdog(db, prev, dst)`; `TestWindowsRestartUsesNativeSCM` rewritten: no `svc/mgr`, raw `windows.OpenSCManager`/`OpenService`, no powershell) + `windows_service_win_test.go` (windows-tagged seam pins: `TestPerformRestartWindowsServiceBranch` — the branch delegates to the recovery self-restart seam, external branch keeps the synchronous stop→start; `TestSelfRestartRefusesWithoutRecovery` — no recovery action = error, NOT exit; `TestDetectRestartWindows` now stubs `scmStateFn`) + `update_watchdog_verify_test.go` (Linux-runnable: intact=no action, data-loss+stopped=restore+rollback+restart, data-loss+running+stop-denied=NOTHING touched + manual instructions in the log, data-loss+running+stop-ok=full restore, no-backup/zero-backup/live-unavailable=skip; all read `pulsemon-watchdog.log` for the audit trail). Sabotage-verified: removing the `os.Exit(updateExitCode)` path, the recovery pre-flight, the `sc failure` line from the .iss, or the state gate in `verifySensorsIntactWatchdog` reds the matching pins.

## deleting-state-stuck-recovery (api_sensors.go, probe.go, deleting_state_lifecycle_test.go, 2026-11-24)
**Decision:** three changes close the lifecycle of a sensor row marked `state = 'deleting'` so the transient mark can never outlive the process that set it. (1) `DELETE /api/sensors/{id}` runs its entire post-mark work — the mark, both `deleteRowsBatched` calls, and the final row DELETE — on `context.WithoutCancel(r.Context())`: the cascade outlives a client that leaves mid-delete (tab closed, navigation). The pre-commit existence check keeps `r.Context()` (a client that is already gone should not start a delete). `restoreState` moves to a fresh `context.Background()` + 5s timeout, and its UPDATE gains a `state = 'deleting'` guard so it rolls back only what THIS delete marked. (2) `ProbeWorker.Run` finishes interrupted deletions at boot: `DELETE FROM sensors WHERE state = 'deleting'` between `purgeOld` and `warmStats` (the FK cascade cleans the footprint; nothing is probing yet, so the single-statement sweep stalls no concurrent writer), logging the count when nonzero. (3) The PATCH in-tx read gains `AND state <> 'deleting'` — a mid-delete row 404s like a missing one, so no PATCH (e.g. `{"state":"active"}`) can match and revive a sensor halfway through its cascade; the UPDATE is unchanged because the IMMEDIATE tx already holds the write lock the read takes.
**Why:** the batched cascade takes seconds (a 5s sensor carries ~17k probe rows), and everything in it ran on the request context. A client departure — or a crash, a kill, or `srv.Shutdown`'s 5s drain expiring — cancels that context mid-cascade: the next `deleteRowsBatched` fails with `context.Canceled`, and `restoreState`'s `ExecContext` on the SAME dead context fails at once, so the row is stranded in `'deleting'` with no compensating path. A stranded row is invisible (fetchSensors filters it), loopless (syncSensors/warmStats exclude it), Pulse-Now-409 (errSensorDeleting), name-UNIQUE-held (re-creating "nas" 409s with nothing visible to explain it), and purgeOld's 60-row tail exemption (keyed off `SensorIDs()`, any state) keeps its probe tail forever. The boot sweep is the backstop for the deaths the detached contexts cannot cover (a process cannot outlive its own death); the PATCH filter closes the sibling hole the same review flagged — the in-tx SELECT and the UPDATE both matched deleting rows, so a state PATCH could resurrect a sensor mid-delete. `WithoutCancel` (not a fresh `Background`) is deliberate: it keeps the request's values (logging, tracing) while dropping only the cancel signal, and the cascade needs no deadline of its own — each batch is a bounded autocommit holding the WAL write lock for milliseconds.
**Pinned by:** `deleting_state_lifecycle_test.go` — `TestDeleteCompletesWhenClientGoesAwayMidCascade` (the seam cancels the request context mid-cascade, then runs the REAL batched delete on the handler's context: detached → 204 + full footprint gone; the old request-context shape fails the first batch and the row is stranded), `TestDeleteRestoreStateSurvivesCanceledRequest` (client gone AND a genuine cascade failure: the restore must still land the row back to its pre-delete state — the exact shape `TestDeleteSensorRestoresStateOnBatchedDeleteFailure` misses, where the error fires while the request context is still live), `TestRunCompletesInterruptedDeletesAtBoot` (a `'deleting'` row with full cascade footprint + a paused positive control; `Run`'s boot sweep must remove the former's row and every child table and leave the latter intact), `TestPatchDeletingSensorIsNotFound` (state-revive and name PATCH both 404 on a deleting row, row untouched; a paused sensor still PATCHes to active). Sabotage-verified: restoring the request context to the cascade/restore reds pins 1–2; deleting the boot sweep reds pin 3; dropping the `state <> 'deleting'` filter reds pin 4.

## restore-db-atomic-swap (update.go, update_restore_test.go, 2026-11-24)
**Decision:** external review finding #3 VERDICT valid, fix taken as proposed. `restoreDatabaseFile` — the watchdog's data-loss self-heal (the only path that replaces the live DB with the `pulsemon.db.preupdate` snapshot) — did `os.ReadFile(backup)` + `os.WriteFile(live, …)`: the whole database in RAM (hundreds of MB at the declared fleet), then a truncate-and-rewrite of the live file IN PLACE. A power loss in the write window strands a truncated live DB — in the one code path that runs only AFTER the watchdog has already proved data loss, i.e. exactly when a second failure is least acceptable. The .preupdate copy survives either way, so the old behavior was recoverable-but-manual; the new one cannot lose the live file at all.
**Fix (reviewer's remedy, verbatim):** stream the backup with `os.Open` + `io.Copy` into a same-directory temp file (`os.CreateTemp(dir, ".pulsemon-restore-*")`), `Chmod 0600` + `Sync()` it, then `os.Rename` into place. Same directory is what makes the rename atomic (cross-device rename would fall back to a non-atomic copy). The live path now sees the old file whole or the new one whole, never a prefix; the restored file is 0600 (owner-only data, stricter than the old preserved-mode behavior, which only mattered when the live file pre-existed). The stale -wal/-shm removal is unchanged and stays first.
**Pinned by:** `update_restore_test.go` — `TestRestoreDatabaseFileAtomicSwap` (1 MiB backup: content byte-identical, -wal/-shm gone, NO temp file left, restored mode 0600, and the mechanism itself: the live file's INODE CHANGES — a rename swap installs a new file, the in-place shape kept the same inode), `TestRestoreDatabaseFileFailureLeavesLiveIntact` (a copy that fails mid-way — backup path is a directory, Open accepts it, the first read fails — must return an error with the live file byte- AND inode-untouched and no temp leak), `TestRestoreDatabaseFileNoBulkRead` (source-level audit, precedent TestAPIRoutesAllSessionWrapped: no `os.ReadFile` in the function; `os.CreateTemp` + `io.Copy` + `os.Rename` + `Sync()` all present). Sabotage-verified: restoring the old ReadFile/WriteFile body reds the inode pin and the audit pin (the failure-intact pin survives by design — the old code's real danger window is between truncate and write, which no deterministic test can land in; the two mechanism pins are what keep it closed).

## rtt-wire-rounding (stats.go, statscache_test.go, stats_float_noise_test.go, 2026-11-24)
**Decision:** external review finding #4 VERDICT valid, fix taken as proposed. RTTs live as float32 in the in-memory series and are widened to float64 for JSON; a bare widening carries float32 quantization noise (12.34 → 12.34000015258789) — digits the measurement cannot support, ~90 of them per sensor per 5s poll, per tab, compressing poorly under gzip. Every RTT response-exit site in `computeSensorStats` now rounds to 1µs (0.001 ms) via one helper, `roundRTT` (`math.Round(v*1000)/1000`), applied at the exit, not during accumulation: `rttToPtr` (feeds the 30 Recent values), `RTTLast` (now via rttToPtr), `RTTMin/RTTMax/RTTAvg` (raw values feed the min/max/sum scan; the three exits round), `HourRTTAvg`, and the 60 hour-bucket values (raw minRTT comparison, rounded on publish). Rounding BEFORE the min/max comparison or the sum would be a behavior change; at the exit it is pure presentation.
**Deliberate non-changes:** (1) Percentages (LossPct, HourLossPct, StatusLossPct, Uptime24h) are count ratios, not RTTs — their digits are informative (33.333… is a real 1/3), so they are NOT rounded; pinning that is part of the test. (2) The DB storage path is untouched: probe inserts widen float32→REAL at the driver, so stored rows carry the same noise, and /history and /graph serve it. Both are on-demand endpoints (inspector click, graph fetch), not the 5s poll the finding sizes; rounding at insert would mix two precision generations across the 24h retention window for no per-poll gain. (3) The finding's scaling note (cache SensorStats keyed on (newest ts, current minute) at 1,000+ sensors — ~90 small allocations per sensor per poll per tab today) is DEFERRED: the fleet is 22 sensors; the allocation cost is noise at 50 and only becomes visible in the 500–1,000+ regime the finding itself gates on.
**Ripple:** the SQL parity reference (`sqlStats`, statscache_test.go) mirrors the contract exactly — raw values feed its window scan, and the same 1µs rounding is applied at each of its five exits (Recent, RTTLast, min/max/avg, HourRTTAvg, the hour buckets) — because `compareStats` checks at 1e-6 and a 1µs-round vs raw comparison is up to 5e-4 apart.
**Pinned by:** `stats_float_noise_test.go` — `TestRTTToPtrRoundsWideningNoise` (12.34 and 15.67 come back exactly; 12.3446 → 12.345 proves 1µs resolution survives; NaN → nil), `TestComputeSensorStatsRTTWireValuesAreClean` (all five field families clean at 1µs on a 60-probe lo/hi alternation; RTTAvg/HourRTTAvg exactly 14.005; the MARSHALED JSON contains no widening-noise digit sequences and does contain the clean values), `TestComputeSensorStatsRoundingKeepsDecisioningIntact` (Total/LostCount exact, LossPct full-precision and NOT 1µs-rounded). Sabotage-verified: reverting rttToPtr to the bare widening reds both the helper pin and the wire pin.

## ci-stats-contamination-fix (stats.go, statscache_test.go, 2026-11-24)
**Decision:** `1c8ac35` (finding #4) accidentally carried the in-flight probes-table batch into two files: `stats.go`'s `warmStats` had been re-keyed to `sk`/`ts_ms` (migration 14) and `statscache_test.go`'s fixtures INSERTed `sk` — while `store.go` on main was still at migration 13. Result: main was a half-migration; CI red (`table probes has no column named sk`, all warmStats/graph/chunk tests reading 0 rows because the epoch-ms integers were string-compared against the TEXT `ts` column). Fix: both files restored to the `af31d31` base with ONLY the finding-#4 rounding re-applied (roundRTT at the five exits + the SQL reference's mirrored rounding); the batch's `sk`/`ts_ms` changes return to main exactly once, with migration 14, in the batch commit. The batch's full diff against these two files is therefore unchanged — only its base moved.
**Pinned by:** CI on this commit (full `go test -race ./...`), plus the existing `rtt-wire-rounding` pins, which are the content-identical re-application.

## probe-rows-int-schema (internal/store/store.go, probe.go, stats.go, status.go, api_sensors.go, 46 test files, 2026-11-24)
**Decision:** the probes table — the one table that grows without bound (every probe of every sensor, 24h retention) — moves from `sensor_id TEXT` (a 36-byte UUID per row, per probe) + `ts TEXT` (a 33-byte RFC3339Nano string per row, compared lexicographically) to `sk INTEGER NOT NULL REFERENCES sensors(sk) ON DELETE CASCADE` + `ts_ms INTEGER NOT NULL` (epoch milliseconds, exact integer comparison). Row size drops ~3.2x; the covering index `idx_probes_cov(sk, ts_ms, rtt_ms, manual)` serves the stats/guard reads index-only. `sensors` gains the surrogate `sk INTEGER` (unique, auto-assigned by the `sensors_sk_autogen` trigger on `NEW.sk IS NULL`, so hand-inserted rows and the API path share one numbering). The swap is a SINGLE ATOMIC migration (14) — no dual-write transition: build `probes_new` with the new layout, copy rows in a `sk` join, rename, index, `PRAGMA user_version = 14` in the same transaction; a mid-migration death leaves the old table intact (the rename never half-happens). Migration 13 (the covering index on the legacy columns) gains a shape guard (`pragma_table_info('probes')` ts-column check → no-op on the new layout) so replay on a migrated DB is a no-op, and the legacy index's CREATE left the base DDL (fresh installs run 1→14 and the swap happens on the empty table; a post-swap boot must not recreate an index on columns that no longer exist).
**Boundary contract (unchanged):** the API still emits the exact same `ts` string format — `ts_ms` is converted to RFC3339Nano at the response boundary, so the frontend is untouched. The EVENTS table stays TEXT by decision (small, sparse, lexicographic order already pinned by TestFix_TS_FixedWidthLexicographicEqualsChronological); events' purge branch keys on the TEXT id, probes' on sk (`Store.SensorKeys` returns both).
**Why:** at the declared fleet this is the scaling bottleneck the external review sized: every 5s poll, per sensor, per tab, ~90 timestamps cross the wire and every stats/guard/purge read compares 33-byte strings. The TEXT UUID FK also made every probes row carry the full 36-byte id that the covering index then duplicated. INTEGER keys make the hot path (probe insert, stats window, retention sweep, cascade delete) exact-integer work on a smaller row, and the `sk` FK gives the delete cascade a key it can walk without a per-row UUID lookup.
**Ripple:** `sensorConfig` carries `sk` (syncSensors fills it from the sensor list; tests that hand-build a config for a DB-seeded sensor read it via the `sensorSK` helper — a zero sk writes an FK-orphan row and reads nothing, which is how this class of miss shows up). `warmStats` bridges `sk`→id with a `skByID` map built from the same sensor list. `purgeOld`'s tail-exemption subquery keys on sk. `recentFromDB` (the cold-cache status fallback) takes sk. The DELETE cascade's footprint checks capture the sk BEFORE the row delete (post-delete the id→sk subquery is empty).
**Pinned by:** `internal/store/probes_int_schema_test.go` — fresh-DB shape (sk + trigger + idx_probes_cov present, legacy index absent), the v13→v14 upgrade is row-exact (a populated legacy table migrates with every value preserved, ids remapped through the join), an unparseable legacy ts REFUSES the migration (no silent data loss — the old table survives, the boot fails loudly), and a replay on the new layout is a no-op. Plus the converted suite: purge tail/cutoff arithmetic on epoch-ms (with the 24h-boundary seed made unambiguous — a row at exactly 24h is past the cutoff by the time the purge computes it, and purging it is correct), warmStats tail rebuild after purge, the delete-cascade footprint checks, and the SQL-parity reference re-expressed in sk/ts_ms with the finding-#4 rounding mirrored. Sabotage-verified per the batch protocol.

## detached-doc-comments (api.go, api_middleware.go, api_sensors.go, api_settings.go, auth.go, listener.go, ping.go, update_windows.go, doc_comment_pin_test.go, 2026-11-24)
**Decision:** external review finding #5 VERDICT valid, fix taken as proposed. 52 doc comments sat a blank line away from their declarations. The Go parser associates a comment with a declaration only when they are adjacent — a blank line sets `Decl.Doc == nil`, and go doc / gopls hover read exactly that field, so the text was invisible to every tool while still visible to a human scrolling. The reviewer's per-file counts matched the AST audit exactly (api_sensors.go 25, api_settings.go 11, api_middleware.go 8, api.go 5). The fix: 46 attached in place (blank line removed); 6 RELOCATED to the correct declaration — leftovers of the api.go four-way split, where the declaration moved file and the doc did not (or vice versa): maxRequestBytes (api.go → api_middleware.go const), parseAllowedHosts (api.go → api_middleware.go), authGate, 19 lines (api.go → api_middleware.go), cachedSensorCount (api.go → api_sensors.go method), minIntervalS (api_middleware.go → api_sensors.go const), webhookMasked (api_sensors.go → api_settings.go func). The last is the actively-wrong case the finding named (it described webhookMasked while sitting above normalizeProbeType); cachedSensorCount was a sixth the finding did not list — its text sat above handleStatic. Two section-header prose blocks (the auth.go auth-section essay, the update_windows.go VSA/SCM-restart essay) attach to their section's first declaration, the same treatment as the listener.go and ping.go section headers. All-dash dividers — bare, labeled (`// ---- label ----`), or a label framed by dash rules — are intentional labels, not doc comments: left in place and exempt from the pin. A trailing comment on a code line (ping.go's `// 28 bytes, <= payloadSize`) is not a doc comment and is not a violation.
**Why:** detached docs mislead navigation — hover on the real symbol shows nothing while the text floats above the wrong one — and the breakage is silent: gofmt, go vet and the compiler all accept the detached shape, so nothing ever flags a new one. The CI-level source scan is the only guard that exists.
**Pinned by:** `doc_comment_pin_test.go` — `TestDocCommentsAttachedToDeclarations`: walks every non-test .go file with go/ast and fails on any comment group separated from the next top-level declaration (or any code) by ≥1 blank line; exempt: `//go:build` tags (the blank line after a build tag is REQUIRED), dash-rule dividers, trailing comments on code lines; positive control asserts ≥40 attached docs are still seen so a broken scanner cannot pass vacuously. It is an ordinary Go test, so the existing CI `go test` step runs it — no workflow change. Sabotage-verified: re-inserting the blank line between the maxRequestBytes doc and its const reds the pin (message names the file:line); tree MD5-verified restored. `GOOS=windows GOARCH=amd64 go build` green (update_windows.go touched).

## comment-history-relocation (auth.go 4-way split, comment diet, nits-test regroup, maintainability_pin_test.go, 2026-11-24)
**Decision:** external review finding #6 VERDICT valid: comment volume plus file size were the standing maintainability drag (auth.go 2503 lines, 45% comment at the 2026-11-11 audit; the 69 comment groups ≥10 lines were essays, not contracts). Scope A+B+C, one behavior-neutral commit: (A) comment diet — every one of the 69 groups in auth*.go / alerts.go / api_sensors.go rewritten to invariant + one-clause why + `History: docs/DECISIONS.md → <anchor>` pointer, incident narrative relocated to its DECISIONS entry (the pointers resolve to the 2026-11-11/11-18/11-20/11-24 entries where the full narrative already lives); (B) auth.go split 4 ways inside `package main` — auth.go 740 (AuthState + user CRUD + KDF), auth_throttle.go 563 (throttle/lockout/IP tracking), auth_session.go 327 (session lifecycle + cookies), auth_handlers.go 679 (HTTP handlers + middleware) — pure moves, zero import/DI changes, all test seams survive untouched; (C) the three nits_<date>_test.go incident files dissolved — 11 tests moved into their 8 feature test files (http, cert_freshness, graph, retry_after, ping, tcp, validation_bounds, webhook), so tests group by feature, not by review batch.
**Why (split, not the 2026-11-11 package split):** `structure-and-comment-density` REJECTED `internal/{probe,auth,alert,api}` + constructor DI because the package vars ARE the test seams and the harness would have to be rewritten for zero behavior change. A same-package file split is a different move: no boundary ceremony, no DI surface, no test-file change from the split itself — it only makes a 2503-line file navigable. The rejection stands for package boundaries; it was never a bar on file organization.
**Pin calibration (maintainability_pin_test.go, 3 guards):** (1) no top-level function in the 6 dieted files may carry more comment lines than code lines with ≥30 comment lines on a function with ≥20 code lines — doc comments COUNT (the first version started the span at `fd.Pos()`, excluding `fd.Doc`, and a 25-line doc bloat on stormSummaryMarkdown sailed through the sabotage test — the span now starts at `fd.Doc.Pos()`); the ≥30/≥20 floors are deliberate: a 12-line helper with a 23-line doc is dense-but-fine style, an essay burying 60 lines of logic is not — the first ≥20-only threshold tripped 3 of those small helpers and forced gutting of genuinely useful docs; (2) the 4 auth files exist with their anchor symbols (throttleKey/ClientIP/beginAttempt, CreateSession/CookieRenewalDue, handleAuthLogin/requireAdmin) and auth.go stays <1200 lines; (3) no nits_<date>_test.go reappears.
**Post-move state (gate box, doc-inclusive):** handleAuthLogin 63c/63k, reauthCurrentPassword 36c/36k, ClientIP 28c/28k, alertTarget 19c/20k; file comment ratios auth.go 0.25, auth_throttle 0.23, auth_session 0.22, auth_handlers 0.63, alerts 0.20, api_sensors 0.33 (was 1.37 / 0.50 / 0.95 on the three named files).
**Gate:** gofmt clean, build + vet OK, 3 pin tests PASS, sabotage-verified both ways (35-line doc bloat on setAlertState reds the ratio pin; clean tree green), targeted -race suite ok 234.992s on esthero-zentest (Go 1.27.4). Full -race suite at batch end per protocol. No release, tag, or zentest:9299 deploy — the user cuts releases.

## review-nits-20261124 (api_sensors.go, sensor_spec.go, README.md, validation_bounds_test.go, 2026-11-24)
**Decision:** external review follow-up nits, four in one behavior-preserving commit. (1) `handleSensors` GET loop recomputed the redaction decision per sensor via `viewerTarget` (sessionFrom + IsAdmin per row) — the decision is per REQUEST (auth enabled AND caller not admin, invariant across the loop), so it is now computed once above the loop and applied as `if redact { v.Target = alertTarget(v.Target) }`; `viewerTarget` stays for the single-sensor path, which is one call per request. (2) `sensorSpec.validate()` ran `validateCrossField()` BEFORE the per-field range loop, so interval_s=4 + timeout_ms=4500 reported "timeout_ms must not exceed interval_s*1000" instead of "interval_s must be 5-3600", and a huge interval_s overflowed the `IntervalS*1000` / `DownAfter*IntervalS` products before the range check could reject them — the range loop now runs first; the PATCH path is untouched (it calls validateCrossField directly on DB-overlay values that are already in range). (3) README "Sessions last 30 days" → "renew on activity (7-day sliding window) with a 30-day absolute cap" (authSessionTTL 7d / authSessionMaxAge 30d). (4) README alerts line "Google Chat + Discord" → "Google Chat, Discord, Telegram, SMTP" (telegram.go and smtp.go are first-class destinations).
**Why:** (1) is N redundant session lookups per poll-sized response for a value that cannot change mid-loop; (2) is a message-ordering contract — the first error a user sees must name the field that is actually out of range, and a cross-field comparison against an out-of-range input is meaningless by construction; (3)+(4) are doc-vs-code drift the kind that trains readers to distrust the README.
**Pinned by:** `validation_bounds_test.go` — `TestValidateRangeBeforeCrossField` (interval_s=4 + timeout_ms=4500 → the exact interval range error, not the timeout rule; interval_s=1e18 → the range error before any cross-field product overflows; positive control 5s+6000ms still gets the cross-field message). Nit (1) is a behavior-neutral hoist — no dedicated pin, the full -race suite is the behavioral guard. Nits (3)+(4) are README-only.
**Gate:** gofmt clean, build + vet OK, order pin + targeted sensor/validation suite on esthero-zentest (Go 1.27.4), sabotage-verified (restoring cross-field-first reds the pin). Full -race suite at batch end per protocol. No release, tag, or zentest:9299 deploy — the user cuts releases.

## windows-update-staged (update_windows.go, update.go, update_api.go, web/app.js, main_windows.go, installer/pulsemon.iss, update_api_test.go, windows_service_test.go, windows_service_win_test.go, 2026-11-24)
**Decision:** the Windows in-dashboard self-update no longer restarts the service — it STAGES the update and hands the operator the restart. `POST /api/update` keeps the verified swap half (download → ed25519 + SHA-256 verify → atomic rename with the .prev rollback copy), then answers `200 {status:"installed", hint}` with an operator instruction (services.msc → Pulsemon → Restart service, or `Restart-Service Pulsemon`) instead of `202 {status:"restarting"}` + a self-restart. The in-service restart machinery is deleted: `selfRestartViaRecoveryFn` (clean drain + `os.Exit(updateExitCode=3)` for the SCM recovery action), `recoveryActionConfiguredFn` (the registry pre-flight), the `updateExitCode` const, and the `isWindowsService()` branch in `performRestartWindows`. Two new shared seams carry the contract: `apiAutoRestart` (default true; the Windows init sets it false — the systemd path is untouched) and `restartServiceHint` (the operator-facing restart instruction, Windows-override names the service and both restart paths). What survives: (1) the installer's `sc failure ... actions= restart/...` recovery action, now a CRASH safety net only (a crashed service comes back automatically; it is NOT part of the update flow — the old "load-bearing for the self-update" framing is retired); (2) the external restart path — an elevated console `pulsemon update --restart` / `pulsemon restart` / the rollback watchdog still does the synchronous stop→start through the native SCM (a High-integrity token passes the check); (3) the `GrantServiceSelfAccess` ACE, now documented for what it actually buys (the VSA's QUERY rights for the state checks — the DACL-granted START/STOP were run-time denied by mandatory integrity all along); (4) the 45s `wdOldProcTimeout` (the Windows clean drain is ~30s + SCM grace — it serves the external update's watchdog and the rollback watchdog, not the retired in-service exit).
**Why (supersedes the in-service restart half of windows-recovery-restart):** the VSA's integrity wall (probed live twice — 2026-11-23 and 2026-11-24, from the service's own token: the DACL grants START|STOP, the open is access-denied) means the process that starts the service must not be the VSA. The recovery-action handoff (deliberate 7031 → services.exe restart) was the architecture that satisfied that — but it never completed cleanly in live testing: the 2026-11-24 in-dashboard update on zendev reached the swap and the 202, then the process hung between the response and the guaranteed `os.Exit(3)` (the only unbounded call in that window was the watchdog's `CreateProcess`), with the UI's 60s poll window shorter than the ~30–75s happy path and zero milestone logging to triage with. The user's call (2026-11-24): "it doesn't make sense for us to implement the self update on windows — roll it back to have the user restart the service themselves." A staged update with a human restart is deterministic, observable (the dashboard says exactly what to do), has zero moving parts to fail in the dark, and keeps every safety net as operator tooling: the .prev rollback, the .preupdate DB backup, the crash-recovery action, and the full auto-restart + healthz-verified watchdog for the elevated console path.
**Pinned by:** `update_api_test.go` — `TestUpdateStagedWhenAutoRestartDisabled` (live-service update with `apiAutoRestart=false` → 200/`installed` + hint, binary swapped, ZERO restarts issued, no 202; the Linux `TestUpdateHappyPathRestart` 202/restarting path is the positive control and stays green). `windows_service_test.go` — `TestWindowsRecoveryRestart` rewritten as `TestWindowsUpdateStaged` (source-level, Linux-gate-runnable: `selfRestartViaRecoveryFn` / `recoveryActionConfiguredFn` / `updateExitCode` / `s.Start()` / `__restart-helper` are ABSENT from update_windows.go code; `apiAutoRestart = false` and `restartWindowsServiceFn()` present; the .iss still carries the `sc failure`/`restart/` recovery action as the crash net; the watchdog's `verifySensorsIntactWatchdog` intact). `windows_service_win_test.go` (windows-tagged, compiles on the gate box via `GOOS=windows go vet`, runs on the Windows QA box) — `TestPerformRestartWindowsServiceBranch` + `TestSelfRestartRefusesWithoutRecovery` replaced by `TestPerformRestartWindowsExternalOnly` (the only remaining branch is the synchronous stop→start) and `TestWindowsUpdateStagedSeams` (`apiAutoRestart` false + hint names the Pulsemon service). Sabotage-verified: restoring the old `if d == ""` condition (dropping `!apiAutoRestart`) reds `TestUpdateStagedWhenAutoRestartDisabled` (202 instead of 200).
**Gate:** gofmt clean, `go vet . ./internal/store` OK, targeted `-race` suite (`TestUpdate|TestWindows`) ok, `GOOS=windows GOARCH=amd64 go build .` OK (20MB exe), sabotage red/green, full `-race` suite at batch end on esthero-zentest (Go 1.27.4). Known pre-existing (not this batch): `GOOS=windows go vet .` fails on `update_restore_test.go`'s `syscall.Stat_t` (POSIX-only, no build tag) — present on pristine main. No release, tag, or deploy — the user cuts releases; the staged flow ships with the next Windows release and needs no zendev action (the v1.1.22 service stays as-is until then).

## install-pubkeys-proto-argv (install.sh, install_proto_pin_test.go, 2026-11-25)

**Decision:** external review CRITICAL-1, fix taken as proposed. The `PUBKEYS_PROTO` value in install.sh is now `--proto =https --tlsv1.2` — no shell quotes. The old value `"--proto '=https' --tlsv1.2"` embedded literal single quotes inside a double-quoted scalar; quote removal applies only to quotes in the source text, never to expansion results, so the unquoted `$PUBKEYS_PROTO` expansion passed `'=https'` (quotes and all) to curl as one argument. `=https` carries no glob or shell metacharacters, so the unquoted expansion splits into exactly the three intended argv tokens. The case-arm shape is unchanged: https:// URLs only, the `PULSEMON_PUBKEYS_URL` file:// test hook stays unrestricted.
**Why:** curl received the 8-char arg `'=https'` and exited 2 (`unrecognized protocol ''=https''`), so EVERY production (https) bare-Linux install aborted with "could not fetch release_pubkeys from main". The release-sig harness serves `file://`, so the https case arm never executed — the defect shipped green.
**Pinned by:** `TestInstallPubkeysProtoPin` — structural checks (the case arm sets the quote-free token string; the quoted shape must be ABSENT; the curl consumes `$PUBKEYS_PROTO`) plus a new behavioral argv pin: the real block is extracted verbatim from install.sh (not a copy), run under bash with a stub curl that dumps its argv NUL-separated, and the exact argv is asserted for an https:// URL (`-sfL --proto =https --tlsv1.2 -o … <url>`, and no token may contain a quote) and for a file:// URL (no proto flags — positive control against the pin regressing to a hardcoded value outside the case arm). Sabotage-verified: v1 old quoted shape → pin fails (the argv dump shows the literal `'=https'` token); v2 pin hardcoded before the case arm → pin fails. install.sh MD5-verified restored.
**Note (pre-existing, not this change):** `scripts/release-sig-harness.sh`'s `valid-sig` case is red on main independent of this fix — the `.sig` fetch's inline `--proto '=https'` refuses the harness's `file://` BASE (`Protocol file not allowed`, rc=1 verified live on the gate box). Present on pristine main (verified by harness run on the unmodified tree); reported to the user, out of scope for CRITICAL-1.

## preupdate-vacuum-into-replace (internal/store/store.go, update.go, update_api.go, 2026-11-25)

**Decision:** external review CRITICAL-2, all four sub-defects fixed. (1) `Store.BackupTo` now writes `VACUUM INTO` to a fresh sibling `dst.tmp` and atomically renames it into place (chmod 0600). SQLite's `VACUUM INTO` REFUSES an existing target file ("output file already exists"), so the old direct-`VACUUM INTO ?` form made the second (and every later) pre-update backup fail, leaving the FIRST — possibly months-old — snapshot on disk. The tmp+rename shape makes the Nth backup succeed and REPLACE the stale snapshot with current data, and a VACUUM that dies mid-flight leaves only a `.tmp` orphan, never a truncated `dst`. (2) `backupDatabasePreUpdate` now takes the in-process store: the API update path (`handleUpdate`) passes `s.db` — it runs INSIDE the server, so a second connection pool on the same file was the defect; the CLI path passes `nil` (it has no in-process store) and opens one short-lived pool. (3) `verifySensorsIntactWatchdog` opens the backup with the new `store.NewStoreReadOnly` (a `file:`-URI DSN with `mode=ro`, no pragmas) instead of the read-write `store.NewStore`. The read-write open set `journal_mode(WAL)` and created `-wal`/`-shm` sidecars beside the snapshot (stranding uncheckpointed frames if the process died mid-open) and made the safety copy writable. The `file:` URI form is load-bearing: modernc.org/sqlite strips the query from non-URI DSNs and hardcodes `READWRITE|CREATE` — a bare `path?mode=ro` opens WRITABLE (probe-verified 2026-11-25), while a `file:` DSN passes `mode=ro` to SQLite under `SQLITE_OPEN_URI`. (4) The watchdog now REMOVES the pre-update backup after a verified (sensors-intact) update — a surviving snapshot is the stale-baseline trap: months of legitimate sensor deletion later, a future watchdog comparing the lower live count against the months-old backup would declare data loss and restore it, wiping the intervening months of config, users and history.
**Why:** the old chain failed closed in the WRONG direction. Update #2's `VACUUM INTO` failed with only a logged warning, so a months-old snapshot persisted; after the operator legitimately deleted sensors, the post-restart verifier saw `live < want` and OVERWROTE the live DB with the stale snapshot — the exact destructive false-positive the finding describes. A read-write open of the backup risked corrupting the one safety copy the whole rollback design depends on.
**Pinned by:** `TestStoreBackupToReplacesExistingSnapshot` (2nd `BackupTo` over an existing dst succeeds and the snapshot carries the NEW 2-sensor state, not the stale 3; no `.tmp` orphan), `TestStoreReadOnlyRefusesWritesAndSidecars` (read-only open reads, REFUSES a write, creates no `-wal`/`-shm`), `TestStoreReadOnlyMissingFileIsAnError` (`mode=ro` must not create a missing file), `TestBackupDatabasePreUpdateSecondUpdateReplacesStaleBackup` (the pre-update path end-to-end: update #2's backup carries the current count), `TestVerifySensorsIntactRemovesVerifiedBackup` (verified update removes the backup), `TestVerifySensorsDataLossKeepsBackup` (POSITIVE CONTROL: the data-loss path restores FROM the backup and must keep it), `TestVerifySensorsOpensBackupReadOnly` (source-shape: the watchdog consumes `NewStoreReadOnly`, not `NewStore` — a post-run directory check CANNOT distinguish the two shapes because the watchdog's own `Close()` checkpoints and removes the WAL sidecars, so the shape is pinned at the call site), and the tightened `TestSelfUpdateBacksUpDBBeforeSwap` (per-path store arg: `s.db` in `update_api.go`, `nil` in `update.go`). The `setupVerifyFixture` fixture now builds the backup via `store.BackupTo` (the real `VACUUM INTO` shape — a delete-journal snapshot) instead of byte-copying a WAL file, which is what let the read-only pin pass for the wrong reason. Sabotage-verified: all four vectors individually reverted → each pin fails (v1 fails on the genuine `output file already exists` signal); tree MD5-verified restored.
**Gate:** gofmt clean, `go vet . ./internal/store` OK, `GOOS=windows GOARCH=amd64 go build` OK, targeted `-race` suites (store + main) ok on esthero-zentest (Go 1.27.4). Full `-race` suite at batch end per protocol. No release, tag, or deploy — the user cuts releases.

## watchdog-rollback-bus (update.go, update_windows.go, update_watchdog_bus_test.go, update_restart_test.go, update_watchdog_verify_test.go, update_test.go, watchdog_restart_guard_test.go, windows_service_test.go, 2026-11-25)

**Decision:** external review CRITICAL-3, all five sub-defects fixed. The watchdog's post-rollback restart now runs on the AUTHORITATIVE bus captured at spawn time, not a re-detection at rollback time. (1) `buildWatchdogCommand` puts the bus into the watchdog argv (`--bus <bus>`); before it was used only for the `systemd-run` prefix and then discarded. (2) The `pulsemon update watchdog` CLI parses and validates `--bus` via `validRestartBus` (user/system/windows-service) — a garbage value is refused at parse time instead of being issued to systemctl for a unit that is not there. (3) `runWatchdog(prev, dst, bus, …)` unhealthy path: after the binary rollback the restart goes out on the spawn-time bus. The old detect-only shape (`if d := detectRestart(); d != ""`) skipped the restart entirely, because a broken binary has crashed the service into activating/failed, where `systemctl is-active` exits non-zero (it exits 0 only when active) and detection reports "". (4) `verifySensorsIntactWatchdog(db, prev, dst, bus)` sensor-loss path: the service is STOPPED by `stopForRestoreFn` before the restore, so the old `performRestart(detectRestart())` re-detected "" and ran bare `systemctl restart pulsemon` on the SYSTEM bus (no `--user`) — failing on every install.sh user-bus deployment. It now restarts on the spawn-time bus; when NO bus is known at all (none passed and none detected) it logs the existing manual-recovery instructions instead of firing a blind system-bus restart. (5) `runRestart` issues `systemctl [--user] reset-failed pulsemon` on the SAME bus before the restart — best effort (a reset failure does not block the restart): a crash-looped broken binary trips StartLimitBurst, and until the failed state is cleared the restart fails with "start-limit-hit" no matter how often it is retried. (6) Windows: `stopWindowsServiceFn` treats `windows.ERROR_SERVICE_NOT_ACTIVE` (1062) as success — an already-stopped service IS the goal state of a stop, and the old error return made every restart of a stopped service (the watchdog's post-rollback restart, an operator `pulsemon restart` after a crash) die at the stop step before the start ever ran.
**Windows self-restart boundary (the user's concern, documented as designed):** on Windows the in-dashboard update is staged (`apiAutoRestart = false`) and never spawns a watchdog — the only Windows watchdog caller is an external elevated process, where stop→start passes the SCM check (High-integrity token). A VSA-spawned watchdog cannot start the service (mandatory-integrity denial, probed live 2026-11-23/24 from the service's own token) — and no such path exists in the code. The 1062 fix is still required: it is what makes stop→start work against an already-stopped service for the external callers that DO exist.
**Why:** the rollback safety net restored the old binary/DB and then left the monitor permanently offline: the unhealthy path skipped the restart (exit 0, no "service restarted" line), the sensor-loss path issued the restart on the wrong bus, a start-limit-hit unit was un-restartable by retry, and on Windows the restart died at the stop step.
**Pinned by:** `update_watchdog_bus_test.go` — `TestBuildWatchdogCommandPassesBus` (exact argv for plain AND systemd-run scope shapes, user/system/empty bus), `TestRunRestartResetsFailedBeforeRestart` (fake-systemctl argv log: `reset-failed` precedes `restart`, on the same bus, both buses), `TestRunRestartResetFailedFailureIsBestEffort` (reset exits 1 → the restart still runs, `runRestart` nil), `TestRunWatchdogUnhealthyRestartsWithSpawnBus` (core: detection reports "" — the crashed service — yet the restart goes out on the spawn-time `user` bus; rollback verified), `TestRunWatchdogUnhealthyNoBusNoRestart` (POSITIVE CONTROL: no bus + nothing detectable → roll back, no restart — the old safe default), `TestVerifySensorsRestartsWithSpawnBus` (core: post-stop detection reports "" and the post-restore restart goes out on the spawn-time bus, not the system bus), `TestWatchdogCLIRejectsUnknownBus` + `TestWatchdogCLIAcceptsKnownBus` (parse-time validation; the accept case reaches the old-pid guard, proving the bus sailed through parsing). `windows_service_test.go` — `TestWindowsStopToleratesAlreadyStopped` (source-shape: the 1062 tolerance is present in update_windows.go, which never compiles on the Linux gate) and the tightened `TestWindowsUpdateStaged` pin (the healthy-path call is now `verifySensorsIntactWatchdog(db, prev, dst, bus)`). Existing call sites updated to the new signatures: the 9 verify tests pass `""` (falling back to the harness's `test-bus` detection) and the runWatchdog tests pass `""`. Sabotage-verified: all five vectors individually reverted to the exact old shape → each pin fails (v3 fails on the genuine argv signal `calls = [restart pulsemon], want [reset-failed pulsemon, restart pulsemon]`); tree MD5-verified restored.
**Gate:** gofmt clean (box Go 1.27.4 — a doc-list `//` separator in the buildWatchdogCommand comment, synced back), `go vet . ./internal/store` OK, `GOOS=windows GOARCH=amd64 go build .` OK, targeted `-race` suite (all new pins + the full adjacent watchdog/restart/verify surface) green on esthero-zentest. Full `-race` suite at batch end per protocol. No release, tag, or deploy — the user cuts releases.

## auth-torn-read-window (api_middleware.go, auth.go, auth_torn_read_test.go, 2026-11-25)

**Decision:** external review CRITICAL-4, fixed at BOTH layers — the finding's proposed fix plus a gate-side guard the proposal leaves open. (1) `Bootstrapped()` now refreshes the `Enabled()` cache at the FIRST in-process latch (`if !a.bootstrapped.Swap(true) { a.refreshEnabledNow() }` — the finding's exact shape; `Swap` not `Store` so the refresh fires exactly once, since the latch ratchets true and never moves). This heals the cache at the source, for every consumer (gate, `requireAuth`/`requireAdmin`, the auth-status endpoint, the main.go startup warning), the moment the process first sees `auth_bootstrapped=1`. (2) NEW: the gate's (Enabled=false, Bootstrapped=true) branch settles the ambiguity with a fresh count via the new `AuthState.EnabledNow()` (force-refresh, returns the fresh value, does NOT clear adminCache — a gate read is not a mutation site) BEFORE opening the dashboard: a real user exists → the request falls through to the authenticated path (401 without a session) instead of the "operator disabled auth" open branch. (3) The fresh-install branch moved into an `else` so the fall-through is the only exit from the bootstrapped case. The extra COUNT lands only in the rare branch (the deliberately-open auth-off state), never on the hot authenticated path.
**Why:** the CLI `auth-user add` commits the user row and `auth_bootstrapped='1'` in one transaction, while `Enabled()` caches `false` for `enabledTTL` (2s) and `Bootstrapped()` queries live until it latches. For up to 2s after the commit, the pair (Enabled=false, Bootstrapped=true) reads as "operator intentionally disabled auth": the gate forwards every LAN request to `s.mux` unauthenticated, and `requireAuth`/`requireAdmin` (which enforce only `if s.auth.Enabled() && …`) stand down on the SAME stale cache — full admin access (sensor CRUD, settings, TLS upload, history wipes) at the exact moment authentication is being enabled. The finding's latch-refresh alone closes the window for every consumer EXCEPT the first request that performs the latch: the gate evaluates `Enabled()` (stale) BEFORE `Bootstrapped()` (latch), so that one request still takes the open branch — and a tight-polling LAN attacker (or the dashboard's own 5s poll landing in the window) can be that request. The re-enable variant makes the gate guard the ONLY defense: on an older install the latch fired at boot (zero users), so a CLI re-add triggers no latch refresh at all. Both layers are needed; each pin isolates its layer.
**Pinned by:** `auth_torn_read_test.go` — `TestBootstrappedLatchRefreshesEnabledCache` (latch with a committed user → `Enabled()` true immediately, counting seam proves the refresh), `TestBootstrappedLatchRefreshesExactlyOnce` (no per-request COUNT after the latch), `TestEnabledNowBypassesTheTTL` (force refresh bypasses the TTL while `Enabled()` keeps serving the cache), `TestGateTornWindowIsNotOpen` (end-to-end FIRST-USER torn state: sessionless data read → 401, not open), `TestGateTornReEnableIsNotOpen` (end-to-end RE-ENABLE torn state, latch already latched at boot: sessionless data read → 401 — this pin isolates the gate guard, because no latch refresh fires in this scenario), `TestGateRealAuthOffStaysOpen` (POSITIVE CONTROL: genuine auth-off state, fresh count 0 → 200, the guard must not over-fire and lock a trusted-LAN install). Sabotage-verified: v1 old latch shape (Store, no refresh) → `TestBootstrappedLatchRefreshesEnabledCache` red (`counts = 1, want 2`); v2 gate guard removed → `TestGateTornReEnableIsNotOpen` red (200, want 401); v3 guard reading the cached `Enabled()` → red (200, want 401). Tree MD5-verified restored.
**Gate:** gofmt clean, `go vet . ./internal/store` OK, targeted `-race` suite (all 6 new pins + the full auth/gate/off-rebinding/setup surface) green on esthero-zentest (Go 1.27.4). Full `-race` suite at batch end per protocol. No release, tag, or deploy — the user cuts releases.
