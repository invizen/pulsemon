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
arm64 asset. **Transition:** `verifyReleaseSignature` checks the manifest
first and falls back to the legacy raw-bytes form (the messages differ, so
a signature verifies under at most one form — unambiguous). The pipeline
signs with `RELEASE_SIGN_FORMAT=legacy` (the default is `manifest`) for
ONE release only — the first one carrying the manifest verifier — so
v0.4.4-era clients can install it; the next cut reverts to the default.

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

**Key custody:** the private key is the release-signing SECRET — it lives on
the trusted release host (a 600-perm file) and, for the Windows CI path, as
the `RELEASE_SIGNING_KEY` GitHub Actions secret. It is NEVER committed; only
`release_pubkeys` (the pubkeys) is committed. Maintainer tools:
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
LegacyFallback,ManifestNotLegacy,ManifestExactBytes}` and the end-to-end
`TestVerifyDownloadedAsset_ManifestReplay` (a v0.3.11 signature served as
v9.9.9 is refused); `update_downgrade_test.go` — the floor:
`TestDowngradeGuard` (decision table), `TestBumpMaxVersionSeen` (monotonic,
dev-safe), `TestRunUpdate_{RefusesDowngradeBelowMaxSeen,
AllowDowngradePassesGuard}` (CLI end-to-end) and
`TestUpdate_{RefusesDowngradeBelowMaxSeen,
ExplicitPinBypassesDowngradeGuard}` (dashboard 409 / pin opt-out). A
sabotage that drops the authenticity gate makes `_Unsigned` and `_ForeignSig`
fail; one that drops the manifest binding makes `_ManifestReplayWrongTag`
fail; one that drops the floor makes `_RefusesDowngradeBelowMaxSeen` fail.

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

## sensor-delete-alert-state (alerts.go `setAlertState`, store.go schema, 2026-11-10)
**Decision:** `setAlertState` now uses the reviewer's guarded upsert (`INSERT ... SELECT id FROM sensors WHERE id = ? ON CONFLICT ...`): for a sensor deleted concurrently, the SELECT yields no row and nothing is written, so alert state can never be resurrected for a deleted sensor. The DELETE handler is unchanged — its single `DELETE FROM sensors` already cascades.
**Why:** the finding's two orphan-row mechanisms were both already closed: (1) the schema declares `ON DELETE CASCADE` on probes, events, sensor_tags AND alert_state, and `store.NewStore`'s DSN enables `foreign_keys(1)` on every connection, so the delete cleans up all child rows atomically (verified — no missing-CASCADE bug); (2) an in-flight `setAlertState` on a deleted sensor failed at the FK check and the `_, _ =` swallowed the error — no resurrection, but the invariant was IMPLICIT (depended on the DSN pragma) and SILENT (error discarded). The guard makes it explicit and self-contained: it holds even on a bare FK-OFF connection, and the statement is atomic (no delete/upsert TOCTOU). The third sub-claim — the per-sensor alertGateConsumer drains ≤8 queued + 1 in-flight alerts for a deleted sensor — is TRUE and accepted by design (documented at `alertGateConsumer`/`Remove`): bounded, one-shot, self-reaping on `alertGateIdle`, no goroutine leak; the alerts were legitimately triggered pre-deletion, and delivering them mid-storm is arguably correct.
**Pinned by:** `TestSensorDeleteCascadesAlertState` (delete → probes/events/sensor_tags/alert_state all 0 rows), `TestSetAlertStateDeletedSensorNoResurrection` (bare `sql.Open` connection, FK OFF: the child row survives the delete, and `setAlertState` leaves that row UNTOUCHED — the old plain INSERT would have updated it via ON CONFLICT; positive control: a live sensor upserts insert-then-update exactly as before). Sabotage-verified: restoring the plain `VALUES` INSERT fails the resurrection test on the FK-OFF connection.

## redirect-ssrf-dns-rebinding (http.go `redirectTargetAllowed` / `CheckRedirect`, 2026-11-05)
**Decision:** `redirectTargetAllowed` now returns the checked IP alongside the error. `CheckRedirect` rewrites the redirect request's URL to that IP (`req.URL.Host = ip:port`, `req.Host = origHostname`), so the transport dials the checked IP directly — no re-resolution. The initial target is NOT rewritten (operator's own sensor, admin privilege by design); only cross-host redirect hops are pinned.
**Why:** the old check-then-dial had a TOCTOU window: `redirectTargetAllowed` resolved the hostname and checked the IPs, then the transport resolved the SAME hostname again when dialing. A DNS-rebinding attacker (LAN DNS control) could return a public IP at check time (allowed) and a loopback/link-local IP at dial time (the check never saw it). The fix is the same pattern `webhook.go`'s `dialChecked` already uses — validate the IP at dial time by pinning the dial to the checked address. The `Host` header keeps the original hostname for virtual hosting; the SNI becomes the IP (blanked by RFC 6066 §3 for IP literals), which is correct for IP-literal cert verification.
**Pinned by:** `TestProbeHTTPRedirectRebindingClosed` (`review_fixes_test.go`) — a fake DNS-over-UDP responder returns 203.0.113.1 on the first lookup (check passes) and 127.0.0.1 on the second (rebinding); a loopback stand-in server on the rebinding port must NOT receive the request. Sabotage-verified: disabling the URL rewrite (`if false`) makes the probe dial 127.0.0.1 and mark up (the rebinding server answers 200).

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
