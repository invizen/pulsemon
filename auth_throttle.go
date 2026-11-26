// auth_throttle.go — login throttling and lockout: per-IP + per-username
// failure budgets, the known-good exemption, sweep/hard-cap bounding, and
// the IP attribution (trusted proxies / XFF) those budgets are keyed on.
// History: docs/DECISIONS.md -> login-throttle-per-username,
// login-throttle-known-good-exemption, knowngood-bound
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// parseTrustedProxies turns a comma-separated list of CIDRs (or bare IPs,
// which become /32 / /128) into matchable networks. Entries that don't parse
// are dropped with a warning rather than failing startup — a typo must not
// take the dashboard down, it just means that entry isn't trusted.
func parseTrustedProxies(raw string) []*net.IPNet {
	var out []*net.IPNet
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var cidr string
		if strings.Contains(part, "/") {
			cidr = part
		} else if ip := net.ParseIP(part); ip != nil {
			ones := 32
			if ip.To4() == nil {
				ones = 128
			}
			cidr = fmt.Sprintf("%s/%d", ip.String(), ones)
		} else {
			log.Printf("auth: PULSEMON_TRUSTED_PROXIES: ignoring unparseable entry %q", part)
			continue
		}
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			out = append(out, n)
		} else {
			log.Printf("auth: PULSEMON_TRUSTED_PROXIES: ignoring invalid CIDR %q: %v", part, err)
		}
	}
	return out
}

// purgeUserThrottle drops every per-username throttle entry for username —
// userFails, userLock, userHour, and the (username, ip) knownGood
// exemptions (keyed username\x00ip; the \x00 makes the prefix
// collision-free since usernames match usernameRe). RemoveUser calls it
// after the account row is gone: without the purge a RE-CREATED username
// inherits the old account's IP exemptions and failure history (a
// recreated account starts already-locked by the old account's 30/hr debt).
// History: docs/DECISIONS.md → throttle-edge-cases
func (a *AuthState) purgeUserThrottle(username string) {
	a.loginThrottle.Lock()
	defer a.loginThrottle.Unlock()
	delete(a.loginThrottle.userFails, username)
	delete(a.loginThrottle.userLock, username)
	delete(a.loginThrottle.userHour, username)
	prefix := username + "\x00"
	for k := range a.loginThrottle.knownGood {
		if strings.HasPrefix(k, prefix) {
			delete(a.loginThrottle.knownGood, k)
			delete(a.loginThrottle.knownGoodFails, k)
		}
	}
}

// purgeAllUserThrottle drops ALL per-username throttle state (userFails,
// userLock, userHour, knownGood). Disable removes every user, so every
// per-user entry is stale: without the purge a re-created account inherits
// a removed account's exemptions and failure debt.
// History: docs/DECISIONS.md → throttle-edge-cases
func (a *AuthState) purgeAllUserThrottle() {
	a.loginThrottle.Lock()
	defer a.loginThrottle.Unlock()
	a.loginThrottle.userFails = map[string][]time.Time{}
	a.loginThrottle.userLock = map[string]time.Time{}
	a.loginThrottle.userHour = map[string]*userHourBudget{}
	a.loginThrottle.knownGood = map[string]time.Time{}
	a.loginThrottle.knownGoodFails = map[string]int{}
}

// peerIP extracts the client's IP from the request's direct TCP peer
// (r.RemoteAddr), stripping the port. This is the ONLY source of truth for
// the login throttle unless the peer is a configured trusted proxy — see
// ClientIP. Using the peer (and not X-Forwarded-For) means an attacker can't
// rotate a spoofed X-Forwarded-For header to dodge the per-IP lockout.
func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ClientIP resolves the client's IP for the login throttle. The default is
// the direct TCP peer (peerIP) — a spoofed X-Forwarded-For from an untrusted
// peer is IGNORED, so an attacker cannot rotate it to reset the per-IP
// counter and brute-force past loginFailMax. When the immediate TCP peer is
// in PULSEMON_TRUSTED_PROXIES, XFF is walked RIGHT to LEFT and the first
// entry that parses and is NOT itself a trusted proxy is used (proxies
// APPEND, so everything left of our hop is client-supplied and rotatable).
// Trusting the header is gated on the PEER being in a trusted CIDR, so the
// header is only ever read from a connection we know is our proxy; a direct
// attacker (peer not in the list) gets the peer address and their rotation
// attempt is pointless.
//
// X-Forwarded-For is trusted ONLY for rate-limiting, never authentication.
// History: docs/DECISIONS.md → login-throttle-per-username.
func (a *AuthState) ClientIP(r *http.Request) string {
	peer := peerIP(r)
	if a.trustedPeer(peer) {
		// Combine ALL X-Forwarded-For lines before parsing: HAProxy-style
		// proxies APPEND a new header line instead of extending the first,
		// and r.Header.Get returns only the first — the CLIENT-CONTROLLED
		// one. Reading it alone attributed every attempt to the attacker's
		// chosen address; joining with "," keeps the original rightmost-
		// untrusted semantics for single-line XFF.
		if vals := r.Header.Values("X-Forwarded-For"); len(vals) > 0 {
			xf := strings.Join(vals, ",")
			parts := strings.Split(xf, ",")
			var leftmost net.IP
			for i := len(parts) - 1; i >= 0; i-- {
				ip := net.ParseIP(strings.TrimSpace(parts[i]))
				if ip == nil {
					continue
				}
				if !a.trustedIP(ip) {
					return ip.String()
				}
				leftmost = ip
			}
			if leftmost != nil {
				return leftmost.String()
			}
		}
		return peer
	}
	// Untrusted peer: the header is IGNORED (a sender can rotate it to
	// dodge the throttle — see the ClientIP doc), but its PRESENCE is the
	// signature of a reverse proxy sitting in front of pulsemon WITHOUT
	// PULSEMON_TRUSTED_PROXIES: every client behind that proxy shares the
	// proxy's throttle bucket, so loginFailMax bad guesses from ANYONE lock
	// everyone out for loginLockout. Surface it once — a log line only,
	// security behavior unchanged (a direct connection sending the header
	// is a false positive, hence the hedged wording).
	if r.Header.Get("X-Forwarded-For") != "" && xffMisconfigWarned.CompareAndSwap(false, true) {
		log.Printf("auth: ignoring X-Forwarded-For from untrusted peer %s — if pulsemon sits behind a reverse proxy, set PULSEMON_TRUSTED_PROXIES to the proxy's address; until then every client behind it shares the proxy's login-throttle bucket (so %d failed guesses from anyone lock everyone out for %s), and — behind a TLS-terminating proxy — the dashboard's API calls are blocked with 403 'cross-origin request blocked' (logged once)", peer, loginFailMax, loginLockout)
	}
	return peer
}

// xffMisconfigWarned: logged-once flag for the "untrusted peer carrying
// X-Forwarded-For" shape (see ClientIP) — the signature of a reverse
// proxy missing from PULSEMON_TRUSTED_PROXIES. atomic.Bool rather than
// sync.Once so tests can reset it between runs.
var xffMisconfigWarned atomic.Bool

// trustedPeer reports whether the IP string (host, no port) is inside any of
// the trusted-proxy CIDRs. An unparseable IP is never trusted.
func (a *AuthState) trustedPeer(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	return a.trustedIP(p)
}

// trustedIP reports whether p is inside any of the trusted-proxy CIDRs.
func (a *AuthState) trustedIP(p net.IP) bool {
	for _, n := range a.trustedProxies {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

// cgnetRange is 100.64.0.0/10 (RFC 6598). Addresses from this space can
// only reach the socket over an overlay (Tailscale/Headscale): every one of
// them is an individually assigned, individually trusted peer — exactly
// like RFC1918 space — so the login throttle buckets it PER-IP. A public-
// internet attacker never presents a 100.64/x source address: carrier NAT
// is invisible past the carrier's public egress.
// History: docs/DECISIONS.md → login-throttle-bucketing.
var cgnetRange = func() *net.IPNet {
	_, n, err := net.ParseCIDR("100.64.0.0/10")
	if err != nil {
		panic(err) // unreachable: literal
	}
	return n
}()

// throttleKey maps a client IP to its login-throttle bucket:
//
//   - private (RFC1918), loopback, and CGNAT (RFC 6598, see cgnetRange)
//     IPv4 → the exact address (/32): each device is a distinct host with
//     no rotation, and a shared /24 let one misbehaving client lock out
//     the whole homelab subnet.
//   - other IPv4 → the /24: an internet attacker rotating within a /24
//     stays in one bucket.
//   - IPv6 → the /64: one host owns a whole /64 (privacy-extension
//     rotation), so per-address keying would hand it 2^64 separate
//     budgets.
//
// An unparseable string is returned as-is.
// History: docs/DECISIONS.md → login-throttle-bucketing.
func throttleKey(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ip
	}
	if v4 := p.To4(); v4 != nil {
		if v4.IsPrivate() || v4.IsLoopback() || cgnetRange.Contains(v4) {
			return v4.String()
		}
		return fmt.Sprintf("%d.%d.%d.0", v4[0], v4[1], v4[2])
	}
	return p.Mask(net.CIDRMask(64, 128)).String()
}

// userHourBudget is one account's slow (hourly) failed-login budget: the
// window anchor (start) and the failed-check count since it opened. A fail
// at/after start+loginHourWindow re-anchors the window (count resets to 0),
// so the budget is a rolling 1-hour total, not a fixed clock-aligned hour.
type userHourBudget struct {
	start time.Time
	count int
}

// ensureThrottleMaps lazily initializes the throttle maps (cheap, idempotent).
func (a *AuthState) ensureThrottleMaps() {
	if a.loginThrottle.fails == nil {
		a.loginThrottle.fails = map[string][]time.Time{}
	}
	if a.loginThrottle.lockout == nil {
		a.loginThrottle.lockout = map[string]time.Time{}
	}
	if a.loginThrottle.userFails == nil {
		a.loginThrottle.userFails = map[string][]time.Time{}
	}
	if a.loginThrottle.userLock == nil {
		a.loginThrottle.userLock = map[string]time.Time{}
	}
	if a.loginThrottle.userHour == nil {
		a.loginThrottle.userHour = map[string]*userHourBudget{}
	}
	if a.loginThrottle.knownGood == nil {
		a.loginThrottle.knownGood = map[string]time.Time{}
	}
	if a.loginThrottle.knownGoodFails == nil {
		a.loginThrottle.knownGoodFails = map[string]int{}
	}
}

// Throttle GC tuning. Vars, not consts, so tests
// can exercise the cap paths without 100k-entry seeding.
var (
	throttleSweepThreshold = 1024
	throttleSweepInterval  = 30 * time.Second
	throttleHardCap        = 1 << 17
)

// beginAttempt atomically decides whether ip may run a credential check NOW
// and, if so, records the attempt in the SAME critical section — before the
// caller runs bcrypt. Counting first is what closes the concurrency bypass:
// a check-then-KDF-then-record shape let N parallel requests all pass
// before any of them recorded a failure, so a burst ran the KDF N times.
// With the count inside the lock, at most loginFailMax concurrent attempts
// pass; the rest get a fast 429 without touching the KDF.
//
// Returns (false, how-long-until-the-lockout-lifts) when locked out; the
// caller answers 429 + Retry-After. A failed attempt is NOT recorded again
// by the caller — it is already counted here, for success OR failure alike
// (a success clears the counter via loginSuccess).
func (a *AuthState) beginAttempt(ip string) (bool, time.Duration) {
	a.loginThrottle.Lock()
	defer a.loginThrottle.Unlock()
	a.ensureThrottleMaps()
	now := time.Now()
	// Opportunistic GC (see sweepThrottle), rate-limited by nextSweep: a
	// spray keeps every entry in-window, so a per-call sweep prunes nothing
	// at O(n) cost.
	//
	// The trigger watches ALL THREE maps: userFails is keyed by the raw
	// request username (up to the 1 MiB body limit), so a small IP pool
	// rotating random usernames grows userFails while len(fails) stays tiny
	// — and knownGood is the same class: loginSuccess DELETES from fails
	// and INSERTS into knownGood, so successful logins from rotating source
	// buckets grow knownGood while fails AND userFails hover near zero.
	// Gating the sweep on the per-IP map alone left both unbounded.
	// History: docs/DECISIONS.md → knowngood-bound.
	if (len(a.loginThrottle.fails) > throttleSweepThreshold ||
		len(a.loginThrottle.userFails) > throttleSweepThreshold ||
		len(a.loginThrottle.knownGood) > throttleSweepThreshold) && !now.Before(a.loginThrottle.nextSweep) {
		a.sweepThrottle(now)
		a.loginThrottle.nextSweep = now.Add(throttleSweepInterval)
		// Spray-proof memory bound: if a sweep still leaves a map huge
		// (every entry fresh — a wide one-shot spray), drop ONLY that
		// layer's throttle state. Each layer fails open on its own cap: a
		// per-IP spray resets the per-IP maps, a username-rotation spray
		// resets the per-username maps, a successful-login spray resets
		// knownGood. The per-username maps are no longer bounded by
		// account count (unknown names are counted — userfails-unknown-
		// names), so a wide name-rotation spray can reach this cap and
		// wipe an ACTIVE account lockout mid-attack; that trade is
		// accepted: reaching it needs ~18k distinct IP buckets in 30s
		// (the per-IP 7/60s cap), which is the out-of-model botnet the
		// reverse proxy is for. userHour is wiped WITH its layer: it
		// shares the per-username key space and its persist-across-
		// lockouts contract is meaningless once the lockout is gone.
		// Chosen bound: 131072 entries ≈ tens of MB worst case per
		// map.
		// History: docs/DECISIONS.md → throttle-edge-cases,
		// userfails-unknown-names
		if len(a.loginThrottle.fails) > throttleHardCap {
			a.loginThrottle.fails = map[string][]time.Time{}
			a.loginThrottle.lockout = map[string]time.Time{}
		}
		if len(a.loginThrottle.userFails) > throttleHardCap {
			a.loginThrottle.userFails = map[string][]time.Time{}
			a.loginThrottle.userLock = map[string]time.Time{}
			a.loginThrottle.userHour = map[string]*userHourBudget{}
		}
		if len(a.loginThrottle.knownGood) > throttleHardCap {
			a.loginThrottle.knownGood = map[string]time.Time{}
			a.loginThrottle.knownGoodFails = map[string]int{}
		}
	}
	if until, ok := a.loginThrottle.lockout[ip]; ok {
		if now.Before(until) {
			return false, until.Sub(now)
		}
		// Lockout elapsed: clear it and the stale failures.
		delete(a.loginThrottle.lockout, ip)
		delete(a.loginThrottle.fails, ip)
	}
	cutoff := now.Add(-loginFailWindow)
	fails := a.loginThrottle.fails[ip]
	kept := fails[:0]
	for _, t := range fails {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= loginFailMax {
		a.loginThrottle.lockout[ip] = now.Add(loginLockout)
		a.loginThrottle.fails[ip] = kept
		return false, loginLockout
	}
	// Counted NOW, before the KDF: this timestamp is the attempt itself.
	a.loginThrottle.fails[ip] = append(kept, now)
	return true, 0
}

// knownGoodKey keys the knownGood exemption by (username, ip bucket).
// Usernames match usernameRe (letters, digits, . _ -) and ip buckets are
// dotted/colon address strings, so neither side can contain \x00 and the
// pair is collision-free.
func knownGoodKey(username, ip string) string {
	return username + "\x00" + ip
}

// loginSuccess clears all failure accounting for ip and marks
// (username, ip) as known-good.
func (a *AuthState) loginSuccess(username, ip string) {
	a.loginThrottle.Lock()
	defer a.loginThrottle.Unlock()
	a.ensureThrottleMaps()
	delete(a.loginThrottle.fails, ip)
	delete(a.loginThrottle.lockout, ip)
	// Mark this (username, IP bucket) pair known-good: a successful
	// login is the signal that this is the operator (or a trusted
	// client) for THAT account, so the per-username lockout must not
	// block them on a later attempt. Scoped to the account — a success
	// by any other user on the same shared IP must not exempt this one
	// (see the knownGood field comment).
	a.loginThrottle.knownGood[knownGoodKey(username, ip)] = time.Now()
	// Re-mint resets the revocation count: an operator who typos a few
	// times and then logs in successfully keeps their exemption (the count
	// is "since mint", so N fails must come from AFTER the last success).
	delete(a.loginThrottle.knownGoodFails, knownGoodKey(username, ip))
}

// checkUserLock reports whether username is locked out by the per-username
// fail counter — a multi-IP attacker that has exhausted the account's
// budget. Returns (false, how-long-until-the-lockout-lifts) when locked;
// the caller answers 429 + Retry-After. An elapsed lockout is cleared here
// so the next attempt starts fresh.
//
// ipBucket is the request's throttle bucket (throttleKey of the client IP);
// a known-good (username, bucket) pair is exempt (see knownGoodKey).
// History: docs/DECISIONS.md → login-throttle-known-good-exemption.
func (a *AuthState) checkUserLock(username, ipBucket string) (bool, time.Duration) {
	a.loginThrottle.Lock()
	defer a.loginThrottle.Unlock()
	a.ensureThrottleMaps()
	now := time.Now()
	// Known-good (username, IP bucket) pair: exempt from the per-username
	// lockout (see knownGoodKey).
	if t, ok := a.loginThrottle.knownGood[knownGoodKey(username, ipBucket)]; ok && now.Sub(t) < knownGoodTTL {
		return true, 0
	}
	if until, ok := a.loginThrottle.userLock[username]; ok {
		if now.Before(until) {
			return false, until.Sub(now)
		}
		// Lockout elapsed: clear it and the stale failures.
		delete(a.loginThrottle.userLock, username)
		delete(a.loginThrottle.userFails, username)
	}
	return true, 0
}

// clearIPThrottle drops one bucket's per-IP failure accounting (fails +
// lockout) without touching the per-username maps. The setup-success path
// uses it to close out the dedicated "setup|ip" bucket: loginSuccess
// records the (username, ip) known-good exemption under the BARE bucket
// key (what checkUserLock looks up), so its own fails/lockout clear lands
// on the login bucket and the setup bucket needs its own explicit clear.
// History: docs/DECISIONS.md → throttle-edge-cases
func (a *AuthState) clearIPThrottle(ip string) {
	a.loginThrottle.Lock()
	defer a.loginThrottle.Unlock()
	delete(a.loginThrottle.fails, ip)
	delete(a.loginThrottle.lockout, ip)
}

// recordUserFail counts ONE failed credential check against username (across
// all source IPs — the per-username layer the per-IP throttle can't see) and
// locks the account out when the in-window count reaches loginFailMax. Called
// ONLY on a failed check, after the KDF ran; a success clears it via
// clearUserFail, so typos that eventually succeed don't accumulate.
//
// ipBucket is the request's throttle bucket: a fail from a KNOWN-GOOD
// (username, bucket) pair is charged to the exemption itself, and
// knownGoodRevokeFails such fails revoke it — the account budget above keeps
// counting under the exemption, so without the revocation a bucket-sharer
// paces the 30-day exemption past the hourly cap (the per-IP 7/60s layer
// only forces a 5-minute pause per burst).
// History: docs/DECISIONS.md → knowngood-revoke-on-bucket-fails.
func (a *AuthState) recordUserFail(username, ipBucket string) {
	a.loginThrottle.Lock()
	defer a.loginThrottle.Unlock()
	a.ensureThrottleMaps()
	now := time.Now()
	// Fast layer: the rolling 60s window (unchanged).
	cutoff := now.Add(-loginFailWindow)
	fails := a.loginThrottle.userFails[username]
	kept := fails[:0]
	for _, t := range fails {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	a.loginThrottle.userFails[username] = kept
	// Slow layer: the hourly budget. It PERSISTS across rolling lockouts —
	// checkUserLock's expiry wipes userFails (the rolling window) but NOT
	// userHour, so a 7-fails/60s → 5-min burst repeated every 6 min (~70/hr)
	// can't outrun the 30/hr cap. The window re-anchors by wall clock; >=
	// (not >) so the budget is already reset the instant a 1h lockout lifts,
	// never re-locking the account on the very next fail.
	b := a.loginThrottle.userHour[username]
	if b == nil {
		b = &userHourBudget{}
		a.loginThrottle.userHour[username] = b
	}
	if now.Sub(b.start) >= loginHourWindow {
		b.start, b.count = now, 0
	}
	b.count++
	// The hourly budget is the binding cap, so it outranks the rolling
	// threshold: a paced attack that never trips 7/60s still locks at 30/hr.
	// A rolling trip while UNDER the hourly cap takes the shorter 5-min
	// lockout (the hourly counter keeps climbing in the background).
	if b.count >= loginHourFailMax {
		a.loginThrottle.userLock[username] = now.Add(loginHourLockout)
	} else if len(kept) >= loginFailMax {
		a.loginThrottle.userLock[username] = now.Add(loginLockout)
	}
	// Known-good revocation: charge the fail to the pair's exemption.
	// Only pairs WITH an active exemption accumulate (no entry is minted
	// for non-exempt users — the map stays bounded by knownGood's keys).
	k := knownGoodKey(username, ipBucket)
	if _, ok := a.loginThrottle.knownGood[k]; ok {
		a.loginThrottle.knownGoodFails[k]++
		if a.loginThrottle.knownGoodFails[k] >= knownGoodRevokeFails {
			delete(a.loginThrottle.knownGood, k)
			delete(a.loginThrottle.knownGoodFails, k)
		}
	}
}

// clearUserFail clears the per-username fail accounting for username (a
// successful login resets the account's budget).
func (a *AuthState) clearUserFail(username string) {
	a.loginThrottle.Lock()
	defer a.loginThrottle.Unlock()
	delete(a.loginThrottle.userFails, username)
	delete(a.loginThrottle.userLock, username)
	delete(a.loginThrottle.userHour, username)
}

// refundAttempt releases ONE counted admission (the timestamp
// beginAttempt appended) when the caller discovers — BEFORE paying the
// bcrypt KDF — that the check needn't run: the setup-mode bootstrap lost
// the single-shot race (errBootstrappedEarly) or failed cheap validation.
// Without refunds, ordinary traffic against a CLAIMED install would
// accumulate toward the setup bucket's lockout while costing the server
// nothing — throttling is for KDF cost, and no cost was paid. Best-effort:
// it pops the most recent entry, which under concurrency may refund a
// different same-IP attempt; the failure direction is at most one extra
// admitted free attempt, never a false lockout. Caller must only refund
// admissions beginAttempt ACCEPTED (returned ok).
//
// When a refund brings the count back UNDER loginFailMax it also clears any
// lockout: a burst of >loginFailMax no-KDF-cost requests that are all
// subsequently refunded (browser double-submits, scripts hitting
// errBootstrappedEarly / invalid usernames) would otherwise leave the IP
// locked out for the full lockout despite paying zero KDF cost. The
// lockout is only ever set with >= loginFailMax entries present, so
// dropping back under the threshold means the IP no longer has enough real
// (KDF-cost) failures to justify it. A genuine attacker who pays the KDF
// for loginFailMax failures never gets those refunded, so their lockout is
// preserved.
// History: docs/DECISIONS.md → login-lockout-429-refund.
func (a *AuthState) refundAttempt(ip string) {
	a.loginThrottle.Lock()
	defer a.loginThrottle.Unlock()
	f := a.loginThrottle.fails[ip]
	if len(f) > 0 {
		f = f[:len(f)-1]
		a.loginThrottle.fails[ip] = f
		if len(f) < loginFailMax {
			delete(a.loginThrottle.lockout, ip)
		}
	}
}

// sweepThrottle drops throttle entries that can no longer affect a decision:
// no unexpired lockout and no failure within the rolling window. It is called
// opportunistically from beginAttempt once the maps grow past a threshold,
// bounding memory under a multi-IP spray (one failed login per source IP,
// where no single IP ever re-triggers its own prune). Caller must hold
// a.loginThrottle.
func (a *AuthState) sweepThrottle(now time.Time) {
	cutoff := now.Add(-loginFailWindow)
	for ip, ts := range a.loginThrottle.fails {
		recent := false
		for _, t := range ts {
			if t.After(cutoff) {
				recent = true
				break
			}
		}
		if recent {
			continue
		}
		if until, ok := a.loginThrottle.lockout[ip]; ok && now.Before(until) {
			continue // active lockout: keep
		}
		delete(a.loginThrottle.fails, ip)
		delete(a.loginThrottle.lockout, ip)
	}
	// Per-username layer: same drop rule — no in-window failure
	// and no active account lockout.
	for u, ts := range a.loginThrottle.userFails {
		recent := false
		for _, t := range ts {
			if t.After(cutoff) {
				recent = true
				break
			}
		}
		if recent {
			continue
		}
		if until, ok := a.loginThrottle.userLock[u]; ok && now.Before(until) {
			continue // active lockout: keep
		}
		delete(a.loginThrottle.userFails, u)
		delete(a.loginThrottle.userLock, u)
	}
	// The hourly budget: the same drop rule as userFails — an account
	// with no in-window failures and no active lockout has nothing left
	// to spend, and (now that unknown names are counted) the key space
	// is attacker-chosen, so stale entries must go. An ACTIVE-lockout
	// account keeps its budget (the lockout check mirrors userFails'),
	// which is the persist-across-rolling-lockouts contract.
	for u := range a.loginThrottle.userHour {
		if until, ok := a.loginThrottle.userLock[u]; ok && now.Before(until) {
			continue // active lockout: keep
		}
		recent := false
		for _, t := range a.loginThrottle.userFails[u] {
			if t.After(cutoff) {
				recent = true
				break
			}
		}
		if !recent {
			delete(a.loginThrottle.userHour, u)
		}
	}
	// Known-good IP buckets: drop entries older than
	// knownGoodTTL, so a stale IP stops being exempt from the per-username
	// lockout.
	for ip, t := range a.loginThrottle.knownGood {
		if now.Sub(t) > knownGoodTTL {
			delete(a.loginThrottle.knownGood, ip)
			delete(a.loginThrottle.knownGoodFails, ip)
		}
	}
}
