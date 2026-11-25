package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"pulsemon/internal/store"

	"golang.org/x/crypto/bcrypt"
)

// Authentication: the users table is the single source of truth for who may
// log in; sessions are in-memory (a restart logs everyone out) and only
// /api/auth/{status,login,logout} and /api/setup are unauthenticated.
//
// Invariants:
//   - the last user cannot be removed, only disabled; the CLI
//     (pulsemon auth-user) is the out-of-band recovery path and bypasses the
//     login throttle.
//   - the in-memory throttle resets on restart by design: the threat model
//     is a LAN brute-forcer, and the only way to reset a lockout is a
//     process restart, which already implies host access.
//   - auth-off installs are a trusted-LAN single-operator mode: requireAdmin
//     stands down and the dashboard is fully open.
//
// Incident history: docs/DECISIONS.md → login-throttle-per-username,
// login-hourly-budget, knowngood-bound, oversized-login-guard.
const (
	authSessionName = "pulsemon_session"
	// authSessionTTL is the SLIDING inactivity window: a session lapses if it
	// goes unused for this long. ValidSession and SessionUser move expiry
	// forward on every live hit, so an active operator stays logged in while
	// an idle session dies after a week. It is deliberately SHORTER than
	// authSessionMaxAge (see below): with the two equal the sliding machinery
	// was a no-op and every session died exactly 30 days after login.
	authSessionTTL = 7 * 24 * time.Hour
	// authSessionMaxAge is the ABSOLUTE session lifetime from login, independent
	// of activity: a sliding TTL alone would let a continuously-active (or
	// periodically-replayed stolen) cookie never lapse. Sliding 7-day, absolute
	// 30-day; CookieRenewalDue keeps an active cookie ≥ half the TTL from
	// expiring on the browser side.
	// History: docs/DECISIONS.md → session-absolute-max-age.
	authSessionMaxAge = 30 * 24 * time.Hour
	bcryptCost        = bcrypt.DefaultCost
	minPasswordLen    = 8
	maxUsernameLen    = 32

	// Per-IP login throttle: up to loginFailMax failures in a rolling
	// loginFailWindow, then locked for loginLockout. In-memory only by design —
	// the threat model is "don't let an attacker spray passwords", and the only
	// way to reset a lockout is a process restart, which already means host
	// access.
	// History: docs/DECISIONS.md → login-throttle-per-username.
	loginFailMax    = 7
	loginFailWindow = 60 * time.Second
	loginLockout    = 5 * time.Minute
	// loginSlowDown is a constant-time-ish delay applied to every rejected
	// login (401) so the response time doesn't depend on which path ran, and
	// an online attacker gets at most ~5 guesses/second per IP.
	loginSlowDown = 200 * time.Millisecond

	// Second, SLOWER per-username limit: the 60s window only catches bursts
	// (6 guesses/min runs forever under it), so the hourly budget caps a single
	// account's total failed checks, then locks it for loginHourLockout.
	// Persists across rolling lockouts; known-good (account, IP) pairs are
	// exempt; success clears it.
	// History: docs/DECISIONS.md → login-hourly-budget.
	loginHourFailMax = 30
	loginHourWindow  = time.Hour
	loginHourLockout = time.Hour

	// knownGoodTTL bounds how long a previously-successful IP bucket stays
	// exempt from the per-username lockout. It matches the session's ABSOLUTE
	// cap (authSessionMaxAge), not the sliding idle TTL: a session can stay
	// valid up to max-age if active, so the operator's IP must stay exempt for
	// that whole window, not just the 7-day idle period. An IP that hasn't
	// logged in in a month expires (and is recoverable via the CLI — see the
	// file header).
	knownGoodTTL = authSessionMaxAge

	// enabledTTL bounds how long the "is auth enabled?" (user count > 0)
	// cache is trusted before re-reading the DB. In-app user mutations
	// refresh it immediately (the dashboard is never stale); this only caps
	// how long an OUT-OF-BAND `pulsemon auth-user add/remove` waits before
	// the gate notices. 2s is far below any human-perceptible gap and keeps
	// the SELECT COUNT(*) off the per-request hot path.
	enabledTTL = 2 * time.Second
)

// usernameRe: starts with a letter, then letters/digits/._- . Stored
// lowercase; the UNIQUE constraint is on the lower-cased column value.
var usernameRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9._-]*$`)

// dummyBcryptHash is the unknown-user KDF equalizer: a well-formed hash
// built ONCE at init at bcryptCost, so unknown-user and wrong-password
// VerifyUser paths take the same time (no username-enumeration oracle).
// Invariants: the cost stays tied to bcryptCost (a fixed cost re-opens the
// oracle if the cost is ever raised), and the embedded body is the canonical
// public bcrypt test vector — its shape and cost matter, nothing ever
// authenticates against it. Never paste a real account's hash here.
// History: docs/DECISIONS.md → login-throttle-per-username.
var dummyBcryptHash = []byte(fmt.Sprintf("$2a$%02d$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", bcryptCost))

// bcryptSem bounds CONCURRENT bcrypt KDFs to runtime.NumCPU, so a multi-IP
// burst cannot drive more parallel KDFs than there are cores. Blocking (it
// queues, never rejects) so under attack the operator's login waits for a
// free core instead of 429ing — the exact regression a select/default
// variant would cause. Both KDF flavors go through it (verify + generate;
// setup mode is an unauthenticated surface). Acquire is ctx-aware: a
// disconnected client stops waiting for a core.
// History: docs/DECISIONS.md → bcrypt-sem-full-coverage.
var bcryptSem = make(chan struct{}, runtime.NumCPU())

// acquireBcryptSem blocks until a KDF slot frees up or ctx is canceled.
// Returns false (no slot taken) when ctx completes first — the caller must
// then skip the KDF entirely. The select makes the wait cancellable: a
// multi-IP burst whose clients time out no longer parks handlers on the
// semaphore (and burns CPU on the queued KDFs) after the flood stops.
func acquireBcryptSem(ctx context.Context) bool {
	select {
	case bcryptSem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func releaseBcryptSem() { <-bcryptSem }

// kdfCostFloor separates a ZERO-KDF-COST return from the bcrypt queue
// (acquireBcryptSem's ctx.Done select fires in microseconds) from a return
// that PAID the KDF (bcrypt at bcryptCost=DefaultCost runs ≥50ms on any
// supported hardware and cannot be interrupted by ctx — see the
// api_context_test.go empirical pin) when the login and change-password
// disconnect arms decide whether to refund the per-IP throttle admission.
// The refund contract ("throttling is for KDF cost", refundAttempt) refunds
// only the unpaid case; the margin is ≥2x under the paid side and ≥4
// orders of magnitude over the unpaid side, so the split is deterministic.
const kdfCostFloor = 25 * time.Millisecond

type authSession struct {
	user   string
	expiry time.Time
	// created is the login time, kept for the absolute authSessionMaxAge cap.
	// Unlike expiry — which ValidSession and SessionUser slide forward on every
	// live hit — created is fixed at login and never moved, so it bounds the
	// total lifetime of a continuously-active session. The sliding TTL alone
	// can't do that: activity keeps pushing expiry out, so without this field
	// an always-open tab (or a periodically-used stolen cookie) never lapses.
	created time.Time
	// cookieIssued is when the browser cookie for this session was last
	// (re)issued. The cookie carries a fixed Max-Age=authSessionTTL set at
	// login, so without re-issuance the browser deletes it exactly TTL
	// after login even though ValidSession slides the in-memory expiry on
	// every use — the sliding-session design was defeated by the cookie's
	// fixed expiry. authGate re-issues the
	// same token once the cookie ages past half the TTL
	// (CookieRenewalDue), keeping an active user's cookie ahead of its
	// browser-side expiry.
	cookieIssued time.Time
	// cookieSecure pins the Secure decision made when the session was
	// minted: renewals re-issue the cookie on a
	// LATER request, whose HTTPS-ness may differ (a TLS-terminating proxy
	// that misses X-Forwarded-Proto on one hop used to re-issue the same
	// token WITHOUT Secure — downgrading the very protection the login
	// applied). A Secure-minted session stays Secure through every
	// renewal; the pin only ever ratchets UP (a non-secure mint plus an
	// https renewal still sets Secure for that response).
	cookieSecure bool
}

type AuthState struct {
	db *store.Store

	// nextSweepSessions rate-limits the session-map GC (see
	// sweepExpiredSessions / CreateSession).
	// Guarded by a.mu.
	nextSweepSessions time.Time

	// userCountFn is the count source Enabled() reads through. Defaults to
	// db.UserCount; a test may substitute a counting stub to prove the cache
	// actually stops the per-request query. Guarded by enabledMu.
	userCountFn func() (int, error)

	mu       sync.Mutex
	sessions map[string]authSession // session token → owner + expiry

	// userOKCache: username → last time we confirmed the account exists
	// in the users table (see userOKTTL). Guarded by mu. Sessions are
	// in-memory, so an out-of-band `pulsemon auth-user remove` (a separate
	// process with its own AuthState) cannot touch this map — session
	// validation therefore re-checks the users table at most once per
	// userOKTTL per user. Populated only by
	// validation, never by CreateSession: a freshly minted session gets a
	// LIVE existence check on first use (the login/remove race, F2).
	userOKCache map[string]time.Time

	// adminCache: username → last IsAdmin answer + when it was read
	// (see userOKTTL). Guarded by mu. Caches BOTH answers: non-admins are
	// the steady state (viewer accounts 403 on every admin route), so a
	// positives-only cache would leave the common path uncached — the
	// point is zero DB queries per admin-gated request in steady state.
	// A read error is NOT cached (IsAdmin fails closed). In-app user
	// mutations (AddUser/RemoveUser/Disable) clear it via
	// refreshEnabledNow so a last-admin promotion is visible on the very
	// next request; the TTL bounds out-of-band CLI changes.
	adminCache map[string]adminEntry

	// enabledCache: whether auth is enabled (user count > 0), memoized for
	// enabledTTL so the 5s dashboard poll doesn't pay a SELECT COUNT(*) on
	// every request. enabledAt is zero until the first read; in-app user
	// mutations call refreshEnabledNow to invalidate it instantly.
	enabledMu sync.Mutex
	enabled   bool
	enabledAt time.Time

	// bootstrapped: one-way ratchet — true once this install has ever had an
	// account (settings auth_bootstrapped=1, set by AddUser and never cleared,
	// including when the operator later disables auth). The flag never goes
	// back to false, so caching only the TRUE value stays correct even for an
	// out-of-band `pulsemon auth-user add` (a separate process that writes the
	// setting without touching this AuthState): the latch only ratchets
	// false→true, and a not-yet-latched read always re-queries, so it picks up
	// the CLI's write on the next call. atomic so the per-request auth gate
	// reads it lock-free.
	bootstrapped atomic.Bool

	// bootstrappedFn is the read source Bootstrapped() uses. Defaults to
	// db.GetSetting("auth_bootstrapped"); a test may substitute a counting
	// stub to prove the latch stops the per-request query.
	bootstrappedFn func() string

	// loginThrottle: per-client-IP login failure accounting. Keyed by the
	// request's source IP as resolved by ClientIP — the TCP peer by default,
	// or the first X-Forwarded-For entry ONLY when the immediate TCP peer is
	// inside a trusted-proxy CIDR (PULSEMON_TRUSTED_PROXIES) — so a reverse-
	// proxied install still attributes attempts to the real client. An
	// untrusted peer's XFF header is ignored, so it can't be rotated to dodge
	// the throttle. failAt holds the timestamps of recent failed attempts;
	// lockUntil holds the time at which the IP is released from lockout.
	loginThrottle struct {
		sync.Mutex
		fails   map[string][]time.Time
		lockout map[string]time.Time
		// userFails / userLock are a PER-USERNAME layer on top of the per-IP
		// maps: the per-IP throttle is keyed by source address,
		// so a multi-IP attacker (an IPv6 /48 is 65k distinct /64 buckets)
		// hammering ONE account never exhausts any single IP's budget. The
		// per-username counter accumulates failures for that account across
		// ALL sources and locks the account out at the same loginFailMax /
		// loginFailWindow / loginLockout cadence. Only a failed credential
		// check increments it (a success clears it via clearUserFail), so an
		// operator who typos once from two devices doesn't self-lock.
		userFails map[string][]time.Time
		userLock  map[string]time.Time
		// userHour: the per-username HOURLY budget (loginHourFailMax). The
		// rolling userFails window only catches bursts; userHour caps the
		// account's total failed checks per hour so a paced multi-IP attack
		// can't stay under the 60s threshold indefinitely. It PERSISTS across
		// rolling lockouts (a rolling expiry wipes userFails, not userHour)
		// and self-resets by wall clock once the window elapses. Bounded by
		// account count — recordUserFail only counts EXISTING users — so it
		// never grows unboundedly and needs no sweep of its own.
		userHour map[string]*userHourBudget
		// knownGood: (username, IP bucket) → last successful login. A
		// previously-successful (account, client) pair is EXEMPT from the
		// per-username lockout, scoped to the account (a success by another account
		// on the same IP does not exempt this one). Bounded by sweepThrottle.
		// History: docs/DECISIONS.md → login-throttle-known-good-exemption.
		knownGood map[string]time.Time
		// nextSweep rate-limits the O(n) map GC to once per throttleSweepInterval:
		// a spray keeps every entry in-window, so a per-call sweep prunes nothing at
		// O(n) cost. The sweep/wipe trigger watches ALL THREE maps — userFails is
		// keyed by arbitrary request usernames, so a small IP pool rotating names
		// grows it while the per-IP map stays tiny.
		// History: docs/DECISIONS.md → knowngood-bound.
		nextSweep time.Time
	}

	// trustedProxies: CIDRs of immediate TCP peers whose X-Forwarded-For is
	// trusted for rate-limiting. Loaded from PULSEMON_TRUSTED_PROXIES at
	// construction; empty (the default) means the header is never trusted.
	trustedProxies []*net.IPNet
}

func NewAuthState(db *store.Store) *AuthState {
	a := &AuthState{
		db:          db,
		sessions:    map[string]authSession{},
		userOKCache: map[string]time.Time{},
		adminCache:  map[string]adminEntry{},
	}
	a.trustedProxies = parseTrustedProxies(os.Getenv("PULSEMON_TRUSTED_PROXIES"))
	return a
}

// userOKTTL bounds how long a confirmed "account exists" answer is reused
// by session validation (see SessionUser/ValidSession). It matches
// enabledTTL: an out-of-band `pulsemon auth-user remove` is a separate
// process that cannot touch this process's in-memory session map, so a
// removed user's sessions die within this window instead of living out
// their 30-day TTL. It also bounds the IsAdmin answer cache (adminCache).
const userOKTTL = 2 * time.Second

// adminEntry is one cached IsAdmin answer (see AuthState.adminCache).
type adminEntry struct {
	at    time.Time
	admin bool
}

// userExists reports whether the account exists in the users table — the
// cross-process source of truth for session validity. A read error is
// treated as "exists" (fail open for the session): a transient DB hiccup
// must not log the operator out, the same tradeoff Enabled() makes.
func (a *AuthState) userExists(username string) bool {
	var n int
	if err := a.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&n); err != nil {
		log.Printf("auth: user existence check failed for %q (keeping session): %v", username, err)
		return true
	}
	return n > 0
}

// userExistsCached is the TTL-cached wrapper session validation uses (one
// users-table lookup per user per userOKTTL). Caller must hold a.mu.
// Deliberately under the lock: it is a sub-millisecond point lookup at most
// once per user per 2s, and moving it out needs an unlock→query→re-lock→
// re-validate dance that opens a race window (session deleted or user
// re-created in the gap). The property this check exists for: out-of-band
// deletions are rejected within userOKTTL.
func (a *AuthState) userExistsCached(username string) bool {
	if t, ok := a.userOKCache[username]; ok && time.Since(t) < userOKTTL {
		return true
	}
	exists := a.userExists(username)
	if exists {
		a.userOKCache[username] = time.Now()
	} else {
		delete(a.userOKCache, username)
	}
	return exists
}

// Enabled reports whether at least one user exists, memoized for enabledTTL
// so the 5s dashboard poll doesn't pay a SELECT COUNT(*) per request.
// In-app mutations call refreshEnabledNow (never stale in-app); out-of-band
// CLI changes are honored within enabledTTL. The count-and-fallback rules
// live in refreshEnabledLocked (a COUNT error keeps the last known value;
// the first read fails closed).
func (a *AuthState) Enabled() bool {
	a.enabledMu.Lock()
	defer a.enabledMu.Unlock()
	if time.Since(a.enabledAt) < enabledTTL && a.enabledAt != (time.Time{}) {
		return a.enabled
	}
	a.refreshEnabledLocked()
	return a.enabled
}

// refreshEnabledLocked re-reads the user count and updates the Enabled()
// cache. The caller holds enabledMu. On a COUNT error the LAST KNOWN value
// is kept (a transient "database is locked" must not read as "auth
// disabled"); if there is no last known value yet (first-ever read) the gate
// fails CLOSED — enabled — so a DB hiccup can never open the dashboard.
func (a *AuthState) refreshEnabledLocked() {
	fn := a.userCountFn
	if fn == nil {
		fn = a.db.UserCount
	}
	n, err := fn()
	if err != nil {
		log.Printf("auth: user count failed (keeping previous state): %v", err)
		if a.enabledAt.IsZero() {
			a.enabled = true // never read: fail closed
		}
		a.enabledAt = time.Now()
		return
	}
	a.enabled = n > 0
	a.enabledAt = time.Now()
}

// refreshEnabledNow re-reads the user count and updates the Enabled() cache
// immediately; called by the in-app user mutations (AddUser/RemoveUser/
// Disable). It also clears adminCache — these same sites are the only
// in-app places an admin flag changes (bootstrap create, last-admin
// promotion); without the clear a promoted user's cached 'non-admin' 403s
// for up to userOKTTL.
func (a *AuthState) refreshEnabledNow() {
	a.mu.Lock()
	a.adminCache = map[string]adminEntry{}
	a.mu.Unlock()
	a.enabledMu.Lock()
	defer a.enabledMu.Unlock()
	a.refreshEnabledLocked()
}

// EnabledNow force-refreshes the Enabled() cache (bypassing the TTL) and
// returns the fresh value. The gate calls it in the (Enabled=false,
// Bootstrapped=true) branch before treating that pair as "operator
// disabled auth": the CLI first-user add commits the user row and the
// bootstrapped flag together, so a stale 'false' can outlive the commit
// by up to enabledTTL, and only a fresh count tells a real auth-off state
// from that torn window. Unlike refreshEnabledNow it does NOT clear
// adminCache — a gate read is not a mutation site, and clearing on every
// read in the (rare, deliberately open) auth-off state would trash the
// admin TTL cache for no gain.
func (a *AuthState) EnabledNow() bool {
	a.enabledMu.Lock()
	defer a.enabledMu.Unlock()
	a.refreshEnabledLocked()
	return a.enabled
}

// UserCount/CRUD live on *store.Store (internal/store); AuthState adds the password
// hashing, validation, and session bookkeeping on top.
var (
	errUsernameInvalid = fmt.Errorf("username must start with a letter and contain only letters, digits, . _ - (max %d)", maxUsernameLen)
	errPasswordWeak    = fmt.Errorf("password must be at least %d characters", minPasswordLen)
	// errPasswordTooLong: bcrypt rejects inputs over 72 bytes
	// (ErrPasswordTooLong) — pre-check it so create maps to a 400 instead of
	// a 500 and change-password returns our text, not the library's
	errPasswordTooLong = fmt.Errorf("password exceeds 72 bytes")
	// errPasswordCommon: the password is one of the most common passwords
	// (see isCommonPassword). Rejected at creation so an internet-reachable
	// install can't be a free password-cracking target — the 8-char minimum
	// alone still admits "password" and "qwerty123", the first entries of any
	// cracking list. Maps to a 400 (a client error, not a 500).
	errPasswordCommon = fmt.Errorf("password is too common — choose one not in the most-used passwords list")
	// errUserExists is the ONLY db error AddUser maps to a user-facing
	// message; every other db failure propagates as a raw error so the
	// handler can 500 it (respondInternal) instead of misreporting it as
	// a duplicate.
	errUserExists = fmt.Errorf("user already exists")
	// errBootstrapped: a concurrent unauthenticated first-user creation
	// won the setup-mode bootstrap. The handler
	// maps it to 409 — the install is no longer fresh, the account
	// already exists.
	errBootstrapped = fmt.Errorf("an account already exists — this install is set up")
	// errBootstrappedEarly wraps errBootstrapped for the pre-bcrypt count
	// check: the caller paid NO KDF cost, so the setup throttle refunds the
	// attempt (a claimed install must not lockout-accumulate the operator's
	// IP for ordinary traffic). errors.Is(errBootstrapped) stays true so
	// the 409 mapping is unchanged.
	errBootstrappedEarly = fmt.Errorf("%w (pre-check)", errBootstrapped)
)

// setupNoKDF reports whether a setup-mode rejection paid NO bcrypt KDF cost
// — the cheap validation sentinels, the early bootstrap pre-check, and a
// client that left while QUEUED on bcryptSem. In-tx race loss and db
// failures DID pay the KDF (bcrypt runs to completion and ignores ctx) and
// are NOT refunded: a disconnect mid-KDF must not buy a free retry (it would
// hand a scripted attacker an unbounded per-IP guessing channel).
// History: docs/DECISIONS.md → throttle-edge-cases.
func setupNoKDF(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, errBootstrappedEarly) || errors.Is(err, errUsernameInvalid) ||
		errors.Is(err, errPasswordWeak) || errors.Is(err, errPasswordTooLong) ||
		errors.Is(err, errPasswordCommon)
}

func validUsername(u string) bool {
	return u != "" && len(u) <= maxUsernameLen && usernameRe.MatchString(u)
}

// AddUser validates and creates an account; the first AddUser enables
// authentication. Check-and-create runs in ONE BEGIN IMMEDIATE transaction:
// on a fresh install the bootstrap POST is unauthenticated and LAN-open, so
// with a DEFERRED begin every concurrent first-user POST reads
// user_count=0 first — N racers, N "first" accounts. BEGIN IMMEDIATE
// serializes the writers: the winner commits the account and the
// auth_bootstrapped flag in the SAME tx; losers get errBootstrapped (409).
// In-app adds keep the normal path (duplicate → errUserExists 400).
func (a *AuthState) AddUser(ctx context.Context, username, password string) error {
	// In-app / CLI add: the user table may already be populated; a
	// duplicate username is the expected client error (400).
	return a.AddUserMode(ctx, username, password, false)
}

// AddUserMode is AddUser with the setup-mode flag explicit. setupMode=true
// means the caller came through the fresh-install gate: ONLY the first
// account may be created, and the check runs INSIDE the ImmediateTx on the
// serialized connection — the gate's Enabled() is TTL-cached, so N
// concurrent setup POSTs all pass the gate and only the in-tx user_count
// distinguishes winner from losers.
func (a *AuthState) AddUserMode(ctx context.Context, username, password string, setupMode bool) error {
	username = strings.ToLower(username)
	if !validUsername(username) {
		return errUsernameInvalid
	}
	if len(password) < minPasswordLen {
		return errPasswordWeak
	}
	if len(password) > 72 { // bcrypt input limit
		return errPasswordTooLong
	}
	// Reject the most common passwords at creation: the 8-char minimum alone
	// still admits "password" and "qwerty123", the first entries of any
	// cracking list. A set lookup (isCommonPassword) — cheap, before the
	// bcrypt KDF, so it costs the unauthenticated setup surface nothing. The
	// operator can always pick a password outside the list (it's the top-N
	// offenders, not all of password space); the hourly login budget is the
	// binding runtime cap for accounts that do exist.
	if isCommonPassword(password) {
		return errPasswordCommon
	}
	if setupMode {
		// Cheap pre-check BEFORE paying bcrypt: setup mode is
		// single-shot, so with any account already present this request
		// is guaranteed to lose the in-tx bootstrap check below. Without
		// it, unauthenticated setup mode is an unlimited bcrypt-CPU
		// endpoint. The authoritative check stays in
		// the tx (a pre-check alone cannot close the race); a failed
		// count just falls through to it.
		if n, err := a.db.UserCount(); err == nil && n > 0 {
			return errBootstrappedEarly
		}
	}
	// Same bcrypt semaphore as VerifyUser: setup
	// mode is an unauthenticated surface, so without the cap concurrent
	// bootstrap POSTs would run NumCPU-or-more parallel KDFs. A canceled
	// ctx (client gone) skips the KDF — it never ran, so the caller's
	// throttle refund logic treats it as a no-KDF rejection.
	if !acquireBcryptSem(ctx) {
		return ctx.Err()
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	releaseBcryptSem()
	if err != nil {
		return err
	}
	// A FRESH context for the tx itself: the request ctx is only the
	// KDF-skip signal above; the (millisecond) tx runs to completion so
	// a mid-tx disconnect can't leave a half-committed bootstrap.
	txCtx := context.Background()
	err = a.db.ImmediateTx(txCtx, func(c *sql.Conn) error {
		var n int
		if err := c.QueryRowContext(txCtx, "SELECT COUNT(*) FROM users").Scan(&n); err != nil {
			return err
		}
		if n > 0 && setupMode {
			// Setup mode is single-shot: an account already exists (the
			// winner of this race committed before our serialized BEGIN
			// took its snapshot). 409, not 400 — the client's own
			// username was fine, the install just isn't fresh anymore.
			return errBootstrapped
		}
		admin := 0
		if n == 0 {
			admin = 1 // first account = the admin (the account panel is admin-gated)
		}
		if _, err := c.ExecContext(txCtx,
			"INSERT INTO users (username, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?)",
			username, string(hash), store.Now(), admin); err != nil {
			// Only a UNIQUE-constraint violation (by result code) means
			// "account exists" — any other db failure must surface as a
			// 500, not be misreported as a duplicate.
			if isUniqueConstraintErr(err) {
				if n == 0 {
					// Lost the bootstrap race to a concurrent first user
					// that committed between our BEGIN and our INSERT.
					return errBootstrapped
				}
				return errUserExists
			}
			return err
		}
		if n == 0 {
			// First account: mark the install bootstrapped atomically
			// (see the function comment for why the flag must commit with
			// the user row).
			if _, err := c.ExecContext(txCtx,
				"INSERT OR REPLACE INTO settings (setting_key, value, updated_at) VALUES ('auth_bootstrapped', '1', ?)",
				store.Now()); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	a.refreshEnabledNow() // first user enables auth — don't wait for the TTL
	log.Println("Dashboard user added: " + username)
	return nil
}

// Bootstrapped reports whether this install has ever had an account
// (settings row auth_bootstrapped=1, set by AddUser, never cleared —
// including after auth is later disabled). The gate uses it to pick between
// the two zero-user states: fresh install → bootstrap-only surface;
// intentionally disabled → fully open. The answer latches: once a read sees
// '1', later calls return true without touching SQLite; a not-yet-latched
// read re-queries, so an out-of-band CLI add is picked up on the next call.
// History: docs/DECISIONS.md → auth-bootstrapped-latch.
func (a *AuthState) Bootstrapped() bool {
	if a.bootstrapped.Load() {
		return true
	}
	read := func() string { return a.db.GetSetting("auth_bootstrapped") }
	if a.bootstrappedFn != nil {
		read = a.bootstrappedFn
	}
	if read() == "1" {
		if !a.bootstrapped.Swap(true) {
			// First in-process latch: refresh the Enabled() cache NOW.
			// An out-of-band (CLI) first-user add commits the user row
			// and this flag together, so the moment this process first
			// sees '1', an Enabled() cache holding a stale 'false'
			// (enabledTTL = 2s) makes the pair (Enabled=false,
			// Bootstrapped=true) read as "operator disabled auth" — the
			// gate and requireAuth/requireAdmin would stand down and
			// open the dashboard for up to 2s. Refreshing at the latch
			// moment heals the cache at the source, for every consumer,
			// not just the gate. Swap (not Store) so the refresh fires
			// exactly once: the latch ratchets true and never moves.
			a.refreshEnabledNow()
		}
		return true
	}
	return false
}

// IsAdmin reports whether the username holds the admin flag — the gate for
// account management and the admin routes (settings, TLS, self-update,
// history wipes). Unknown/deleted users are not admins; a db error fails
// closed. Cached per username for userOKTTL (adminCache): in-app mutations
// clear it via refreshEnabledNow, out-of-band CLI changes are honored within
// the TTL. The query runs OUTSIDE a.mu (no lock held across I/O).
func (a *AuthState) IsAdmin(username string) bool {
	username = strings.ToLower(username)
	a.mu.Lock()
	if e, ok := a.adminCache[username]; ok && time.Since(e.at) < userOKTTL {
		a.mu.Unlock()
		return e.admin
	}
	a.mu.Unlock()
	var n int
	if err := a.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ? AND is_admin = 1", username).Scan(&n); err != nil {
		return false // fail closed: a read error must not grant admin
	}
	admin := n > 0
	a.mu.Lock()
	a.adminCache[username] = adminEntry{at: time.Now(), admin: admin}
	a.mu.Unlock()
	return admin
}

// RemoveUser deletes an account and every live session it owns. The last
// remaining user is protected — use Disable (auth-off) for that. The count
// below is only a fast path; the authoritative guard is the atomic
// conditional DELETE in db.RemoveUser. Removing the
// last admin promotes the oldest remaining user in the same transaction, so
// the install is never left without an admin.
func (a *AuthState) RemoveUser(ctx context.Context, username string) error {
	username = strings.ToLower(username)
	n, err := a.db.UserCount()
	if err != nil {
		return err
	}
	if n <= 1 {
		// A mistyped name in a single-user install is "no such user",
		// not "cannot remove the last user" — check existence before
		// blaming the guard.
		if !a.userExists(username) {
			return fmt.Errorf("%w: %s", store.ErrUserNotFound, username)
		}
		return store.ErrLastUser
	}
	if err := a.db.RemoveUser(ctx, username); err != nil {
		return err
	}
	a.dropUserSessions(username)
	a.purgeUserThrottle(username) // a re-created name starts with a clean budget
	a.refreshEnabledNow()         // may be the last user — don't wait for the TTL
	log.Println("Dashboard user removed: " + username)
	return nil
}

// SetUserPassword replaces a user's password and drops that user's other
// sessions (the caller's own session, if any, is kept so "change my
// password" does not log the operator out mid-panel).
func (a *AuthState) SetUserPassword(ctx context.Context, username, password, keepSession string) error {
	username = strings.ToLower(username)
	if len(password) < minPasswordLen {
		return errPasswordWeak
	}
	// Same blocklist as AddUser: a password created under the
	// hardening rule must not be changeable back onto the list —
	// otherwise the creation-time check is a formality (create with a
	// strong password, change to "password" in the next request).
	if isCommonPassword(password) {
		return errPasswordCommon
	}
	if len(password) > 72 { // bcrypt input limit
		return errPasswordTooLong
	}
	// Same bcrypt semaphore as VerifyUser: this is
	// a KDF too — a session holder (or a throttled spray) must not drive
	// NumCPU-or-more parallel GenerateFromPassword calls on top of the
	// login-path KDFs.
	if !acquireBcryptSem(ctx) {
		return ctx.Err()
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	releaseBcryptSem()
	if err != nil {
		return err
	}
	if err := a.db.SetUserPassword(username, string(hash)); err != nil {
		return err
	}
	a.dropUserSessionsExcept(username, keepSession)
	log.Println("Dashboard password changed: " + username)
	return nil
}

// VerifyUser reports whether username/password is a valid account.
func (a *AuthState) VerifyUser(ctx context.Context, username, password string) (string, bool) {
	username = strings.ToLower(username)
	hash, err := a.db.UserHash(username)
	if err != nil || hash == "" {
		// Constant-time-ish compare against dummyBcryptHash (built at bcryptCost,
		// so unknown-user and wrong-password ALWAYS run the same KDF cost — no
		// timing oracle if the cost is ever raised). Both paths go through
		// bcryptSem: the dummy path is the one an unknown-username spray drives, so
		// it needs the concurrency cap too. The acquire is ctx-aware: a disconnected
		// client skips the KDF; the live-client timing equalizer is untouched.
		// History: docs/DECISIONS.md → login-throttle-per-username.
		if !acquireBcryptSem(ctx) {
			return "", false
		}
		defer releaseBcryptSem()
		bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))
		return "", false
	}
	if !acquireBcryptSem(ctx) {
		return "", false
	}
	defer releaseBcryptSem()
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return "", false
	}
	return username, true
}

// Disable removes ALL users, opening the dashboard again.
func (a *AuthState) Disable() error {
	if err := a.db.RemoveAllUsers(); err != nil {
		return err
	}
	a.mu.Lock()
	a.sessions = map[string]authSession{}
	a.mu.Unlock()
	a.purgeAllUserThrottle() // every account is gone, so every per-user entry is stale
	a.refreshEnabledNow()    // all users gone — open the dashboard immediately
	log.Println("Dashboard authentication disabled (all users removed)")
	return nil
}
