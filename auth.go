package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ---------- dashboard authentication (username / password) ----------
//
// A `users` table holds every account: username + bcrypt password hash.
// Authentication is enabled IFF at least one user exists — creating the
// first account (from the still-open dashboard, or `pulsemon auth-user
// add`) turns the gate on; removing the last one (the "Disable
// Authentication" action) opens the dashboard again. There is no separate
// enabled flag: the user table is the single source of truth.
//
// Login is username + password; success issues an httpOnly session cookie
// (30-day sliding expiry, in-memory). Sessions are deliberately NOT
// persisted — a restart invalidating logins is acceptable for a tool with
// a handful of operators, and it keeps credentials to the users table.
//
// User management (add/remove/change-password) requires a valid session;
// only /api/healthz, /api/auth/status, /api/auth/login and
// /api/auth/logout are reachable without one. The last user cannot be
// removed through the user-management endpoints — that is reserved for the
// explicit disable action, so a typo can't silently open the dashboard.
//
// No per-ACCOUNT brute-force lockout (a typo'd password won't lock the
// operator out), but the login endpoint DOES apply a per-IP failure
// throttle (loginFailMax failures in a rolling window → lockout) plus a
// constant-time delay on every 401, so an internet-reachable install is
// not a free online password-cracking target against the 8-char minimum.
// The threat model is "a public URL must not expose the dashboard", not
// "an anonymous internet scanner must not probe it".

const (
	authSessionName = "pulsemon_session"
	authSessionTTL  = 30 * 24 * time.Hour
	bcryptCost      = bcrypt.DefaultCost
	minPasswordLen  = 8
	maxUsernameLen  = 32

	// Login throttling (see AuthState.loginThrottle). An internet-reachable
	// install must not be a free online password-cracking target against the
	// 8-char minimum. Per-IP: up to loginFailMax failures in a rolling
	// loginFailWindow, then the IP is locked for loginLockout. In-memory only
	// (restarts clear it) — the threat model is "don't let an attacker spray
	// passwords", not "survive a restart mid-attack".
	//
	// Why in-memory and NOT persisted to the settings table (2026-10-13
	// review, dismissed): an attacker who can force a process restart — the
	// only way to reset the lockout — already has host/docker access, at
	// which point brute-forcing the dashboard is moot (they can read the
	// SQLite DB or change the password directly), OR a pre-existing remote
	// crash bug, which is a separate finding to fix on its own. The
	// realistic brute-forcer (LAN access to :9299, no host access) cannot
	// restart the container, so the in-memory lockout holds for the
	// process's uptime. Persisting the per-IP failure map to SQLite would add
	// a write + a failure mode to the auth hot path for a vector the threat
	// model excludes. And even a coincidental restart (deploy/OOM) only
	// resets the attacker to a fresh loginFailMax budget at the
	// loginSlowDown-limited ~5 guesses/s — not an unlimited free pass.
	loginFailMax    = 7
	loginFailWindow = 60 * time.Second
	loginLockout    = 5 * time.Minute
	// loginSlowDown is a constant-time-ish delay applied to every rejected
	// login (401) so the response time doesn't depend on which path ran, and
	// an online attacker gets at most ~5 guesses/second per IP.
	loginSlowDown = 200 * time.Millisecond

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

// dummyBcryptHash is the "unknown user" KDF equalizer for VerifyUser: a
// well-formed bcrypt hash built ONCE at package init, at the SAME cost every
// real account hash is generated at (bcryptCost). An unknown user and a wrong
// password both run a full cost-N KDF, so the two paths take the same time —
// no username enumeration via timing.
//
// It is a package-level var (not rebuilt per call) so a login spike or
// brute-force attempt doesn't re-format the string on every failed lookup.
// The slice is shared read-only across concurrent logins (bcrypt never
// mutates its hash argument), and because bcryptCost is a const it is
// computed exactly once, so there is no cross-goroutine write to protect.
// It MUST stay tied to bcryptCost (never hardcode a fixed cost): raising the
// cost and leaving the dummy behind would make the unknown-user path run a
// weaker KDF than real hashes — a timing oracle.
var dummyBcryptHash = []byte(fmt.Sprintf("$2a$%02d$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", bcryptCost))

type authSession struct {
	user   string
	expiry time.Time
}

type AuthState struct {
	db *DB

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
	// userOKTTL per user (2026-10-19 review F1). Populated only by
	// validation, never by CreateSession: a freshly minted session gets a
	// LIVE existence check on first use (the login/remove race, F2).
	userOKCache map[string]time.Time

	// enabledCache: whether auth is enabled (user count > 0), memoized for
	// enabledTTL so the 5s dashboard poll doesn't pay a SELECT COUNT(*) on
	// every request. enabledAt is zero until the first read; in-app user
	// mutations call refreshEnabledNow to invalidate it instantly.
	enabledMu sync.Mutex
	enabled   bool
	enabledAt time.Time

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
	}

	// trustedProxies: CIDRs of immediate TCP peers whose X-Forwarded-For is
	// trusted for rate-limiting. Loaded from PULSEMON_TRUSTED_PROXIES at
	// construction; empty (the default) means the header is never trusted.
	trustedProxies []*net.IPNet
}

func NewAuthState(db *DB) *AuthState {
	a := &AuthState{
		db:          db,
		sessions:    map[string]authSession{},
		userOKCache: map[string]time.Time{},
	}
	a.trustedProxies = parseTrustedProxies(os.Getenv("PULSEMON_TRUSTED_PROXIES"))
	return a
}

// userOKTTL bounds how long a confirmed "account exists" answer is reused
// by session validation (see SessionUser/ValidSession). It matches
// enabledTTL: an out-of-band `pulsemon auth-user remove` is a separate
// process that cannot touch this process's in-memory session map, so a
// removed user's sessions die within this window instead of living out
// their 30-day TTL (2026-10-19 review F1).
const userOKTTL = 2 * time.Second

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

// userExistsCached is the TTL-cached wrapper session validation uses,
// capping the users-table lookups at one per user per userOKTTL. Caller
// must hold a.mu.
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

// Enabled reports whether at least one user exists. The answer is memoized
// for enabledTTL (a short-TTL cache) so the 5s dashboard poll — and every
// other request — doesn't pay a SELECT COUNT(*) round-trip on the hot path.
// In-app user mutations (AddUser/RemoveUser/Disable) call
// refreshEnabledNow, so the dashboard is never stale; only OUT-OF-BAND
// `pulsemon auth-user add/remove` is honored within enabledTTL (≤2s), which
// is the documented tradeoff for removing the per-request query.
//
// The count source is userCountFn (defaults to db.UserCount); the seam lets
// a test count reads and prove the cache actually stops the query.
//
// On a COUNT error the LAST KNOWN value is kept (a transient "database is
// locked" must not read as "auth disabled"); if there is no last known
// value yet (first-ever read) the gate fails CLOSED — enabled — so a DB
// hiccup can never open the dashboard.
func (a *AuthState) Enabled() bool {
	a.enabledMu.Lock()
	defer a.enabledMu.Unlock()
	if time.Since(a.enabledAt) < enabledTTL && a.enabledAt != (time.Time{}) {
		return a.enabled
	}
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
		return a.enabled
	}
	a.enabled = n > 0
	a.enabledAt = time.Now()
	return a.enabled
}

// refreshEnabledNow re-reads the user count and updates the Enabled() cache
// immediately. Called by the in-app user mutations (AddUser/RemoveUser/
// Disable) so the gate reflects them on the very next request with no TTL
// wait. An out-of-band CLI write takes its OWN AuthState on a separate DB
// handle and never reaches this method — which is exactly why the TTL exists.
// Like Enabled(), an error keeps the last known value (fails closed when
// there is none).
func (a *AuthState) refreshEnabledNow() {
	a.enabledMu.Lock()
	defer a.enabledMu.Unlock()
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

// UserCount/CRUD live on *DB (see db.go); AuthState adds the password
// hashing, validation, and session bookkeeping on top.

var (
	errUsernameInvalid = fmt.Errorf("username must start with a letter and contain only letters, digits, . _ - (max %d)", maxUsernameLen)
	errPasswordWeak    = fmt.Errorf("password must be at least %d characters", minPasswordLen)
	// errPasswordTooLong: bcrypt rejects inputs over 72 bytes
	// (ErrPasswordTooLong) — pre-check it so create maps to a 400 instead of
	// a 500 and change-password returns our text, not the library's
	// (2026-10-19 review m2).
	errPasswordTooLong = fmt.Errorf("password exceeds 72 bytes")
	// errUserExists is the ONLY db error AddUser maps to a user-facing
	// message; every other db failure propagates as a raw error so the
	// handler can 500 it (respondInternal) instead of misreporting it as
	// a duplicate.
	errUserExists = fmt.Errorf("user already exists")
	// errBootstrapped: a concurrent unauthenticated first-user creation
	// won the setup-mode bootstrap (2026-10-19 review F11). The handler
	// maps it to 409 — the install is no longer fresh, the account
	// already exists.
	errBootstrapped = fmt.Errorf("an account already exists — this install is set up")
)

func validUsername(u string) bool {
	return u != "" && len(u) <= maxUsernameLen && usernameRe.MatchString(u)
}

// AddUser validates and creates an account. The first AddUser is what
// enables authentication.
//
// The check-and-create runs in ONE BEGIN IMMEDIATE transaction
// (2026-10-19 review F11): on a fresh install the unauthenticated
// bootstrap POST is open to the whole LAN, and with a DEFERRED begin
// every concurrent first-user POST reads user_count=0 before any of them
// writes — N racers, N "first" accounts. BEGIN IMMEDIATE serializes the
// writers: the winner commits the account (and the auth_bootstrapped flag
// in the SAME transaction, so there is no window where the gate sees a
// user without the flag), the losers see user_count > 0 and get
// errBootstrapped (409). In-app adds (user_count > 0) keep their normal
// path: a duplicate username is errUserExists (400).
func (a *AuthState) AddUser(username, password string) error {
	// In-app / CLI add: the user table may already be populated; a
	// duplicate username is the expected client error (400).
	return a.AddUserMode(username, password, false)
}

// AddUserMode is AddUser with the setup-mode flag made explicit.
// setupMode=true means the caller reached this through the fresh-install
// gate (no account existed when the gate checked, modulo its TTL): in that
// world ONLY the first account may be created. The check must happen INSIDE
// the ImmediateTx, on the serialized connection — the gate's Enabled()
// result is TTL-cached, so N concurrent setup POSTs all pass the gate and
// only the in-tx user_count (n > 0) distinguishes the winner from the
// losers. Without it, four clients with four DIFFERENT usernames all see
// an empty table at the gate, all pass the UNIQUE check (their names don't
// collide), and four "first" accounts are created (2026-10-19 review F11 —
// the ImmediateTx alone does not close the race; this check does).
func (a *AuthState) AddUserMode(username, password string, setupMode bool) error {
	username = strings.ToLower(username)
	if !validUsername(username) {
		return errUsernameInvalid
	}
	if len(password) < minPasswordLen {
		return errPasswordWeak
	}
	if len(password) > 72 { // bcrypt input limit (2026-10-19 review m2)
		return errPasswordTooLong
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return err
	}
	ctx := context.Background()
	err = a.db.ImmediateTx(ctx, func(c *sql.Conn) error {
		var n int
		if err := c.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&n); err != nil {
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
		if _, err := c.ExecContext(ctx,
			"INSERT INTO users (username, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?)",
			username, string(hash), tsNow(), admin); err != nil {
			// Only the exact UNIQUE-constraint text means "account
			// exists" — any other db failure must surface as a 500, not
			// be misreported as a duplicate (2026-10-19 review m7).
			if strings.Contains(err.Error(), "UNIQUE constraint failed: users.username") {
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
			if _, err := c.ExecContext(ctx,
				"INSERT OR REPLACE INTO settings (setting_key, value, updated_at) VALUES ('auth_bootstrapped', '1', ?)",
				tsNow()); err != nil {
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

// Bootstrapped reports whether this install has ever had an account created
// (settings row auth_bootstrapped=1, set by AddUser and never cleared —
// including when the operator later disables auth). The auth gate uses it to
// pick between the two zero-user states: a fresh install gets the
// bootstrap-only surface (no unauthenticated sensor create/pulse before the
// first account exists), an intentionally-disabled install stays fully open.
func (a *AuthState) Bootstrapped() bool {
	return a.db.GetSetting("auth_bootstrapped") == "1"
}

// IsAdmin reports whether the username holds the admin flag — the gate for
// the account-management endpoints (add/remove user, disable auth). A
// deleted or unknown user is not an admin; a db error fails closed.
func (a *AuthState) IsAdmin(username string) bool {
	var n int
	if err := a.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ? AND is_admin = 1", strings.ToLower(username)).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

// RemoveUser deletes an account and every live session it owns. The last
// remaining user is protected — use Disable (auth-off) for that. The count
// below is only a fast path; the authoritative guard is the atomic
// conditional DELETE in db.RemoveUser (2026-10-19 review M4). Removing the
// last admin promotes the oldest remaining user in the same transaction, so
// the install is never left without an admin.
func (a *AuthState) RemoveUser(username string) error {
	username = strings.ToLower(username)
	n, err := a.db.UserCount()
	if err != nil {
		return err
	}
	if n <= 1 {
		return fmt.Errorf("cannot remove the last user — disable authentication instead")
	}
	if err := a.db.RemoveUser(username); err != nil {
		return err
	}
	a.dropUserSessions(username)
	a.refreshEnabledNow() // may be the last user — don't wait for the TTL
	log.Println("Dashboard user removed: " + username)
	return nil
}

// SetUserPassword replaces a user's password and drops that user's other
// sessions (the caller's own session, if any, is kept so "change my
// password" does not log the operator out mid-panel).
func (a *AuthState) SetUserPassword(username, password, keepSession string) error {
	username = strings.ToLower(username)
	if len(password) < minPasswordLen {
		return errPasswordWeak
	}
	if len(password) > 72 { // bcrypt input limit (2026-10-19 review m2)
		return errPasswordTooLong
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
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
func (a *AuthState) VerifyUser(username, password string) (string, bool) {
	username = strings.ToLower(username)
	hash, err := a.db.UserHash(username)
	if err != nil || hash == "" {
		// Fail with a constant-time-ish bcrypt compare against a dummy hash so
		// the "unknown user" and "wrong password" paths take the same time (no
		// username enumeration via timing). dummyBcryptHash is built at
		// bcryptCost — the same cost every stored hash is generated at — so the
		// two paths ALWAYS run at the same KDF cost and can never diverge into
		// a timing oracle if bcryptCost is ever raised. It is precomputed (see
		// dummyBcryptHash) so a failed lookup doesn't re-format the string.
		bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))
		return "", false
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return "", false
	}
	return username, true
}

// CreateSession validates the credentials and returns a new opaque session
// token tied to the user.
func (a *AuthState) CreateSession(username, password string) (string, bool) {
	user, ok := a.VerifyUser(username, password)
	if !ok {
		return "", false
	}
	tok, err := newSessionToken()
	if err != nil {
		return "", false
	}
	a.mu.Lock()
	now := time.Now()
	// Re-verify the account STILL exists, under the session-map lock,
	// BEFORE minting (2026-10-19 review F2): VerifyUser's bcrypt check ran
	// against the hash as of a moment ago; a concurrent RemoveUser in that
	// gap used to mint a live 30-day session for an already-deleted user.
	// This is a live check (no cache): the mint path is cold (login rate),
	// and the first validation of the new token is live too (CreateSession
	// never populates userOKCache), so the race window is zero.
	if !a.userExists(user) {
		a.mu.Unlock()
		return "", false
	}
	// Opportunistic GC: see sweepExpiredSessions. Bounded O(n) work, run
	// only once the map is large enough that abandoned sessions are the
	// likely cause (mirrors sweepThrottle for the login-throttle maps).
	if len(a.sessions) > 64 {
		a.sweepExpiredSessions(now)
	}
	a.sessions[tok] = authSession{user: user, expiry: now.Add(authSessionTTL)}
	a.mu.Unlock()
	return tok, true
}

// sweepExpiredSessions evicts sessions whose TTL has lapsed. Expired
// entries are already rejected — and individually deleted — by
// ValidSession/SessionUser when their token is presented; this sweep
// covers the rest: abandoned sessions whose cookie was discarded and
// will never be presented again, which would otherwise pin their map
// entries for the process's entire uptime. It is called opportunistically
// from CreateSession once the map grows past a threshold (no goroutine,
// no ticker — mirrors sweepThrottle). Caller must hold a.mu.
func (a *AuthState) sweepExpiredSessions(now time.Time) {
	for tok, s := range a.sessions {
		if now.After(s.expiry) {
			delete(a.sessions, tok)
		}
	}
	for u, t := range a.userOKCache {
		if now.After(t.Add(userOKTTL)) {
			delete(a.userOKCache, u)
		}
	}
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
// counter and brute-force past loginFailMax.
//
// When PULSEMON_TRUSTED_PROXIES lists the CIDR(s) of the immediate TCP peer
// (a reverse proxy in front of pulsemon), X-Forwarded-For is walked RIGHT to
// LEFT and the first entry that parses and is NOT itself a trusted proxy is
// used — attributing attempts to the real client, not the proxy. Rightmost-
// untrusted, not leftmost: proxies APPEND, so everything left of the hop our
// proxy added is client-supplied and rotatable per request (2026-10-19
// review M3a). If every entry is trusted (nested trusted proxies only), the
// leftmost parseable entry is used.
// Trusting the header is gated on the PEER being in a trusted CIDR, so the
// header is only ever read from a connection we know is our proxy; a direct
// attacker (peer not in the list) gets the peer address and their rotation
// attempt is pointless.
//
// X-Forwarded-For is trusted ONLY for rate-limiting — it is never used for
// authentication.
func (a *AuthState) ClientIP(r *http.Request) string {
	peer := peerIP(r)
	if a.trustedPeer(peer) {
		// Combine ALL X-Forwarded-For lines before parsing (2026-10-19
		// review N7): HAProxy-style proxies APPEND a new header line
		// instead of extending the first, and r.Header.Get returns only
		// the first — the CLIENT-CONTROLLED one. Reading it alone
		// attributed every attempt to the attacker's chosen address.
		// Joining with "," and running the existing rightmost-untrusted
		// parse over the combined list keeps the original semantics for
		// single-line XFF.
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
	}
	return peer
}

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

// throttleKey maps a client IP to its login-throttle bucket (2026-10-19
// review M3b, refined by external review #7):
//
//   - private (RFC1918) and loopback IPv4 → the exact address (/32): on a
//     LAN each device is a distinct host with no address rotation, so a
//     shared /24 bucket let one misbehaving client (stale saved password,
//     an old polling script) lock out every other device on the homelab
//     subnet for loginLockout.
//   - other IPv4 → the /24: an internet attacker rotating within a /24
//     stays in one bucket.
//   - IPv6 → the /64: one host owns a whole /64 (privacy-extension
//     rotation), so per-address keying handed it 2^64 separate budgets.
//
// An unparseable string is returned as-is.
func throttleKey(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ip
	}
	if v4 := p.To4(); v4 != nil {
		if v4.IsPrivate() || v4.IsLoopback() {
			return v4.String()
		}
		return fmt.Sprintf("%d.%d.%d.0", v4[0], v4[1], v4[2])
	}
	return p.Mask(net.CIDRMask(64, 128)).String()
}

// ensureThrottleMaps lazily initializes the throttle maps (cheap, idempotent).
func (a *AuthState) ensureThrottleMaps() {
	if a.loginThrottle.fails == nil {
		a.loginThrottle.fails = map[string][]time.Time{}
	}
	if a.loginThrottle.lockout == nil {
		a.loginThrottle.lockout = map[string]time.Time{}
	}
}

// beginAttempt atomically decides whether ip may run a credential check
// NOW, and if so records the attempt in the SAME critical section — before
// the caller runs bcrypt. Counting first is what closes the concurrency
// bypass: the old check-then-KDF-then-record shape let N parallel requests
// all pass loginAllowed before any of them recorded a failure, so a burst
// ran the KDF N times (repro: 60 concurrent -> 59x 401). With the count
// inside the lock, at most loginFailMax concurrent attempts can pass; the
// rest get a fast 429 without touching the KDF.
//
// Returns (false, how-long-until-the-lockout-lifts) when the IP is locked
// out or has exhausted its window; the caller answers 429 + Retry-After.
// A failed attempt is NOT recorded again by the caller — it is already
// counted here, for success OR failure alike (a success clears the counter
// via loginSuccess).
func (a *AuthState) beginAttempt(ip string) (bool, time.Duration) {
	a.loginThrottle.Lock()
	defer a.loginThrottle.Unlock()
	a.ensureThrottleMaps()
	now := time.Now()
	// Opportunistic GC: see sweepThrottle. Bounded O(n) work, run only once
	// the map is large enough that a multi-IP spray is the likely cause.
	if len(a.loginThrottle.fails) > 1024 {
		a.sweepThrottle(now)
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

// loginSuccess clears all failure accounting for ip.
func (a *AuthState) loginSuccess(ip string) {
	a.loginThrottle.Lock()
	defer a.loginThrottle.Unlock()
	a.ensureThrottleMaps()
	delete(a.loginThrottle.fails, ip)
	delete(a.loginThrottle.lockout, ip)
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
}

// ValidSession validates a session token: a live hit slides its expiry
// forward; an unknown OR expired token is rejected AND deleted — the
// returned value is the expiry test, never just a map hit. The owner's
// account is re-checked against the users table (TTL-cached, see
// userOKTTL) so a user deleted out-of-band (CLI `auth-user remove`) is
// rejected within the window even though the in-memory map can't know
// about it (2026-10-19 review F1).
func (a *AuthState) ValidSession(tok string) bool {
	if tok == "" {
		return false
	}
	a.mu.Lock()
	s, ok := a.sessions[tok]
	if ok && time.Now().Before(s.expiry) && a.userExistsCached(s.user) {
		s.expiry = time.Now().Add(authSessionTTL)
		a.sessions[tok] = s
	} else {
		ok = false
		delete(a.sessions, tok)
	}
	a.mu.Unlock()
	return ok
}

// SessionUser returns the username a live session belongs to, validating
// the expiry (and deleting the entry if it has lapsed) so the result is
// safe to use as an authorization check on its own. Like ValidSession it
// re-checks the owner against the users table (TTL-cached): the in-memory
// session map alone cannot see an out-of-band account deletion
// (2026-10-19 review F1).
func (a *AuthState) SessionUser(tok string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[tok]
	if !ok || !time.Now().Before(s.expiry) {
		delete(a.sessions, tok)
		return "", false
	}
	if !a.userExistsCached(s.user) {
		delete(a.sessions, tok)
		return "", false
	}
	return s.user, true
}

// DropSession removes one session (logout).
func (a *AuthState) DropSession(tok string) {
	a.mu.Lock()
	delete(a.sessions, tok)
	a.mu.Unlock()
}

func (a *AuthState) dropUserSessions(username string) {
	a.mu.Lock()
	for tok, s := range a.sessions {
		if s.user == username {
			delete(a.sessions, tok)
		}
	}
	a.mu.Unlock()
}

func (a *AuthState) dropUserSessionsExcept(username, keepTok string) {
	a.mu.Lock()
	for tok, s := range a.sessions {
		if s.user == username && tok != keepTok {
			delete(a.sessions, tok)
		}
	}
	a.mu.Unlock()
}

// Disable removes ALL users, opening the dashboard again.
func (a *AuthState) Disable() error {
	if err := a.db.RemoveAllUsers(); err != nil {
		return err
	}
	a.mu.Lock()
	a.sessions = map[string]authSession{}
	a.mu.Unlock()
	a.refreshEnabledNow() // all users gone — open the dashboard immediately
	log.Println("Dashboard authentication disabled (all users removed)")
	return nil
}

// newSessionToken returns an opaque random session id (base64url, 192 bits
// of entropy — it lives only in the cookie and the in-memory map).
func newSessionToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// ---------- handlers ----------

type authStatusPayload struct {
	Enabled bool   `json:"enabled"`
	Authed  bool   `json:"authed"`
	User    string `json:"user,omitempty"`
}

// sessionFrom returns the username the request's session belongs to
// ("" when there is no live session).
func (s *Server) sessionFrom(r *http.Request) string {
	c, err := r.Cookie(authSessionName)
	if err != nil {
		return ""
	}
	user, ok := s.auth.SessionUser(c.Value)
	if !ok {
		return ""
	}
	return user
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	user := s.sessionFrom(r)
	respondWithJSON(w, http.StatusOK, authStatusPayload{
		Enabled: s.auth.Enabled(),
		Authed:  user != "",
		User:    user,
	})
}

// handleAuthLogin is the only unauthenticated credential-checking endpoint,
// so its DoS surface is the per-IP throttle, not a global concurrency cap.
//
// Security-review note (deliberate, do NOT "fix" with an in-flight bcrypt
// semaphore): the single-attacker vector is already closed — beginAttempt
// counts the attempt inside the throttle lock BEFORE any bcrypt runs, so at
// most loginFailMax concurrent attempts can reach the KDF (7 fails/60s -> 5
// min lockout, plus a constant 200ms delay on every 401 capping ~5
// guesses/s/IP), and ClientIP keys the throttle to the TCP peer (a spoofed
// X-Forwarded-For from an untrusted peer is ignored), so the counter cannot
// be rotated to dodge the lockout. The only residual is a MULTI-source-IP
// botnet — the classic per-IP-limit bypass — which is OUT of this tool's
// threat model (single-operator LAN dashboard, not an anonymous internet
// endpoint; see the file header). Bounding bcrypt concurrency in-app does not
// stop that vector, and a non-blocking semaphore (select/default -> reject)
// would actively REGRESS legitimate logins: under attack the 2 slots stay
// busy with the attacker's requests and every real operator login hits the
// default branch and fails at the exact moment they most need to get in to
// check the degraded dashboard. If this ever becomes internet-facing, the
// right hardening is a GLOBAL in-flight cap that QUEUES (blocking select with
// a timeout) rather than fails, or a connection cap / fail2ban at the reverse
// proxy (which PULSEMON_TRUSTED_PROXIES already anticipates) — not an in-app
// semaphore that locks the operator out.
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		// Malformed / missing credentials: 400, and NOT counted against the
		// login throttle — these never run the bcrypt KDF, so they're not a
		// credential attempt (and not an online-cracking vector).
		respondWithError(w, http.StatusBadRequest, "username and password required")
		return
	}

	// Per-IP failure throttle: reject a locked-out client FAST, before any
	// bcrypt work (the KDF is the expensive part, and a locked-out attacker
	// shouldn't get to run it at all). beginAttempt counts the attempt in
	// the SAME locked section that admits it — a failed attempt is NOT
	// recorded again below, it is already counted here.
	// The throttle is bucketed, not keyed on the full address: private and
	// loopback IPv4 per host (/32 — LAN devices are distinct hosts, and a
	// shared /24 budget let one client lock out the whole homelab subnet),
	// other IPv4 by /24 (an attacker rotating within a /24 stays in one
	// bucket), IPv6 by /64 (one host owns a whole /64 via
	// privacy-extension rotation, so per-address keying handed it 2^64
	// separate budgets) (2026-10-19 review M3b + external review #7). ip
	// stays the full address for log lines.
	ip := s.auth.ClientIP(r)
	key := throttleKey(ip)
	if ok, wait := s.auth.beginAttempt(key); !ok {
		secs := int((wait + time.Second - 1) / time.Second)
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		respondWithError(w, http.StatusTooManyRequests, "too many failed login attempts — try again in a few minutes")
		return
	}

	tok, ok := s.auth.CreateSession(req.Username, req.Password)
	if !ok {
		// Constant-time-ish delay on rejection: equalizes response time across
		// the unknown-user / wrong-password paths (closes the timing oracle)
		// and caps an online attacker at ~5 guesses/second per IP. The
		// attempt was already counted by beginAttempt before the KDF.
		time.Sleep(loginSlowDown)
		respondWithError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	s.auth.loginSuccess(key)
	s.setAuthCookie(w, r, tok)
	respondWithJSON(w, http.StatusOK, authStatusPayload{Enabled: true, Authed: true, User: strings.ToLower(req.Username)})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if c, err := r.Cookie(authSessionName); err == nil {
		s.auth.DropSession(c.Value)
	}
	s.setAuthCookie(w, r, "")
	respondWithJSON(w, http.StatusOK, authStatusPayload{Enabled: s.auth.Enabled(), Authed: false})
}

// requireAuth runs h only for a valid session; otherwise 401 — but only
// while authentication is enabled. With auth off the dashboard is fully
// open, and creating the FIRST account (the bootstrap) happens through
// exactly these endpoints: the "Create First Account" button in Settings
// and, once the first user exists, normal user management.
func (s *Server) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.auth.Enabled() && s.sessionFrom(r) == "" {
			respondWithError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		h(w, r)
	}
}

func (s *Server) handleAuthUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// requireAuth wraps this route (see routes()).
		users, err := s.db.ListUsers()
		if err != nil {
			respondInternal(w, "list users", err)
			return
		}
		respondWithJSON(w, http.StatusOK, users)
	case http.MethodPost:
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			code, msg := requestBodyErr(err)
			respondWithError(w, code, msg)
			return
		}
		// setupMode mirrors the fresh-install gate: unauthenticated
		// POSTs only reach here while Enabled() is false (TTL-cached),
		// so the in-tx user_count is the real arbiter (review F11).
		// An authenticated admin add is never setup mode.
		_, sessErr := r.Cookie(authSessionName)
		setup := sessErr != nil && !s.auth.Enabled()
		// Account creation is an admin operation: the setup-mode
		// bootstrap (unauthenticated, first user) stays open, but an
		// authenticated NON-admin session cannot mint accounts —
		// otherwise a shared/compromised helper account grows its own
		// persistence (2026-10-19 external review, admin-flag fix).
		if !setup && !s.auth.IsAdmin(s.sessionFrom(r)) {
			respondWithError(w, http.StatusForbidden, "admin only")
			return
		}
		if err := s.auth.AddUserMode(req.Username, req.Password, setup); err != nil {
			// Only the duplicate-account and validation cases are client
			// errors; any other failure (db, KDF) is a 500 with the detail
			// logged. Validation sentinels (incl. the 72-byte bcrypt limit)
			// are 400, not 500 (2026-10-19 review m2). A lost setup-mode
			// bootstrap race is a 409: the winner's account already
			// exists (2026-10-19 review F11).
			if errors.Is(err, errUserExists) || errors.Is(err, errUsernameInvalid) ||
				errors.Is(err, errPasswordWeak) || errors.Is(err, errPasswordTooLong) {
				respondWithError(w, http.StatusBadRequest, err.Error())
				return
			}
			if errors.Is(err, errBootstrapped) {
				respondWithError(w, http.StatusConflict, err.Error())
				return
			}
			respondInternal(w, "add user", err)
			return
		}
		respondWithJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleAuthUserPassword changes the password of the CALLER's own account
// only (the {username} in the path must match the session's user — anyone
// else gets 404, not 403, so the endpoint doesn't even confirm other
// usernames exist).
func (s *Server) handleAuthUserPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	caller := s.sessionFrom(r)
	user := strings.ToLower(r.PathValue("username"))
	if user != caller {
		respondWithError(w, http.StatusNotFound, "not found")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		code, msg := requestBodyErr(err)
		respondWithError(w, code, msg)
		return
	}
	keep := ""
	if c, err := r.Cookie(authSessionName); err == nil {
		keep = c.Value
	}
	if err := s.auth.SetUserPassword(user, req.Password, keep); err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondWithJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAuthUserDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Removing an account is an admin operation (the UI offers it to
	// admins only). Self-removal is allowed — the last-user guard in
	// db.RemoveUser stops it from ever locking the install out, and
	// removing the last admin promotes the oldest remaining user
	// (2026-10-19 external review, admin-flag fix).
	if !s.auth.IsAdmin(s.sessionFrom(r)) {
		respondWithError(w, http.StatusForbidden, "admin only")
		return
	}
	user := strings.ToLower(r.PathValue("username"))
	if err := s.auth.RemoveUser(user); err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondWithJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleAuthDisable removes every user, opening the dashboard. The
// operator's own session dies with the last user, so the UI re-shows the
// login gate — which, with zero users, immediately becomes the open
// dashboard.
func (s *Server) handleAuthDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Disabling auth wipes EVERY account and opens the dashboard to the
	// whole LAN — admin only (2026-10-19 external review, admin-flag fix).
	if !s.auth.IsAdmin(s.sessionFrom(r)) {
		respondWithError(w, http.StatusForbidden, "admin only")
		return
	}
	if err := s.auth.Disable(); err != nil {
		respondInternal(w, "disable auth", err)
		return
	}
	s.setAuthCookie(w, r, "")
	respondWithJSON(w, http.StatusOK, authStatusPayload{Enabled: false, Authed: false})
}

// setAuthCookie sets (or, with an empty value, clears) the session cookie.
// A clear uses a past Expires so the browser drops the cookie outright
// (the value alone is not enough — an empty-valued cookie with a future
// expiry is retained by some browsers). Secure is applied on HTTPS
// requests — including plain-HTTP requests arriving from a trusted
// TLS-terminating reverse proxy (see cookieSecure) — so a proxied install
// never hands the session token to a plaintext hop. On a direct plain-HTTP
// LAN install it is omitted so the dashboard keeps working.
func (s *Server) setAuthCookie(w http.ResponseWriter, r *http.Request, value string) {
	expires := time.Now().Add(authSessionTTL)
	if value == "" {
		expires = time.Unix(0, 0) // past: delete the cookie
	}
	http.SetCookie(w, &http.Cookie{
		Name:     authSessionName,
		Value:    value,
		Path:     "/",
		Domain:   "",
		Expires:  expires,
		Secure:   s.cookieSecure(r),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// cookieSecure reports whether the session cookie should carry the Secure
// flag: always over TLS, and — for a TLS-terminating reverse proxy — when
// the immediate TCP peer is in PULSEMON_TRUSTED_PROXIES and reports the
// original scheme as https. The header is only trusted from a peer we've
// explicitly whitelisted (the same rule ClientIP uses for X-Forwarded-For),
// so a direct attacker cannot spoof it into a Secure cookie (or dodge one).
func (s *Server) cookieSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return s.auth.trustedPeer(peerIP(r)) &&
		strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
