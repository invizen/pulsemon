package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
		db:       db,
		sessions: map[string]authSession{},
	}
	a.trustedProxies = parseTrustedProxies(os.Getenv("PULSEMON_TRUSTED_PROXIES"))
	return a
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
	a.enabled = err == nil && n > 0
	a.enabledAt = time.Now()
	return a.enabled
}

// refreshEnabledNow re-reads the user count and updates the Enabled() cache
// immediately. Called by the in-app user mutations (AddUser/RemoveUser/
// Disable) so the gate reflects them on the very next request with no TTL
// wait. An out-of-band CLI write takes its OWN AuthState on a separate DB
// handle and never reaches this method — which is exactly why the TTL exists.
func (a *AuthState) refreshEnabledNow() {
	a.enabledMu.Lock()
	defer a.enabledMu.Unlock()
	fn := a.userCountFn
	if fn == nil {
		fn = a.db.UserCount
	}
	n, err := fn()
	a.enabled = err == nil && n > 0
	a.enabledAt = time.Now()
}

// UserCount/CRUD live on *DB (see db.go); AuthState adds the password
// hashing, validation, and session bookkeeping on top.

var (
	errUsernameInvalid = fmt.Errorf("username must start with a letter and contain only letters, digits, . _ - (max %d)", maxUsernameLen)
	errPasswordWeak    = fmt.Errorf("password must be at least %d characters", minPasswordLen)
)

func validUsername(u string) bool {
	return u != "" && len(u) <= maxUsernameLen && usernameRe.MatchString(u)
}

// AddUser validates and creates an account. The first AddUser is what
// enables authentication.
func (a *AuthState) AddUser(username, password string) error {
	username = strings.ToLower(username)
	if !validUsername(username) {
		return errUsernameInvalid
	}
	if len(password) < minPasswordLen {
		return errPasswordWeak
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return err
	}
	if err := a.db.AddUser(username, string(hash)); err != nil {
		return fmt.Errorf("user already exists")
	}
	a.refreshEnabledNow() // first user enables auth — don't wait for the TTL
	log.Println("Dashboard user added: " + username)
	return nil
}

// RemoveUser deletes an account and every live session it owns. The last
// remaining user is protected — use Disable (auth-off) for that.
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
	a.sessions[tok] = authSession{user: user, expiry: time.Now().Add(authSessionTTL)}
	a.mu.Unlock()
	return tok, true
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
// (a reverse proxy in front of pulsemon), the first X-Forwarded-For entry is
// used instead — attributing attempts to the real client, not the proxy.
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
		if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
			if ip := net.ParseIP(strings.TrimSpace(strings.Split(xf, ",")[0])); ip != nil {
				return ip.String()
			}
		}
	}
	return peer
}

// trustedPeer reports whether the IP string (host, no port) is inside any of
// the trusted-proxy CIDRs. An unparseable IP is never trusted.
func (a *AuthState) trustedPeer(ip string) bool {
	if len(a.trustedProxies) == 0 {
		return false
	}
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	for _, n := range a.trustedProxies {
		if n.Contains(p) {
			return true
		}
	}
	return false
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

// loginAllowed reports whether ip may attempt a login now, and if not, how
// long until the lockout lifts. It prunes failed-attempt timestamps older
// than loginFailWindow so a long-ago burst can't pin an IP.
func (a *AuthState) loginAllowed(ip string) (bool, time.Duration) {
	a.loginThrottle.Lock()
	defer a.loginThrottle.Unlock()
	a.ensureThrottleMaps()
	now := time.Now()
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
	a.loginThrottle.fails[ip] = kept
	return len(kept) < loginFailMax, 0
}

// loginFailed records a failed attempt for ip; once the rolling window hits
// loginFailMax the IP is locked out for loginLockout.
func (a *AuthState) loginFailed(ip string) {
	a.loginThrottle.Lock()
	defer a.loginThrottle.Unlock()
	a.ensureThrottleMaps()
	now := time.Now()
	cutoff := now.Add(-loginFailWindow)
	fails := a.loginThrottle.fails[ip]
	kept := fails[:0]
	for _, t := range fails {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	if len(kept) >= loginFailMax {
		a.loginThrottle.lockout[ip] = now.Add(loginLockout)
		a.loginThrottle.fails[ip] = kept
		return
	}
	a.loginThrottle.fails[ip] = kept
}

// loginSuccess clears all failure accounting for ip.
func (a *AuthState) loginSuccess(ip string) {
	a.loginThrottle.Lock()
	defer a.loginThrottle.Unlock()
	a.ensureThrottleMaps()
	delete(a.loginThrottle.fails, ip)
	delete(a.loginThrottle.lockout, ip)
}

// ValidSession validates a session token: a live hit slides its expiry
// forward; an unknown OR expired token is rejected AND deleted — the
// returned value is the expiry test, never just a map hit.
func (a *AuthState) ValidSession(tok string) bool {
	if tok == "" {
		return false
	}
	a.mu.Lock()
	s, ok := a.sessions[tok]
	if ok && time.Now().Before(s.expiry) {
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
// safe to use as an authorization check on its own.
func (a *AuthState) SessionUser(tok string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[tok]
	if !ok || !time.Now().Before(s.expiry) {
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
	// shouldn't get to run it at all).
	ip := s.auth.ClientIP(r)
	if ok, wait := s.auth.loginAllowed(ip); !ok {
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
		s.auth.loginFailed(ip)
		// Constant-time-ish delay on rejection: equalizes response time across
		// the unknown-user / wrong-password paths (closes the timing oracle)
		// and caps an online attacker at ~5 guesses/second per IP.
		time.Sleep(loginSlowDown)
		respondWithError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	s.auth.loginSuccess(ip)
	setAuthCookie(w, r, tok)
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
	setAuthCookie(w, r, "")
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
			respondWithError(w, http.StatusInternalServerError, err.Error())
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
		if err := s.auth.AddUser(req.Username, req.Password); err != nil {
			respondWithError(w, http.StatusBadRequest, err.Error())
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
	if err := s.auth.Disable(); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	setAuthCookie(w, r, "")
	respondWithJSON(w, http.StatusOK, authStatusPayload{Enabled: false, Authed: false})
}

// setAuthCookie sets (or, with an empty value, clears) the session cookie.
// Secure is applied on HTTPS requests; on plain HTTP it is omitted so a
// LAN-only install keeps working.
func setAuthCookie(w http.ResponseWriter, r *http.Request, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     authSessionName,
		Value:    value,
		Path:     "/",
		Domain:   "",
		Expires:  time.Now().Add(authSessionTTL),
		Secure:   r.TLS != nil,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}
