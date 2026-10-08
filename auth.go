package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
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
// No brute-force lockout: this is a self-hosted tool behind a real
// credential; the threat model is "a public URL must not expose the
// dashboard", not "an anonymous internet scanner must not probe it".

const (
	authSessionName = "pulsemon_session"
	authSessionTTL  = 30 * 24 * time.Hour
	bcryptCost      = bcrypt.DefaultCost
	minPasswordLen  = 8
	maxUsernameLen  = 32
)

// usernameRe: starts with a letter, then letters/digits/._- . Stored
// lowercase; the UNIQUE constraint is on the lower-cased column value.
var usernameRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9._-]*$`)

type authSession struct {
	user   string
	expiry time.Time
}

type AuthState struct {
	db *DB

	mu       sync.Mutex
	sessions map[string]authSession // session token → owner + expiry
}

func NewAuthState(db *DB) *AuthState {
	return &AuthState{
		db:       db,
		sessions: map[string]authSession{},
	}
}

// Enabled reports whether at least one user exists. Read from the DB on
// every call (one indexed COUNT) so an out-of-band `pulsemon auth-user
// add/remove` takes effect on the very next request — no restart.
func (a *AuthState) Enabled() bool {
	n, err := a.db.UserCount()
	return err == nil && n > 0
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
		// Fail with a constant-time-ish bcrypt compare against a dummy
		// hash so the "unknown user" and "wrong password" paths take the
		// same time (no username enumeration via timing).
		dummy := "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
		bcrypt.CompareHashAndPassword([]byte(dummy), []byte(password))
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

// ValidSession reports whether the session token is live; a live hit
// slides the expiry forward. An expired token is rejected AND deleted —
// the returned value is the expiry test, never just a map hit.
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
	if err := a.db.RemoveallUsers(); err != nil {
		return err
	}
	a.mu.Lock()
	a.sessions = map[string]authSession{}
	a.mu.Unlock()
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
		respondWithError(w, http.StatusBadRequest, "username and password required")
		return
	}
	tok, ok := s.auth.CreateSession(req.Username, req.Password)
	if !ok {
		respondWithError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
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
			respondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
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
		respondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
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
