// auth_handlers.go — the /api/auth/* HTTP handlers and the
// requireAuth/requireAdmin middleware that wrap the rest of the API.
// History: docs/DECISIONS.md -> login-lockout-429-refund,
// oversized-login-guard, password-endpoint-userlock
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"pulsemon/internal/store"
)

type authStatusPayload struct {
	Enabled bool   `json:"enabled"`
	Authed  bool   `json:"authed"`
	User    string `json:"user,omitempty"`
	// Bootstrapped distinguishes the two "off" states for the UI: a
	// fresh install (no account has ever existed) offers the bootstrap
	// button, an operator-disabled install (flag set) must show the CLI
	// re-enable hint instead — unauthenticated account creation is
	// refused server-side there.
	Bootstrapped bool `json:"bootstrapped,omitempty"`
}

// authUserCtxKey is the request-context key for the authenticated
// username, stashed by authGate after ValidSession succeeds. Handlers
// read it via sessionFrom, which avoids the second SessionUser lookup
// (and its second expiry slide) that the old per-handler cookie re-read
// performed.
type authUserCtxKey int

const authUserCtxKeyVal authUserCtxKey = 0

func authUserFromContext(r *http.Request) string {
	if u, ok := r.Context().Value(authUserCtxKeyVal).(string); ok {
		return u
	}
	return ""
}

// sessionFrom returns the username the request's session belongs to
// ("" when there is no live session).
//
// The fast path reads the username authGate stashed in the request
// context (one SessionUser lookup per request, not three). The cookie
// fallback covers routes that bypass authGate (tests, /api/auth/status
// which is gate-exempt).
func (s *Server) sessionFrom(r *http.Request) string {
	if u := authUserFromContext(r); u != "" {
		return u
	}
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
		Enabled:      s.auth.Enabled(),
		Authed:       user != "",
		User:         user,
		Bootstrapped: s.auth.Bootstrapped(),
	})
}

// handleAuthLogin validates credentials and issues a session cookie — the
// only unauthenticated credential-checking endpoint, so its DoS surface is
// the per-IP throttle PLUS the per-username account budget, not a global
// concurrency cap.
//
//   - Body decoded first, then username/password length-checked
//     (maxUsernameLen / 72) BEFORE anything else — a 1 MiB credential must
//     not reach the throttle maps or a bcrypt KDF (History: docs/DECISIONS.md → oversized-login-guard).
//   - beginAttempt (per-IP) and checkUserLock (per-username, known-good
//     exempt) run BEFORE the KDF, count inside the admission lock, and
//     answer 429 + Retry-After, never 401; non-KDF rejections refund the
//     admission (History: docs/DECISIONS.md → login-lockout-429-refund,
//     throttle-edge-cases).
//   - Every rejected 401 sleeps loginSlowDown (the timing equalizer);
//     bcrypt runs under bcryptSem; setup mode is single-shot via the in-tx
//     user_count check (see AddUser). Residual multi-IP botnet: OUT of
//     this tool's threat model — cap it at the reverse proxy.
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		// Shared mapper like every other JSON handler: oversized body
		// (authGate's MaxBytesReader) → 413, other decode errors → 400.
		code, msg := requestBodyErr(err)
		respondWithError(w, code, msg)
		return
	}
	if req.Username == "" || req.Password == "" {
		// Missing credentials: 400, NOT counted against the login throttle
		// — no KDF runs, so it's not a credential attempt.
		respondWithError(w, http.StatusBadRequest, "username and password required")
		return
	}
	if len(req.Username) > maxUsernameLen || len(req.Password) > 72 {
		// Structurally unmatchable: AddUserMode enforces both bounds at
		// creation and bcrypt rejects inputs over 72 bytes — a longer
		// credential can never verify. Same category as empty credentials:
		// no KDF runs, so 400, uncharged, and BEFORE the ToLower /
		// checkUserLock hash / userExists binding an attacker used to pay
		// 1 MiB per request (setup rejects these pre-KDF via sentinels).
		if len(req.Username) > maxUsernameLen {
			respondWithError(w, http.StatusBadRequest, fmt.Sprintf("username exceeds %d characters", maxUsernameLen))
		} else {
			respondWithError(w, http.StatusBadRequest, "password exceeds 72 bytes")
		}
		return
	}

	// Per-IP failure throttle: reject a locked-out client FAST, before any
	// bcrypt work. beginAttempt counts the attempt in the SAME locked
	// section that admits it — not recorded again below. Bucketed, not
	// keyed on the full address (see throttleKey); full address in logs.
	ip := s.auth.ClientIP(r)
	key := throttleKey(ip)
	if ok, wait := s.auth.beginAttempt(key); !ok {
		respondThrottled(w, wait, "too many failed login attempts — try again in a few minutes")
		return
	}

	// Per-username lockout: the per-IP throttle above can't see a multi-IP
	// attacker hammering one account, so this second gate checks the
	// account's own failure budget — AFTER the per-IP gate. The KDF is
	// skipped, so the rejection does not increment the account counter.
	userKey := strings.ToLower(req.Username)
	if ok, wait := s.auth.checkUserLock(userKey, key); !ok {
		// Refund the per-IP admission beginAttempt appended: the account
		// lockout rejects BEFORE the KDF, so no cost was paid — the same
		// refund contract the setup-bootstrap path honors ("throttling is
		// for KDF cost"). Without it, an attacker who locks the account
		// from IP A also locks out every fresh-IP client (no known-good
		// exemption) that clicks "Sign In" loginFailMax times at the 429.
		s.auth.refundAttempt(key)
		respondThrottled(w, wait, "too many failed login attempts — try again in a few minutes")
		return
	}

	tok, ok, kdfRan := s.auth.CreateSession(r.Context(), req.Username, req.Password, s.cookieSecure(r))
	if !ok {
		// Client already gone (disconnected while queued on bcryptSem): a
		// disconnect is not a failed password attempt, so it must not burn
		// the account's failure budget, and the rejection delay buys
		// nothing for a response nobody reads.
		if r.Context().Err() != nil {
			// Refund the per-IP admission — but ONLY when the KDF never
			// ran. kdfRan is CreateSession's explicit acquire-site signal
			// (false = canceled in the queue, zero cost; true = a slot was
			// taken and bcrypt ran to completion, ctx or not). The old
			// elapsed-time floor (kdfCostFloor) was a heuristic that
			// failed both ways: on fast CPUs (cost 10 in 20–25ms) a PAID
			// KDF read as "fast" and got refunded — an unbounded per-IP
			// guessing channel with recordUserFail and loginSlowDown
			// skipped; under a saturated semaphore a legitimate queue
			// wait ≥25ms read as "paid" and was NOT refunded — operator
			// self-lockout.
			if !kdfRan {
				s.auth.refundAttempt(key)
			}
			return
		}
		// Count the failure against the account (across all IPs) — the
		// per-username layer the per-IP budget can't see. EXISTING accounts
		// only: a failure for a name with no account protects nothing (the
		// dummy-hash equalizer already hides the distinction), and the
		// username is attacker-chosen — counting unknown names let a small
		// IP pool rotate random names and grow userFails without bound.
		// Cold path: no timing oracle. History: docs/DECISIONS.md →
		// userfails-bound.
		if s.auth.userExists(userKey) {
			s.auth.recordUserFail(userKey)
		}
		// Constant-time-ish delay on rejection: equalizes the unknown-user /
		// wrong-password paths (closes the timing oracle), ~5 guesses/s/IP.
		time.Sleep(loginSlowDown)
		respondWithError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	s.auth.loginSuccess(userKey, key)
	s.auth.clearUserFail(userKey) // success resets the account's budget
	s.setAuthCookie(w, r, tok, false)
	respondWithJSON(w, http.StatusOK, authStatusPayload{Enabled: true, Authed: true, User: strings.ToLower(req.Username), Bootstrapped: true})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if c, err := r.Cookie(authSessionName); err == nil {
		s.auth.DropSession(c.Value)
	}
	s.setAuthCookie(w, r, "", false)
	respondWithJSON(w, http.StatusOK, authStatusPayload{Enabled: s.auth.Enabled(), Authed: false, Bootstrapped: s.auth.Bootstrapped()})
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

// requireAdmin runs h only for a valid session that holds the admin flag:
// 401 when there is no session, 403 for a non-admin — but only while
// authentication is enabled. With auth off the dashboard is fully open
// (the "auth off = fully open" contract), so the admin gate stands down
// with the auth gate, exactly like requireAuth. Applied to the mutating
// admin surface (self-update, settings incl. test, TLS cert/key,
// wipe-all-history): a regular account is lower-trust and must not swap
// the binary, repoint alerts, change certs, or wipe data.
// History: docs/DECISIONS.md → admin-gate double session check.
func (s *Server) requireAdmin(h http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if s.auth.Enabled() && !s.auth.IsAdmin(s.sessionFrom(r)) {
			respondWithError(w, http.StatusForbidden, "admin only")
			return
		}
		h(w, r)
	})
}

func (s *Server) handleAuthUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// requireAuth wraps this route (see routes()). The FULL roster
		// (every username/created_at/is_admin) is admin-facing data — the
		// users panel that consumes it is admin-gated, and the client
		// hiding the panel was never a server gate.
		// A non-admin session sees only its own row.
		users, err := s.db.ListUsers()
		if err != nil {
			respondInternal(w, "list users", err)
			return
		}
		if caller := s.sessionFrom(r); !s.auth.IsAdmin(caller) {
			mine := make([]store.AuthUser, 0, 1)
			for _, u := range users {
				if u.Username == caller {
					mine = append(mine, u)
				}
			}
			users = mine
		}
		respondWithJSON(w, http.StatusOK, users)
	case http.MethodPost:
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			// Required on the ADMIN-ADD path only (external review L1,
			// 2026-11-23): the session minting a new account must prove
			// it is its owner. Ignored in setup mode (there is no
			// session by definition) — the field is optional there.
			Current string `json:"current_password"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			code, msg := requestBodyErr(err)
			respondWithError(w, code, msg)
			return
		}
		// setupMode mirrors the fresh-install gate: unauthenticated POSTs
		// only reach here while Enabled() is false (TTL-cached), so the
		// in-tx user_count is the real arbiter. An authenticated admin add
		// is never setup mode. Key setup off a VALID session (sessionFrom),
		// not raw cookie presence: a stale pulsemon_session cookie (30-day
		// TTL, or one replayed via curl) would make setup=false and 403 the
		// legitimate "Create First Account" bootstrap — sessionFrom returns
		// "" for dead tokens, so an invalid cookie counts as unauthenticated.
		//
		// Unauthenticated bootstrap is a FRESH-INSTALL surface only (mirrors
		// the outer gate in api.go): once auth_bootstrapped is set, an
		// intentionally-disabled install stays fully open, but account
		// creation is the one open-mode operation with a lockout
		// consequence — the new account is admin and re-enables auth
		// server-wide, so any LAN client could lock the operator out.
		// Re-enable from the CLI: `pulsemon auth-user add`.
		caller := s.sessionFrom(r)
		setup := !s.auth.Enabled() && caller == "" && !s.auth.Bootstrapped()
		// Account creation is an admin operation: the setup-mode
		// bootstrap (unauthenticated, first user) stays open, but an
		// authenticated NON-admin session cannot mint accounts —
		// otherwise a shared/compromised helper account grows its own
		// persistence (admin-flag fix).
		if !setup && !s.auth.IsAdmin(caller) {
			respondWithError(w, http.StatusForbidden, "admin only")
			return
		}
		// External review L1 (2026-11-23): account creation is the
		// sharpest stolen-cookie primitive — a backdoor account mints
		// persistence that survives password rotation and every recovery
		// short of a reinstall — so an authenticated add requires the
		// session's own current password (same helper, same throttle
		// semantics as the password endpoint). The non-admin 403 above
		// runs FIRST, so a helper session never reaches the KDF; the
		// setup-mode bootstrap stays open (no session exists by
		// definition).
		if !setup && !s.reauthCurrentPassword(w, r, caller, req.Current) {
			return
		}
		// Throttle the setup path: an unauthenticated
		// setup POST pays a bcrypt KDF on every admitted request, so an
		// install left unclaimed was an unlimited-KDF-CPU endpoint for any
		// LAN host. Same bucket machinery as login, on a dedicated
		// "setup|ip" key so it neither locks the operator's LOGIN bucket
		// nor is diluted by it. Attempts that never reached the KDF are
		// refunded below; a successful bootstrap clears the bucket.
		var setupKey, ipKey string
		if setup {
			ipKey = throttleKey(s.auth.ClientIP(r))
			setupKey = "setup|" + ipKey
			if ok, wait := s.auth.beginAttempt(setupKey); !ok {
				respondThrottled(w, wait, "too many setup attempts — try again in a few minutes")
				return
			}
		}
		if err := s.auth.AddUserMode(r.Context(), req.Username, req.Password, setup); err != nil {
			// Refund the setup admission for exactly the no-KDF-cost
			// rejections (setupNoKDF): cheap validation, the early
			// bootstrap pre-check, and a client that left while QUEUED on
			// the bcrypt semaphore (AddUserMode returns ctx.Err() before
			// the KDF starts). "Throttling is for KDF cost" — none of these
			// paid it. An in-tx bootstrap race loss DID pay the KDF (bcrypt
			// runs to completion and ignores ctx) — deliberately NOT
			// refunded, even when the client disconnected mid-KDF: refunding
			// the paid case would hand a scripted attacker an unbounded
			// per-IP guessing channel (abort mid-KDF → budget refunded →
			// re-spray, capped only by the global semaphore).
			// History: docs/DECISIONS.md → throttle-edge-cases
			if setup && setupNoKDF(err) {
				s.auth.refundAttempt(setupKey)
			}
			// Client gone: drop the response (the write would be a no-op
			// anyway) — the refund decision above already ran, and a
			// disconnected client owes no delay.
			if r.Context().Err() != nil {
				return
			}
			// Only the duplicate-account and validation cases are client
			// errors; any other failure (db, KDF) is a 500 with the detail
			// logged. Validation sentinels (incl. the 72-byte bcrypt limit)
			// are 400, not 500. A lost setup-mode
			// bootstrap race is a 409: the winner's account already
			// exists.
			if errors.Is(err, errUserExists) || errors.Is(err, errUsernameInvalid) ||
				errors.Is(err, errPasswordWeak) || errors.Is(err, errPasswordTooLong) ||
				errors.Is(err, errPasswordCommon) {
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
		if setup {
			// Record the known-good exemption under the BARE IP bucket —
			// the same key checkUserLock looks up. (The "setup|" key is
			// the admission bucket only; a knownGood entry suffixed with
			// it never matches, so the operator's first post-bootstrap
			// login from that IP would get no per-username exemption —
			// a spray landing during bootstrap would lock them out of
			// their own new account.)
			s.auth.loginSuccess(strings.ToLower(req.Username), ipKey)
			// loginSuccess's own fails/lockout clear targets the key it
			// was passed (the login bucket); close out the dedicated
			// setup bucket itself.
			s.auth.clearIPThrottle(setupKey)
		}
		respondWithJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// reauthCurrentPassword verifies the session caller still knows their own
// password before a destructive account operation proceeds — a stolen
// session cookie must not win account-level decisions. It mirrors
// handleAuthUserPassword's credential-check semantics exactly: empty /
// >72-byte input is an uncharged 400 (no KDF ran); the check runs through
// the per-IP throttle (beginAttempt) AND the shared per-username failure
// budget (checkUserLock), so spraying current_password from many /64 IPs
// locks the account exactly like a login spray; a wrong password pays the
// same constant rejection delay as a rejected login and counts against the
// budget; a correct one clears the caller's failure streak.
//
// `caller` must be the SESSION user (s.sessionFrom(r)) — reauth is "prove
// you are who this session says you are", never the target account's
// password. Returns true when the operation may proceed; false when a
// response was already written.
// History: docs/DECISIONS.md → reauth-destructive-account-ops.
func (s *Server) reauthCurrentPassword(w http.ResponseWriter, r *http.Request, caller, current string) bool {
	if current == "" {
		respondWithError(w, http.StatusBadRequest, "current password required")
		return false
	}
	if len(current) > 72 {
		// bcrypt rejects inputs over 72 bytes: a longer current password
		// can never verify (same category and text as the login gate).
		respondWithError(w, http.StatusBadRequest, errPasswordTooLong.Error())
		return false
	}
	// Per-IP failure throttle, identical bucketing to login: this endpoint
	// verifies a real password, so it carries the same 7-failures/60s →
	// 5-minute lockout (beginAttempt counts in the same locked section).
	ip := s.auth.ClientIP(r)
	key := throttleKey(ip)
	if ok, wait := s.auth.beginAttempt(key); !ok {
		respondThrottled(w, wait, "too many failed attempts — try again in a few minutes")
		return false
	}
	// Per-username lockout (mirror of /api/auth/login): the per-IP gate
	// can't see a multi-IP holder of a valid session (a bearer token)
	// spraying current_password, so the shared failure budget applies —
	// AFTER the per-IP gate; the KDF is skipped on the 429.
	if ok, wait := s.auth.checkUserLock(caller, key); !ok {
		// Refund the per-IP admission: no KDF ran (mirror of the login
		// path) — 429-only requests must not burn the per-IP budget.
		s.auth.refundAttempt(key)
		respondThrottled(w, wait, "too many failed attempts — try again in a few minutes")
		return false
	}
	if _, ok, kdfRan := s.auth.VerifyUser(r.Context(), caller, current); !ok {
		// Client gone while queued on bcryptSem: a disconnect is not a
		// failed attempt — skip the budget and the delay; refund the
		// per-IP admission ONLY for the zero-KDF-cost case. kdfRan is
		// the explicit acquire-site signal (see VerifyUser) — the same
		// split as login, and why the old elapsed-time floor (which
		// misread fast-CPU paid KDFs and long queue waits) is gone.
		if r.Context().Err() != nil {
			if !kdfRan {
				s.auth.refundAttempt(key)
			}
			return false
		}
		// Count the failure against the account — the same shared budget
		// login uses. The caller holds a live session, so the account
		// exists by construction (no userExists gate, unlike login).
		s.auth.recordUserFail(caller)
		// Constant-time-ish delay on rejection, same as a rejected login:
		// caps an online attacker at ~5 guesses/second per IP.
		time.Sleep(loginSlowDown)
		respondWithError(w, http.StatusForbidden, "current password incorrect")
		return false
	}
	s.auth.loginSuccess(caller, key)
	s.auth.clearUserFail(caller) // success resets the account's budget
	return true
}

// handleAuthUserPassword changes the password of the CALLER's own account
// only (the {username} in the path must match the session's user — anyone
// else gets 404, not 403, so the endpoint doesn't even confirm other
// usernames exist).
//
// The CURRENT password is required: without it, any valid session — a
// stolen cookie, an unlocked browser left on the 30-day session — could
// set a new password, and SetUserPassword's dropUserSessionsExcept would
// then log out every other session, so the real owner was permanently
// locked out (account takeover). The check runs through the login
// throttle (beginAttempt, same per-IP bucketing) with the same constant
// rejection delay, and through the SAME per-username failure budget as
// /api/auth/login: a session holder spraying current_password across many
// IPs locks the account just like a login spray, and a locked account
// 429s on BOTH endpoints (shared userFails/userLock maps).
// History: docs/DECISIONS.md → password-endpoint-userlock,
// change-password-prekdf-gate.
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
		Current  string `json:"current_password"`
		Password string `json:"password"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		code, msg := requestBodyErr(err)
		respondWithError(w, code, msg)
		return
	}
	if req.Current == "" || req.Password == "" {
		// Malformed, not a credential attempt — same treatment as login's
		// empty-credentials path: 400, and NOT counted against the throttle
		// (no KDF ran, so it's not an online-cracking vector).
		respondWithError(w, http.StatusBadRequest, "current password and new password required")
		return
	}
	if len(req.Password) < minPasswordLen {
		// Structurally doomed (parity with the login
		// gate's empty-credential reject): SetUserPassword enforces the
		// same floor, so this request can never succeed — reject in the
		// empty-credential category (400, uncharged) BEFORE beginAttempt
		// and before the KDF on req.Current that the old order paid first.
		// Same sentinel text as the SetUserPassword 400 it replaces.
		respondWithError(w, http.StatusBadRequest, errPasswordWeak.Error())
		return
	}
	if isCommonPassword(req.Password) {
		// Structurally doomed (same category as the min-length
		// pre-rejection above): SetUserPassword enforces the same
		// blocklist AddUser applies at creation, so this request can
		// never succeed — reject (400, uncharged) BEFORE beginAttempt
		// and before the KDF on req.Current. Same sentinel text as the
		// SetUserPassword 400 it replaces.
		respondWithError(w, http.StatusBadRequest, errPasswordCommon.Error())
		return
	}
	if len(req.Password) > 72 {
		// bcrypt rejects inputs over 72 bytes: a longer new password can
		// never be stored. Same category, same text as the login gate.
		// (The current-password half of this check lives in
		// reauthCurrentPassword below.)
		respondWithError(w, http.StatusBadRequest, errPasswordTooLong.Error())
		return
	}

	// Credential check (reauth): per-IP throttle, per-username lockout,
	// constant rejection delay, failure budget, success clear — all in
	// one shared helper so this endpoint and the destructive-account
	// endpoints (L1) can never drift apart in throttle semantics.
	if !s.reauthCurrentPassword(w, r, user, req.Current) {
		return
	}

	keep := ""
	if c, err := r.Cookie(authSessionName); err == nil {
		keep = c.Value
	}
	if err := s.auth.SetUserPassword(r.Context(), user, req.Password, keep); err != nil {
		// Client gone while queued on bcryptSem:
		// nothing left to tell.
		if r.Context().Err() != nil {
			return
		}
		// Only the validation sentinels are client errors; any other
		// failure (db, KDF) is a 500 with the detail logged — a raw
		// driver string (e.g. "database is locked") is not a client
		// fault and must not be echoed back as a 400 (same pattern as AddUser).
		if errors.Is(err, errPasswordWeak) || errors.Is(err, errPasswordTooLong) ||
			errors.Is(err, errPasswordCommon) {
			respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
		respondInternal(w, "change password", err)
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
	// removing the last admin promotes the oldest remaining user.
	//
	// External review L1 (2026-11-23): like every destructive account
	// operation, a delete requires the session's own current password —
	// a stolen cookie must not be able to erase accounts (including the
	// real owner's, the clearest takeover tell).
	var req struct {
		Current string `json:"current_password"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		code, msg := requestBodyErr(err)
		respondWithError(w, code, msg)
		return
	}
	if !s.reauthCurrentPassword(w, r, s.sessionFrom(r), req.Current) {
		return
	}
	user := strings.ToLower(r.PathValue("username"))
	if err := s.auth.RemoveUser(r.Context(), user); err != nil {
		// A name that doesn't exist is a 404 — the same policy as the
		// password endpoint (unknown username → 404, not 403, so the
		// endpoint doesn't confirm which names exist). Checked before
		// the last-user guard so a mistyped name in a single-user
		// install is 404, not 400. This used to report SUCCESS for a
		// nonexistent user.
		if errors.Is(err, store.ErrUserNotFound) {
			respondWithError(w, http.StatusNotFound, err.Error())
			return
		}
		// The last-user guard is a client-facing business rule (400);
		// any other failure (db) is a 500 with the detail logged — a
		// raw driver string is not a client fault (same pattern as AddUser).
		if errors.Is(err, store.ErrLastUser) {
			respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
		respondInternal(w, "delete user", err)
		return
	}
	respondWithJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleAuthDisable removes every user, opening the dashboard. The
// operator's own session dies with the last user, so the UI re-shows the
// login gate — which, with zero users, immediately becomes the open
// dashboard. The route is registered with requireAdmin.
//
// Disabling auth is a silent posture downgrade (the dashboard goes open to
// the network, and if allow_unauth_update is set, self-update follows), so
// it requires the session's own current password — a stolen cookie must
// not be able to strip the credential gate from under the operator's
// feet.
// History: docs/DECISIONS.md → reauth-destructive-account-ops.
func (s *Server) handleAuthDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Current string `json:"current_password"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		code, msg := requestBodyErr(err)
		respondWithError(w, code, msg)
		return
	}
	if !s.reauthCurrentPassword(w, r, s.sessionFrom(r), req.Current) {
		return
	}
	if err := s.auth.Disable(); err != nil {
		respondInternal(w, "disable auth", err)
		return
	}
	s.setAuthCookie(w, r, "", false)
	respondWithJSON(w, http.StatusOK, authStatusPayload{Enabled: false, Authed: false, Bootstrapped: true})
}
