// auth_session.go — in-memory session lifecycle: creation, sliding
// renewal, the absolute max age, drops, and the cookie helpers that issue
// sessions. Sessions are deliberately not persisted (see the auth.go header).
// History: docs/DECISIONS.md -> session-absolute-max-age,
// renewal-cookie-maxage-cap
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"time"
)

// maxSessionsPerUser caps the concurrent live sessions ONE user can hold:
// CreateSession evicts that user's OLDEST session before minting a new one
// once they're at the cap. The session map has no other bound —
// sweepExpiredSessions evicts only EXPIRED sessions (30-day TTL / max-age),
// and a repeated SUCCESSFUL login mints a fresh 30-day session while clearing
// the IP's failure throttle (loginSuccess) and skipping loginSlowDown. So a
// single valid credential — e.g. a lower-trust viewer account, or a
// compromised one — driven by a script that discards each returned cookie
// would otherwise mint unbounded sessions the GC never reclaims (unbounded
// memory growth). A per-user cap (not a global one) bounds the total
// (users × cap, and the users table is small) and targets the exact vector:
// one principal can't exhaust the map. 32 is far above any real per-user
// device count (a homelab operator runs 1–3 sessions); a var so tests shrink
// it without minting 32 sessions.
var maxSessionsPerUser = 32

// CreateSession validates the credentials and returns a new opaque session
// token tied to the user.
func (a *AuthState) CreateSession(ctx context.Context, username, password string, cookieSecure bool) (string, bool) {
	user, ok := a.VerifyUser(ctx, username, password)
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
	// BEFORE minting: VerifyUser's bcrypt check ran
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
	// likely cause (mirrors sweepThrottle for the login-throttle maps) —
	// and rate-limited to once per sweep interval for the same reason the
	// throttle GC is: past the threshold a full walk per
	// login is O(n^2) for a fleet of shared-credential devices.
	if len(a.sessions) > 64 && now.After(a.nextSweepSessions) {
		a.sweepExpiredSessions(now)
		a.nextSweepSessions = now.Add(throttleSweepInterval)
	}
	// Per-user session cap (maxSessionsPerUser): before minting, evict this
	// user's OLDEST session if they're already at the cap. This is the bound
	// against the unbounded-mint vector — sweepExpiredSessions above only
	// reclaims EXPIRED sessions, and a fresh login's session isn't expired,
	// so without this a cookie-discarding login loop grows the map forever.
	// The walk is O(n) but logins are bcrypt-rate-limited (cold) and n is
	// bounded by the cap itself. Evicting the oldest (not the newest) keeps
	// the latest login live — the "sign out the oldest device" behavior.
	{
		userCount := 0
		oldestTok := ""
		oldest := time.Time{}
		for k, s := range a.sessions {
			if s.user != user {
				continue
			}
			userCount++
			if oldestTok == "" || s.created.Before(oldest) {
				oldestTok, oldest = k, s.created
			}
		}
		if userCount >= maxSessionsPerUser && oldestTok != "" {
			delete(a.sessions, oldestTok)
		}
	}
	a.sessions[tok] = authSession{user: user, expiry: now.Add(authSessionTTL), created: now, cookieIssued: now, cookieSecure: cookieSecure}
	a.mu.Unlock()
	return tok, true
}

// sweepExpiredSessions evicts sessions whose sliding TTL has lapsed or that
// have passed their absolute authSessionMaxAge cap from login. Expired
// entries are already rejected — and individually deleted — by
// ValidSession/SessionUser when their token is presented; this sweep
// covers the rest: abandoned sessions whose cookie was discarded and
// will never be presented again, which would otherwise pin their map
// entries for the process's entire uptime. It is called opportunistically
// from CreateSession once the map grows past a threshold (no goroutine,
// no ticker — mirrors sweepThrottle). Caller must hold a.mu.
func (a *AuthState) sweepExpiredSessions(now time.Time) {
	for tok, s := range a.sessions {
		// Evict on the lapsed sliding TTL OR on the absolute authSessionMaxAge
		// cap from login. A continuously-active session's sliding expiry is
		// still in the future at max-age, so the TTL test alone would let it
		// linger here until its (slid) expiry lapses; the cap test reclaims it
		// now. (Both paths already reject the token on presentation — this is
		// memory hygiene for sessions that won't be presented again.)
		if now.After(s.expiry) || now.After(s.created.Add(authSessionMaxAge)) {
			delete(a.sessions, tok)
		}
	}
	for u, t := range a.userOKCache {
		if now.After(t.Add(userOKTTL)) {
			delete(a.userOKCache, u)
		}
	}
	for u, e := range a.adminCache {
		if now.After(e.at.Add(userOKTTL)) {
			delete(a.adminCache, u)
		}
	}
}

// sessionWithinMaxAge reports whether the session is still within the
// absolute authSessionMaxAge cap from its login time (s.created). Unlike
// s.expiry — which ValidSession and SessionUser slide forward on every live
// hit — created is fixed at login, so this is what bounds the total lifetime
// of a continuously-active session. A session past the cap is rejected and
// deleted by the caller even if its sliding expiry is still in the future.
// Caller must hold a.mu.
func (a *AuthState) sessionWithinMaxAge(s authSession) bool {
	return time.Since(s.created) <= authSessionMaxAge
}

// SessionUser returns the username a live session belongs to, validating
// the expiry (deleting the entry if lapsed) so the result is safe to use
// as an authorization check on its own. Like ValidSession it re-checks the
// owner against the users table (TTL-cached) — the in-memory map alone
// cannot see an out-of-band account deletion — and slides the expiry on a
// live hit: this is the validation path for the gate-exempt
// /api/auth/status, so without the slide a status-poll-only client would
// never extend its session. It also enforces the absolute
// authSessionMaxAge cap, so a status poll can't slide a session past its
// login-time max age.
// History: docs/DECISIONS.md → session-absolute-max-age.
func (a *AuthState) SessionUser(tok string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[tok]
	if !ok || !time.Now().Before(s.expiry) || !a.sessionWithinMaxAge(s) {
		delete(a.sessions, tok)
		return "", false
	}
	if !a.userExistsCached(s.user) {
		delete(a.sessions, tok)
		return "", false
	}
	s.expiry = time.Now().Add(authSessionTTL)
	a.sessions[tok] = s
	return s.user, true
}

// CookieRenewalDue reports whether the session's browser cookie is old
// enough to warrant a re-issue (and stamps cookieIssued=now when it is).
// The cookie carries a fixed Max-Age=authSessionTTL set at login, so a
// continuously-active user — whose in-memory expiry ValidSession slides on
// every request — would still be logged out when the browser deletes the
// cookie exactly TTL after login. Re-issuing once the cookie ages past
// half the TTL keeps an active user's cookie ≥ half a TTL from browser-
// side expiry; an idle user's cookie and session both lapse after TTL of
// inactivity (the intended sliding behavior). The gate re-issues the SAME
// token (no rotation) when this returns true — at most one Set-Cookie per
// half-TTL of activity, never per request.
//
// The third return is the renewed cookie's lifetime: the full TTL, capped
// at the session's REMAINING absolute lifetime (created +
// authSessionMaxAge − now) — uncapped, a renewal near the 30-day cap
// handed the browser a week-long cookie for a session the server rejects
// within a day. A session at/past the cap gets no renewal at all.
// History: docs/DECISIONS.md → renewal-cookie-maxage-cap.
func (a *AuthState) CookieRenewalDue(tok string) (due bool, pinSecure bool, maxAge time.Duration) {
	if tok == "" {
		return false, false, 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[tok]
	if !ok || !time.Now().Before(s.expiry) {
		return false, false, 0
	}
	maxAge = authSessionTTL
	if rem := s.created.Add(authSessionMaxAge).Sub(time.Now()); rem < maxAge {
		maxAge = rem
	}
	if maxAge <= 0 {
		return false, s.cookieSecure, 0
	}
	if time.Since(s.cookieIssued) < authSessionTTL/2 {
		return false, s.cookieSecure, maxAge
	}
	s.cookieIssued = time.Now()
	a.sessions[tok] = s
	return true, s.cookieSecure, maxAge
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

// newSessionToken returns an opaque random session id (base64url, 192 bits
// of entropy — it lives only in the cookie and the in-memory map).
func newSessionToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// setAuthCookie sets (or, with an empty value, clears) the session cookie.
// A clear uses a past Expires so the browser drops the cookie outright
// (an empty-valued cookie with a future expiry is retained by some
// browsers). Secure is applied on HTTPS requests — including plain-HTTP
// requests arriving from a trusted TLS-terminating reverse proxy (see
// cookieSecure) — so a proxied install never hands the session token to a
// plaintext hop; on a direct plain-HTTP LAN install it is omitted so the
// dashboard keeps working.
// pinSecure carries the session's mint-time Secure decision through
// renewals (see authSession.cookieSecure); non-renewal callers pass false
// and the attribute is computed from this request alone.
// History: docs/DECISIONS.md → renewal-cookie-maxage-cap.
func (s *Server) setAuthCookie(w http.ResponseWriter, r *http.Request, value string, pinSecure bool) {
	s.setAuthCookieLifetime(w, r, value, pinSecure, authSessionTTL)
}

// setAuthCookieLifetime is setAuthCookie with an explicit cookie lifetime:
// session-cookie RENEWALS pass the CookieRenewalDue-capped lifetime so a
// renewal near the absolute session cap cannot advertise a full-TTL cookie
// for a session about to die.
func (s *Server) setAuthCookieLifetime(w http.ResponseWriter, r *http.Request, value string, pinSecure bool, lifetime time.Duration) {
	expires := time.Now().Add(lifetime)
	maxAge := int(lifetime.Seconds())
	if value == "" {
		expires = time.Unix(0, 0) // past: delete the cookie
		maxAge = 0                // Max-Age=0: delete NOW. (Not -1 — a
		// negative MaxAge OMITS the attribute in Go's http.Cookie,
		// leaving only the 1970 Expires.)
	}
	// Both Expires and Max-Age are sent: RFC 6265 §5.3 gives Max-Age
	// precedence, and it is relative to the client's receipt time — an
	// absolute Expires computed from the SERVER clock is mishandled by a
	// client whose clock runs ahead (unsynced homelab Pi): a "future"
	// expiry can already be in the client's past, so the browser drops
	// the session cookie immediately after a successful login.
	http.SetCookie(w, &http.Cookie{
		Name:     authSessionName,
		Value:    value,
		Path:     "/",
		Domain:   "",
		Expires:  expires,
		MaxAge:   maxAge,
		Secure:   pinSecure || s.cookieSecure(r),
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

// requestScheme reports the EXTERNAL scheme of the request: "https" over
// direct TLS, and — for a TLS-terminating reverse proxy — when the immediate
// TCP peer is in PULSEMON_TRUSTED_PROXIES and reports X-Forwarded-Proto:
// https; "http" otherwise. The Origin CSRF gate compares the browser's
// Origin scheme against this, so an http:// page can never masquerade as the
// https dashboard's own origin (and vice versa). Same trusted-peer rule as
// cookieSecure, so a direct attacker cannot spoof it.
func (s *Server) requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if s.auth.trustedPeer(peerIP(r)) &&
		strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return "https"
	}
	return "http"
}
