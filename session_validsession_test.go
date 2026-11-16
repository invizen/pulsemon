package main

// ValidSession is the test-suite twin of SessionUser (the production
// session validator): it exists so session semantics can be asserted as a
// boolean validity test, and production never calls it (m6 sweep — moved
// out of auth.go so the production file carries only live code).

import "time"

// ValidSession validates a session token: a live hit slides its expiry
// forward; an unknown, expired, OR past-max-age token is rejected AND
// deleted — the returned value is the validity test, never just a map hit.
// The absolute authSessionMaxAge cap (measured from login time, not
// activity) is enforced here too, so a continuously-active session cannot
// be slid indefinitely — see authSessionMaxAge. The owner's account is
// re-checked against the users table (TTL-cached, see userOKTTL) so a user
// deleted out-of-band (CLI `auth-user remove`) is rejected within the window
// even though the in-memory map can't know about it.
func (a *AuthState) ValidSession(tok string) bool {
	if tok == "" {
		return false
	}
	a.mu.Lock()
	s, ok := a.sessions[tok]
	if ok && time.Now().Before(s.expiry) && a.sessionWithinMaxAge(s) && a.userExistsCached(s.user) {
		s.expiry = time.Now().Add(authSessionTTL)
		a.sessions[tok] = s
	} else {
		ok = false
		delete(a.sessions, tok)
	}
	a.mu.Unlock()
	return ok
}
