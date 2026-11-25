package main

// ValidSession is the test-suite twin of SessionUser (the production
// session validator): it exists so session semantics can be asserted as a
// boolean validity test, and production never calls it (m6 sweep — moved
// out of auth.go so the production file carries only live code).

// ValidSession validates a session token: a live hit slides its expiry
// forward; an unknown, expired, OR past-max-age token is rejected AND
// deleted — the returned value is the validity test, never just a map hit.
// Delegates to SessionUserAndRenewal (the production core) so the test
// twin can't drift from gate semantics.
func (a *AuthState) ValidSession(tok string) bool {
	_, ok, _, _, _ := a.SessionUserAndRenewal(tok, false)
	return ok
}
