package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// maxRequestBytes bounds every incoming request body (authGate wraps
// r.Body with http.MaxBytesReader). The largest real payload — a TLS
// cert+key upload — is ~16 KB; sensor/user/settings payloads are bytes.
// Anything past 1 MiB is either a bug or a DoS attempt.
const maxRequestBytes = 1 << 20

func respondWithError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(APIError{Error: message})
}

// respondInternal is the ONLY way a handler reports a 500: it logs the full
// error for the operator (the service log is where raw SQL/driver detail
// belongs) and returns a generic body to the dashboard, so internal error
// text never leaks to the client. 4xx validation messages are user-facing
// and keep their specific text via respondWithError.
func respondInternal(w http.ResponseWriter, what string, err error) {
	log.Printf("API: %s: %v", logSafe(what), err)
	respondWithError(w, http.StatusInternalServerError, "internal error")
}

// logSafe bounds and de-controls a value before it lands in a log line.
// Several 'what' strings concatenate request-supplied ids/tags (e.g.
// "delete tag "+tag); SQL is parameterized everywhere, but the LOG is a
// sink of its own: CR/LF forges a fake entry, other control characters
// corrupt terminals and shippers, and an unbounded value lets any session
// write arbitrarily long log lines. Sanitizing
// HERE covers every current and future call site in one place.
func logSafe(s string) string {
	const max = 120
	mapped := strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f {
			return ' '
		}
		return c
	}, s)
	if !utf8.ValidString(mapped) {
		mapped = strings.ToValidUTF8(mapped, "?")
	}
	if utf8.RuneCountInString(mapped) > max {
		// Truncate by RUNES: a byte slice could split a multi-byte
		// character and re-introduce the very invalid UTF-8 we removed.
		r := []rune(mapped)
		return string(r[:max]) + "…"
	}
	return mapped
}

// requestBodyErr maps the MaxBytesReader limit (authGate bounds every body
// to maxRequestBytes) to a clean 413; any other decode error is a plain 400.
// Every JSON handler routes its json.Decoder error through this, so an
// oversized body never surfaces as "invalid request body: http: request
// body too large".
func requestBodyErr(err error) (int, string) {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		return http.StatusRequestEntityTooLarge, "request body too large (limit 1 MiB)"
	}
	return http.StatusBadRequest, "invalid request body: " + err.Error()
}

func respondWithJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	// The status line is already written, so an Encode failure can't change
	// it — log it so a payload that can't be marshalled to JSON surfaces as
	// a visible error + truncated body instead of a silent empty response.
	// ErrBodyNotAllowed is the expected, per-request outcome for HEAD
	// (net/http suppresses the body) — not an error worth a log line.
	if err := json.NewEncoder(w).Encode(payload); err != nil && !errors.Is(err, http.ErrBodyNotAllowed) {
		log.Printf("respondWithJSON: encode: %v", err)
	}
}

// respondThrottled answers a 429 with a Retry-After header derived from
// wait (ceiling to whole seconds, minimum 1) and a caller-supplied message.
// The throttle/lockout sites (login per-IP, login per-username, setup,
// password-change per-IP, password-change per-username) share this instead
// of copy-pasting the secs computation + header + body.
func respondThrottled(w http.ResponseWriter, wait time.Duration, msg string) {
	secs := int((wait + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	respondWithError(w, http.StatusTooManyRequests, msg)
}

// parseAllowedHosts splits PULSEMON_ALLOWED_HOSTS (comma-separated host or
// host:port entries) into a lower-cased list, dropping blanks
func parseAllowedHosts(v string) []string {
	var out []string
	for _, h := range strings.Split(v, ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// splitHostPortLenient splits a host[:port] value into its bare host (no
// port, no brackets) and port. Unlike net.SplitHostPort it also accepts a
// bracketed IPv6 with NO port ("[::1]"), which SplitHostPort rejects — the
// allowlist commonly stores IPv6 that way. It returns the bare host, the
// port ("" if none), and whether a port was present.
func splitHostPortLenient(v string) (host, port string, hasPort bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	if strings.HasPrefix(v, "[") {
		if end := strings.IndexByte(v, ']'); end >= 0 {
			host = v[1:end]
			rest := v[end+1:]
			if strings.HasPrefix(rest, ":") {
				return host, rest[1:], true
			}
			return host, "", false
		}
	}
	if h, p, err := net.SplitHostPort(v); err == nil {
		return h, p, true
	}
	return v, "", false
}

// hostAllowed reports whether r.Host matches the allowlist. An entry with a port must equal r.Host exactly; an entry without a
// port matches r.Host's host portion (any port). Matching is case-insensitive
// and bracket-agnostic, so a bracketed IPv6 entry ([::1]) matches a request
// to [::1]:9299 the same way a bare entry (::1) does. r.Host is
// client-controlled, so this is the only Host check that a DNS-rebinding
// page can't satisfy — the Origin==Host CSRF gate compares two values the
// attacker's page both controls.
func (s *Server) hostAllowed(host string) bool {
	reqHost, _, _ := splitHostPortLenient(host)
	for _, a := range s.allowedHosts {
		entHost, _, entHasPort := splitHostPortLenient(a)
		if entHasPort {
			if strings.EqualFold(a, host) {
				return true
			}
			continue
		}
		if entHost == reqHost {
			return true
		}
	}
	return false
}

// unauthMutateAllowed reports whether a state-changing request arriving
// WITHOUT a session from r.Host is permitted. With
// PULSEMON_ALLOWED_HOSTS unset the LAN-trust default stands (allowed); with
// it set, "auth off = fully open" becomes "open to allowlisted hosts" — a
// DNS-rebinding page fires simple credentials-including requests and, with
// no session cookie protecting the endpoints, every mutating route is
// reachable by it. /api/auth/login is deliberately NOT gated (the auth entry
// point must keep working; it has its own per-IP rate limiting).
func (s *Server) unauthMutateAllowed(r *http.Request) bool {
	if len(s.allowedHosts) == 0 {
		return true
	}
	return s.hostAllowed(r.Host)
}

// authGate wraps the mux with a per-request auth check. The enabled state
// (at least one user in the users table) is memoized in AuthState for
// enabledTTL, so the 5s dashboard poll doesn't pay a SELECT COUNT(*) on the
// hot path. In-app user mutations refresh it immediately; an out-of-band
// `pulsemon auth-user add/remove` is honored within the TTL (≤2s), no
// restart required.
//
// Setup mode (no users exist yet): only the bootstrap surface is reachable —
// static UI assets, /api/healthz, /api/auth/status, and POST /api/auth/users
// (the first account). Everything else is 403 until an account exists, so an
// unauthenticated LAN host can't use the fresh-install window for SSRF or
// internal port scanning.
//
// Every request body is additionally bounded to maxRequestBytes via
// http.MaxBytesReader: a malformed or malicious client can no longer stream
// an arbitrarily large body into the JSON decoders (sensors, users, TLS
// upload, settings). The largest real payload — a TLS cert+key upload — fits
// in ~16 KB, so 1 MiB is generous. Oversized bodies surface as a clean 413
// instead of a generic decode error.
func (s *Server) authGate() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// Strict CSP: the dashboard is fully self-contained (go:embed web/*, no
		// CDN), so 'self' is the whole story. script-src and style-src are
		// 'self' with NO 'unsafe-inline' and no hashes — the theme, app, and
		// custom CSS all live in files (web/theme.js, web/app.js, web/styles.css,
		// web/vendor/tailwind.css), so an injected inline <script>/<style> is
		// refused. That is defence in depth on top of the esc() HTML-escaping:
		// if one interpolation were ever missed, a reflected payload has no
		// script/style source to run from. object-src/base-uri/form-action are
		// locked down; frame-ancestors 'none' keeps the clickjacking guard.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		// Sensitive JSON payloads (/api/settings, /api/auth/status, sensor
		// data) must not be cached by browsers or intermediate proxies:
		// no-store on every /api/ response. Static assets set their own
		// no-cache in serveStatic and keep that contract.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		// Every request body is bounded to maxRequestBytes via
		// http.MaxBytesReader BEFORE w is wrapped: the MaxBytesReader's
		// requestTooLarge hook closes the connection through the writer
		// it was given, so it gets the raw writer (the gzip wrapper is
		// transparent via Unwrap, but this is the authoritative path).
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
		}
		// gzip /api/ responses when the client accepts them (finding #8):
		// every open dashboard tab re-pulls the whole uncompressed fleet
		// every 5s, and the payload grows with sensor count. Compressing the
		// JSON cuts that per-tab, per-poll traffic (it compresses ~5-10x).
		// Only /api/ is wrapped — static assets set their own caching and are
		// served raw. This is the one cheap piece of finding #8's scale
		// ceiling; the two heavier fixes (per-sensor history locks, batched
		// probe writes) are documented in docs/DECISIONS.md → scale-ceiling
		// and deferred — they only pay off at 1000s of sensors.
		//
		// HEAD is EXCLUDED: net/http answers HEAD with a bodyless writer
		// (Write returns ErrBodyNotAllowed), so wrapping it just declares
		// Content-Encoding: gzip on a body the client never gets and logs
		// one ErrBodyNotAllowed per HEAD request in respondWithJSON.
		//
		// POST /api/update is EXCLUDED: handleUpdate ends in a synchronous
		// performRestart that SIGTERMs this process before the deferred
		// gzip Close can write the trailer — a truncated gzip stream breaks
		// the client's decode (ERR_CONTENT_DECODING_FAILED) on the 202. The
		// update responses are a few hundred bytes; compression buys nothing.
		if strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/update" &&
			r.Method != http.MethodHead && acceptsGzip(r) {
			// The body now depends on Accept-Encoding: caches must not
			// serve the gzip variant to an identity client (or vice versa).
			w.Header().Add("Vary", "Accept-Encoding")
			gzw := &gzipResponseWriter{ResponseWriter: w}
			defer gzw.Close()
			w = gzw
		}
		// Cross-port CSRF gate (RFC 6265bis): the session cookie is
		// SameSite=Strict, but "same-site" is scheme+host — the PORT is
		// not part of the site. In a homelab, every other web app on the
		// same IP (192.168.1.10:8080) is same-SITE to this one
		// (192.168.1.10:9299): a page there can fire a simple
		// credentials-including POST (empty body, no custom headers → no
		// CORS preflight) at /api/auth/disable — wiping all dashboard
		// accounts — and the browser WILL attach the session cookie.
		// Browsers send Origin on every cross-origin request; a request
		// with no Origin (curl, server-to-server) cannot be a browser
		// CSRF and passes. A reverse proxy must preserve the original
		// Host header (Caddy does by default) for the comparison to
		// match.
		//
		// Sec-Fetch-Site is the second arm: modern browsers send it on
		// every request (fetch, XHR, form POST) and compute it from the
		// URL's site, so it also covers the narrow window where a
		// browser omits Origin on a POST (legacy quirks, some redirect
		// chains) — and the DNS-rebinding residual noted below. A
		// MISSING value passes (curl, server-to-server, the test
		// suite): a non-browser cannot be a browser CSRF, and
		// cookie-authenticated non-browser API clients must keep
		// working. "same-site" is refused: a page on another PORT of
		// the same IP is same-site, and that is exactly the cross-port
		// vector this gate exists for.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" &&
				sfs != "same-origin" && sfs != "none" {
				respondWithError(w, http.StatusForbidden, "cross-origin request blocked")
				return
			}
			if orig := r.Header.Get("Origin"); orig != "" {
				u, err := url.Parse(orig)
				// Fail closed on an empty host on EITHER side: Origin: null
				// parses with u.Host == "", and an HTTP/1.0 request with no
				// Host header (legal pre-HTTP/1.1) leaves r.Host == "".
				// Without this, EqualFold("", "") reads the degenerate
				// both-empty case as a MATCH. No browser sends Host-less
				// HTTP/1.0, and a non-browser client needs no Origin to
				// pass (the arm is skipped when Origin is absent), so
				// rejecting it breaks nothing — the gate must never treat
				// "no origin host" as equal to "no request host".
				// Reject a scheme mismatch too: the browser's Origin scheme
				// must equal the EXTERNAL scheme of the request (https over
				// direct TLS or a trusted proxy reporting https). Without
				// this, an http:// page on the same host passes the host
				// check and CSRFs the https dashboard (scheme is not part of
				// the host comparison). requestScheme uses the same
				// trusted-peer rule as cookieSecure, so a direct attacker
				// can't spoof it.
				if err != nil || u.Host == "" || r.Host == "" ||
					!strings.EqualFold(u.Host, r.Host) ||
					!strings.EqualFold(u.Scheme, s.requestScheme(r)) {
					respondWithError(w, http.StatusForbidden, "cross-origin request blocked")
					return
				}
			}
		}
		// healthz is the container healthcheck and the external monitoring
		// probe — it must be reachable in every state (setup, unauthenticated,
		// authenticated).
		if r.URL.Path == "/api/healthz" {
			s.mux.ServeHTTP(w, r)
			return
		}
		if !s.auth.Enabled() {
			if s.auth.Bootstrapped() {
				// TORN-READ GUARD: (Enabled=false, Bootstrapped=true) is
				// ambiguous. It is either the operator's documented "auth
				// off = fully open" state (all accounts deleted) — OR the
				// enabledTTL window after an out-of-band CLI first-user
				// add: the user row and auth_bootstrapped committed
				// together, Enabled() still caches a stale 'false', and
				// Bootstrapped() just live-read '1'. In the second case
				// this branch would open the dashboard to any LAN host at
				// the exact moment authentication is being enabled — and
				// the handlers' requireAuth/requireAdmin would stand down
				// on the same stale cache, so the gate is the only line
				// of defense left. Settle the ambiguity with a fresh count
				// before opening: a real user exists → fall through to the
				// authenticated path below (401 without a session). The
				// extra COUNT lands only in this rare branch (the
				// deliberately-open auth-off state), never on the hot
				// authenticated path.
				if !s.auth.EnabledNow() {
					// Auth was disabled by the operator (all accounts
					// deleted): the documented "auth off = fully open"
					// behavior applies.
					// With PULSEMON_ALLOWED_HOSTS set, EVERY /api/ request from a
					// non-allowlisted Host is refused — reads included. A DNS-
					// rebinding page's whole attack is a same-origin GET: it reads
					// /api/sensors (targets with user:pass@ creds) and
					// /api/settings (SMTP user, Telegram chat ID), so gating only
					// the mutations left the data wide open. healthz is served
					// above (the container healthcheck must reach it in every
					// state), and the static UI carries no data. With the
					// allowlist unset the LAN-trust default stands (fully open);
					// the startup warning names that exposure.
					if strings.HasPrefix(r.URL.Path, "/api/") &&
						len(s.allowedHosts) > 0 && !s.hostAllowed(r.Host) {
						respondWithError(w, http.StatusMisdirectedRequest, "host not in PULSEMON_ALLOWED_HOSTS")
						return
					}
					s.mux.ServeHTTP(w, r)
					return
				}
				// Enabled() was stale — a CLI first-user add committed
				// within the TTL. Fall through: this request needs a
				// session like any other authenticated-state request.
			} else {
				// Fresh install: no account has ever existed. Only the bootstrap
				// surface is reachable — static UI assets, /api/auth/status, and
				// POST /api/auth/users (the first account). Everything else
				// (sensor create/pulse, settings, TLS upload, user list) is 403
				// until an account exists, so an unauthenticated LAN host can't
				// use the fresh-install window for SSRF or internal port scanning.
				//
				// ACCEPTED LIMITATION: the first-user bootstrap itself is open to
				// any LAN host — whoever POSTs /api/auth/users first wins it, and
				// a rogue host that wins leaves the operator to create an account
				// via `pulsemon auth-user add` (CLI). Closing that fully would
				// need a setup token or loopback-only bootstrap, both worse UX
				// than the risk justifies on a trusted homelab LAN. DNS
				// rebinding also passes the Origin==Host gate above (both are
				// attacker-controlled), so a remote page could win the bootstrap;
				// operators who set PULSEMON_ALLOWED_HOSTS close that hole — the
				// bootstrap POST is then refused unless r.Host is allowlisted
				// Unset = the LAN-trust default above.
				if r.Method == http.MethodPost && r.URL.Path == "/api/auth/users" &&
					len(s.allowedHosts) > 0 && !s.hostAllowed(r.Host) {
					respondWithError(w, http.StatusMisdirectedRequest, "host not in PULSEMON_ALLOWED_HOSTS")
					return
				}
				if r.URL.Path == "/api/auth/status" ||
					(r.Method == http.MethodPost && r.URL.Path == "/api/auth/users") ||
					!strings.HasPrefix(r.URL.Path, "/api/") {
					s.mux.ServeHTTP(w, r)
					return
				}
				respondWithError(w, http.StatusForbidden, "dashboard setup required: create the first account in Settings")
				return
			}
		}
		// Authenticated traffic is intentionally NOT host-gated:
		// PULSEMON_ALLOWED_HOSTS is documented setup-mode hardening
		// (README: "Has no effect once an account exists") — it closes
		// the unauthenticated rebinding-bootstrap window, not a global
		// access boundary. The session cookie is the credential, and
		// the Host header is client-controlled: a cookie holder can
		// set any Host, so a gate here would lock out direct-IP login
		// and use while protecting no one. Rebinding-with-cookie is
		// already defeated by cookie domain scoping (the browser won't
		// attach a 192.168.1.10 cookie to a request addressed to
		// evil.com), and browser cross-origin vectors on authenticated
		// endpoints are the Origin/Sec-Fetch-Site gate above.
		// (mechanism verified, documented
		// as by design.)
		for _, tok := range sessionCookieValues(r) {
			// ONE lock pass for the gate's session work: liveness, the
			// TTL-cached owner re-check (I/O runs outside a.mu), the
			// sliding expiry, and the sliding-cookie renewal decision.
			// A shadowing first cookie (sessionCookieValues) fails the
			// lookup and the loop moves on to the valid one.
			// History: docs/DECISIONS.md → auth-lock-io-split,
			// session-cookie-shadowing.
			if user, ok, due, pinSecure, renewAge := s.auth.SessionUserAndRenewal(tok, true); ok {
				r = r.WithContext(context.WithValue(r.Context(), authUserCtxKeyVal, user))
				// Sliding cookie: the login cookie carries a fixed
				// Max-Age=authSessionTTL (7d), so without a re-issue
				// the browser would delete it exactly one TTL after
				// login even though ValidSession slides the in-memory
				// expiry on every use — the sliding-session design was
				// defeated by the cookie's fixed expiry. Re-issue the
				// SAME token once the cookie ages past half the TTL:
				// at most one Set-Cookie per ~3.5 days of activity,
				// never per 5s poll. The re-issue lifetime is the
				// CookieRenewalDue-capped one: a renewal near the
				// 30-day absolute cap expires with the session, not a
				// week past it.
				if due {
					s.setAuthCookieLifetime(w, r, tok, pinSecure, renewAge)
				}
				s.mux.ServeHTTP(w, r)
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			// The login/status endpoints must be reachable WITHOUT a
			// session — the UI's gate calls them to decide whether to
			// show the login form. Login is exempt from the Host gate
			// it is the auth entry point and has
			// its own per-IP rate limiting; logout (a POST) is gated like
			// any other sessionless mutating endpoint.
			if r.URL.Path == "/api/auth/login" || r.URL.Path == "/api/auth/status" {
				s.mux.ServeHTTP(w, r)
				return
			}
			// Logout is reachable without a session (the UI clears its
			// cookie on the way out and curl-based ops rely on it), so it
			// gets the same treatment as the other sessionless mutating
			// endpoints: allowed by default on the trusted LAN, 421 when
			// PULSEMON_ALLOWED_HOSTS is set and the Host isn't listed
			// An allowed logout must be FORWARDED
			// to the handler — falling through to the 401 below would
			// break every sessionless logout (csrf_test.go pins this).
			if r.URL.Path == "/api/auth/logout" {
				if s.unauthMutateAllowed(r) {
					s.mux.ServeHTTP(w, r)
					return
				}
				respondWithError(w, http.StatusMisdirectedRequest, "host not in PULSEMON_ALLOWED_HOSTS")
				return
			}
			respondWithError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		// Document requests still get the page; the UI's own login overlay
		// handles the unauthenticated experience.
		s.mux.ServeHTTP(w, r)
	})
}
