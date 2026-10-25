package main

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

//go:embed web/*
var content embed.FS

// maxRequestBytes bounds every incoming request body (authGate wraps
// r.Body with http.MaxBytesReader). The largest real payload — a TLS
// cert+key upload — is ~16 KB; sensor/user/settings payloads are bytes.
// Anything past 1 MiB is either a bug or a DoS attempt.
const maxRequestBytes = 1 << 20

// minIntervalS is the floor on a sensor's probe interval. At 1s a sensor
// holds ~86,400 in-memory entries per day and copies ~1.4 MB per dashboard
// poll, so the API refuses to store intervals below 5s. Existing rows are
// NOT migrated (a legacy 1s sensor keeps running until the operator edits
// it); the floor is enforced only on new writes via the API.
const minIntervalS = 5

// Sensor mirrors the sensors table. JSON is snake_case per SPEC §4.
type Sensor struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Target    string   `json:"target"`
	Type      string   `json:"type"` // "icmp" (default) | "http"
	Tags      []string `json:"tags"`
	IntervalS int      `json:"interval_s"`
	TimeoutMS int      `json:"timeout_ms"`
	LossWarn  int      `json:"loss_warn"`
	DownAfter int      `json:"down_after"`
	// SpikeMult is the relative-spike multiplier for the dashboard
	// sparkline: a bar at/above SpikeMult × the window's average RTT
	// renders amber (absolute red >200 ms is unchanged). Display-only —
	// the probe worker never reads it, so PATCHing it must not respawn
	// the probe loop.
	SpikeMult int    `json:"spike_mult"`
	State     string `json:"state"`  // active | paused
	Status    string `json:"status"` // up | warning | error
	CreatedAt string `json:"created_at"`
}

// SensorView is what GET /api/sensors returns: sensor + window stats.
type SensorView struct {
	Sensor
	Stats *SensorStats `json:"stats"` // nil when paused or no probes yet
	// HTTP-sensor-only, derived from the probe worker (not the DB): the last
	// status code + cert expiry. The card renders "HTTP 503" and a cert
	// expiry note from these. Omitted for ICMP sensors (omitempty + nil).
	HTTPStatus *int       `json:"http_status,omitempty"`
	CertExpiry *time.Time `json:"cert_expiry,omitempty"`
}

// SensorStats is a 60-probe window summary (SPEC §4).
type SensorStats struct {
	RTTLast     *float64   `json:"rtt_last"`
	RTTMin      *float64   `json:"rtt_min"`
	RTTAvg      *float64   `json:"rtt_avg"`
	RTTMax      *float64   `json:"rtt_max"`
	LossPct     float64    `json:"loss_pct"`
	LostCount   int        `json:"lost_count"`
	Total       int        `json:"total"`
	Recent      []*float64 `json:"recent"`        // last 30 probes, newest first, null = lost (kept for compat)
	Hour        []*float64 `json:"hour"`          // 60 one-minute buckets, oldest->newest: min RTT ms, null = lost, -2 = no data
	HourLossPct float64    `json:"hour_loss_pct"` // % of past-hour probes that were lost
	HourRTTAvg  *float64   `json:"hour_rtt_avg"`  // avg RTT ms over the past hour
	Uptime24h   float64    `json:"uptime_24h"`    // % of last-24h probes that replied
	// StatusWindow fields mirror the window deriveStatus actually uses (the
	// last statusWindow probes). The inspector shows them so the badge is
	// directly explained: a green UP can coexist with a high 60p loss% while
	// recovering — the status-window number is the one the badge came from.
	StatusLossPct    float64 `json:"status_loss_pct"`    // % lost over the last statusWindow probes
	StatusLostCount  int     `json:"status_lost_count"`  // losses in that window
	StatusWindowSize int     `json:"status_window_size"` // the window length (statusWindow)
}

type ProbeRow struct {
	TS   string   `json:"ts"`
	RTT  *float64 `json:"rtt_ms"` // null = lost
	Lost bool     `json:"lost"`
}

type APIError struct {
	Error string `json:"error"`
}

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
// write arbitrarily long log lines (review 2026-10-24 nit). Sanitizing
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

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}

type Server struct {
	db          *DB
	probeWorker *ProbeWorker
	mux         *http.ServeMux
	auth        *AuthState
	// allowedHosts is the parsed PULSEMON_ALLOWED_HOSTS list (lower-cased
	// host or host:port entries). Empty = no Host check (LAN-trust default).
	// Enforced only on the setup-mode bootstrap POST — see authGate.
	allowedHosts []string
	// tlsCert memoizes the parsed cert for tlsPayload (2026-10-24
	// review n3); see tlsCertCached in tls_settings.go.
	tlsCert tlsCertMemo
}

func NewServer(db *DB, pw *ProbeWorker) *Server {
	s := &Server{
		db:           db,
		probeWorker:  pw,
		mux:          http.NewServeMux(),
		auth:         NewAuthState(db),
		allowedHosts: parseAllowedHosts(os.Getenv("PULSEMON_ALLOWED_HOSTS")),
	}
	s.routes()
	return s
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

// hostAllowed reports whether r.Host matches the allowlist. An entry with a port must equal r.Host exactly; an entry without a
// port matches r.Host or r.Host's host portion (port stripped). Matching is
// case-insensitive. r.Host is client-controlled, so this is the only Host
// check that a DNS-rebinding page can't satisfy — the Origin==Host CSRF gate
// compares two values the attacker's page both controls.
func (s *Server) hostAllowed(host string) bool {
	host = strings.ToLower(host)
	bare := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		bare = h
	}
	for _, a := range s.allowedHosts {
		if _, _, err := net.SplitHostPort(a); err == nil {
			if a == host {
				return true
			}
			continue
		}
		if a == host || a == bare || "["+a+"]" == bare {
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

func (s *Server) Mux() *http.ServeMux {
	return s.mux
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
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		// Sensitive JSON payloads (/api/settings, /api/auth/status, sensor
		// data) must not be cached by browsers or intermediate proxies:
		// no-store on every /api/ response. Static assets set their own
		// no-cache in serveStatic and keep that contract.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
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
		// match. (valid finding.)
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
				if err != nil || !strings.EqualFold(u.Host, r.Host) {
					respondWithError(w, http.StatusForbidden, "cross-origin request blocked")
					return
				}
			}
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
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
				// Auth was disabled by the operator (all accounts deleted):
				// the documented "auth off = fully open" behavior applies.
				// With PULSEMON_ALLOWED_HOSTS set, mutating requests from a
				// non-allowlisted Host are 403 (see
				// unauthMutateAllowed); reads stay open.
				switch r.Method {
				case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
					if !s.unauthMutateAllowed(r) {
						respondWithError(w, http.StatusMisdirectedRequest, "host not in PULSEMON_ALLOWED_HOSTS")
						return
					}
				}
				s.mux.ServeHTTP(w, r)
				return
			}
			// Fresh install: no account has ever existed. Only the bootstrap
			// surface is reachable — static UI assets, /api/auth/status, and
			// POST /api/auth/users (the first account). Everything else
			// (sensor create/pulse, settings, TLS upload, user list) is 403
			// until an account exists, so an unauthenticated LAN host can't
			// use the fresh-install window for SSRF or internal port scanning
			// (valid finding).
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
		if c, err := r.Cookie(authSessionName); err == nil && s.auth.ValidSession(c.Value) {
			// Sliding cookie: the login cookie carries a fixed
			// Max-Age=30d, so without a re-issue the browser would
			// delete it exactly 30 days after login even though
			// ValidSession slides the in-memory expiry on every use —
			// the sliding-session design was defeated by the cookie's
			// fixed expiry. Re-issue the
			// SAME token once the cookie ages past half the TTL: at
			// most one Set-Cookie per ~15 days of activity, never per
			// 5s poll.
			if due, pinSecure := s.auth.CookieRenewalDue(c.Value); due {
				s.setAuthCookie(w, r, c.Value, pinSecure)
			}
			s.mux.ServeHTTP(w, r)
			return
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

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/healthz", s.handleHealthz)
	s.mux.HandleFunc("GET /api/update-check", s.handleUpdateCheck)
	s.mux.HandleFunc("POST /api/update", s.requireAdmin(s.handleUpdate))
	s.mux.HandleFunc("/api/sensors", s.handleSensors)
	s.mux.HandleFunc("/api/sensors/{id}", s.handleSensorByID)
	s.mux.HandleFunc("POST /api/sensors/{id}/ping", s.handleSensorPing)
	s.mux.HandleFunc("POST /api/sensors/{id}/clone", s.handleSensorClone)
	s.mux.HandleFunc("GET /api/sensors/{id}/history", s.handleSensorHistory)
	s.mux.HandleFunc("GET /api/sensors/{id}/graph", s.handleSensorGraph)
	s.mux.HandleFunc("DELETE /api/sensors/{id}/history", s.handleSensorClearHistory)
	s.mux.HandleFunc("DELETE /api/history", s.requireAdmin(s.handleClearAllHistory))
	s.mux.HandleFunc("/api/tags", s.handleTags)
	s.mux.HandleFunc("/api/events", s.handleEvents)
	s.mux.HandleFunc("GET /api/settings", s.handleSettingsGet)
	s.mux.HandleFunc("PUT /api/settings", s.requireAdmin(s.handleSettingsPut))
	s.mux.HandleFunc("POST /api/settings/test", s.requireAdmin(s.handleSettingsTest))
	s.mux.HandleFunc("POST /api/settings/tls", s.requireAdmin(s.handleTLSSettingsPut))
	s.mux.HandleFunc("DELETE /api/settings/tls", s.requireAdmin(s.handleTLSSettingsDelete))
	s.mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)
	s.mux.HandleFunc("POST /api/auth/login", s.handleAuthLogin)
	s.mux.HandleFunc("POST /api/auth/logout", s.handleAuthLogout)
	s.mux.HandleFunc("GET /api/auth/users", s.requireAuth(s.handleAuthUsers))
	s.mux.HandleFunc("POST /api/auth/users", s.requireAuth(s.handleAuthUsers))
	s.mux.HandleFunc("POST /api/auth/users/{username}/password", s.requireAuth(s.handleAuthUserPassword))
	s.mux.HandleFunc("DELETE /api/auth/users/{username}", s.requireAuth(s.handleAuthUserDelete))
	s.mux.HandleFunc("POST /api/auth/disable", s.requireAuth(s.handleAuthDisable))
	s.mux.HandleFunc("/", s.handleStatic)
}

// handleHealthz is a real check: DB must be reachable (SPEC §8, fix #5).
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	var n int
	if err := s.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM sensors").Scan(&n); err != nil {
		// 503, not 500: the API process is healthy, the DB is down. Keep
		// the "db unreachable" wording (operators and health checks read
		// it) and log the driver detail instead of leaking it.
		log.Printf("API: healthz db check: %v", err)
		respondWithError(w, http.StatusServiceUnavailable, "db unreachable")
		return
	}
	hz := map[string]interface{}{
		"status":  "ok",
		"sensors": n,
		"probing": s.probeWorker.ActiveCount(),
		"time":    time.Now().UTC().Format(time.RFC3339),
	}
	hz["version"] = Version
	// ICMP availability: the probe worker warms the shared engine at startup,
	// so by the time healthz is reachable the outcome is known. Reporting it
	// here closes the silent-failure mode: when BOTH transports fail
	// (e.g. RHEL 8's default ping_group_range excludes the uid and there is
	// no CAP_NET_RAW), the server used to start and report "ok" with no
	// pings. Now it reports "degraded" + an explicit remediation hint.
	switch m := EngineMode(); {
	case m != "":
		hz["icmp_mode"] = m
	case EngineDead():
		hz["status"] = "degraded"
		hz["icmp_mode"] = "unavailable"
		hz["icmp_hint"] = icmpHint()
	}
	if e := LastProbeError(); e != "" {
		hz["probe_error"] = e
	}
	respondWithJSON(w, http.StatusOK, hz)
}

func (s *Server) fetchSensors(ctx context.Context) []Sensor {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at FROM sensors ORDER BY name`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := []Sensor{} // non-nil even when empty: nil is the error sentinel
	// the handler distinguishes from a genuinely empty fleet.
	for rows.Next() {
		var sn Sensor
		// A per-row scan error means a corrupt/mismatched row. The schema is
		// app-controlled so this shouldn't happen — but log it so a real
		// corruption event is visible in the service log instead of "one
		// sensor silently vanished from the fleet view".
		if err := rows.Scan(&sn.ID, &sn.Name, &sn.Target, &sn.Type, &sn.IntervalS, &sn.TimeoutMS, &sn.LossWarn, &sn.DownAfter, &sn.SpikeMult, &sn.State, &sn.Status, &sn.CreatedAt); err != nil {
			log.Printf("API: skipping corrupt sensor row: %v", err)
			continue
		}
		if sn.Type == "" {
			sn.Type = "icmp"
		}
		out = append(out, sn)
	}
	// A mid-stream iteration error (DB file I/O failure) ends rows.Next()
	// without a query error: surface it via the nil sentinel the callers
	// already treat as "query failed" instead of a truncated fleet view.
	if err := rows.Err(); err != nil {
		log.Printf("API: sensor query failed mid-stream: %v", err)
		return nil
	}

	// ONE batched tag query after the loop — never a per-sensor query inside
	// rows.Next(): the outer iteration holds a pooled connection, and nested
	// per-row queries starve the pool (deadlock risk under concurrency).
	ids := make([]string, len(out))
	for i := range out {
		ids[i] = out[i].ID
	}
	tagMap := s.db.SensorTagsFor(ids)
	for i := range out {
		out[i].Tags = tagMap[out[i].ID]
	}
	return out
}

// fillHTTPView attaches the probe-worker's last HTTP status code and cert
// expiry to a view (HTTP sensors only). It is a no-op for ICMP sensors:
// the card renders the status code + cert-expiry note from these, and both
// stay omitted from the JSON for ICMP (pointer omitempty + nil).
func (s *Server) fillHTTPView(v *SensorView) {
	if v.Type != "http" {
		return
	}
	v.HTTPStatus, v.CertExpiry = s.probeWorker.LastHTTPStatus(v.ID)
}

func (s *Server) handleSensors(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		sensors := s.fetchSensors(r.Context())
		if sensors == nil {
			respondWithError(w, http.StatusInternalServerError, "failed to read sensors")
			return
		}
		views := make([]SensorView, 0, len(sensors))
		for _, sn := range sensors {
			v := SensorView{Sensor: sn}
			if sn.State == "active" {
				// In-memory stats (v0.1.18): one map lookup, no per-sensor
				// SQLite queries. This was 4 queries per sensor per poll —
				// the N+1 load this release eliminates.
				v.Stats = s.probeWorker.GetStats(sn.ID)
			}
			s.fillHTTPView(&v)
			views = append(views, v)
		}
		respondWithJSON(w, http.StatusOK, views)

	case http.MethodPost:
		var req struct {
			Name      string   `json:"name"`
			Target    string   `json:"target"`
			Type      string   `json:"type"`
			Tags      []string `json:"tags"`
			IntervalS int      `json:"interval_s"`
			TimeoutMS int      `json:"timeout_ms"`
			LossWarn  int      `json:"loss_warn"`
			DownAfter int      `json:"down_after"`
			SpikeMult int      `json:"spike_mult"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			code, msg := requestBodyErr(err)
			respondWithError(w, code, msg)
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		req.Target = strings.TrimSpace(req.Target)
		req.Type = normalizeProbeType(req.Type)
		if req.Name == "" || req.Target == "" {
			respondWithError(w, http.StatusBadRequest, "name and target are required")
			return
		}
		if !validSensorName(req.Name) {
			respondWithError(w, http.StatusBadRequest, "name must be 1-60 characters and may not contain quotes, angle brackets, backslash, or control characters")
			return
		}
		if req.Type == "http" {
			if !validURL(req.Target) {
				respondWithError(w, http.StatusBadRequest, "target must be an http:// or https:// URL (e.g. https://example.com/health)")
				return
			}
		} else if !validTarget(req.Target) {
			respondWithError(w, http.StatusBadRequest, "target must be an IPv4 address or hostname")
			return
		}
		req.Tags = cleanTags(req.Tags)
		if req.IntervalS <= 0 {
			req.IntervalS = 60
		}
		if req.IntervalS < minIntervalS || req.IntervalS > 3600 {
			respondWithError(w, http.StatusBadRequest, "interval_s must be 5-3600")
			return
		}
		if req.TimeoutMS <= 0 {
			req.TimeoutMS = 1000
		}
		if req.TimeoutMS < 100 || req.TimeoutMS > 30000 {
			respondWithError(w, http.StatusBadRequest, "timeout_ms must be 100-30000")
			return
		}
		// A probe timeout longer than the interval means two probes can
		// never complete back-to-back — the loss window becomes
		// meaningless. Reject it once both values are final.
		if req.TimeoutMS > req.IntervalS*1000 {
			respondWithError(w, http.StatusBadRequest, "timeout_ms must not exceed interval_s*1000")
			return
		}
		if req.LossWarn <= 0 {
			req.LossWarn = 25
		}
		if req.LossWarn < 1 || req.LossWarn > 100 {
			respondWithError(w, http.StatusBadRequest, "loss_warn must be 1-100")
			return
		}
		if req.DownAfter <= 0 {
			req.DownAfter = 2
		}
		if req.DownAfter < 1 || req.DownAfter > 100 {
			respondWithError(w, http.StatusBadRequest, "down_after must be 1-100")
			return
		}
		if req.SpikeMult <= 0 {
			req.SpikeMult = 5
		}
		if req.SpikeMult < 2 || req.SpikeMult > 10 {
			respondWithError(w, http.StatusBadRequest, "spike_mult must be 2-10")
			return
		}

		id := newID()
		now := tsNow()
		// New sensors start PAUSED (no probing) so a freshly-added, possibly
		// mistyped, target can't fire down alerts before the user has a chance
		// to review it. The user resumes it from the dashboard.
		//
		// The row INSERT and the tag replace commit in ONE ImmediateTx (the
		// same single-tx idiom as the PATCH path): a tag-write failure
		// used to be logged and swallowed while the handler still returned 201
		// with the requested tags — the UI then showed tags the DB never had,
		// and with alert_scope='tags' the (paused) sensor would route no alerts
		// once the user resumed it. Now the INSERT rolls back and the request
		// fails instead of half-committing.
		err := s.db.ImmediateTx(r.Context(), func(c *sql.Conn) error {
			if _, err := c.ExecContext(r.Context(), `INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, created_at, status)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'paused', ?, 'up')`,
				id, req.Name, req.Target, req.Type, req.IntervalS, req.TimeoutMS, req.LossWarn, req.DownAfter, req.SpikeMult, now); err != nil {
				return err
			}
			if len(req.Tags) > 0 {
				return setSensorTagsInConn(r.Context(), c, id, req.Tags)
			}
			return nil
		})
		if err != nil {
			// Exact constraint text, not a bare "UNIQUE" substring

			if strings.Contains(err.Error(), "UNIQUE constraint failed: sensors.name") {
				respondWithError(w, http.StatusConflict, "sensor name already exists")
				return
			}
			respondInternal(w, "create sensor", err)
			return
		}
		log.Printf("API: created sensor %s (%s) [%s] [paused]", req.Name, id, req.Type)
		respondWithJSON(w, http.StatusCreated, Sensor{
			ID: id, Name: req.Name, Target: req.Target, Type: req.Type, Tags: req.Tags,
			IntervalS: req.IntervalS, TimeoutMS: req.TimeoutMS,
			LossWarn: req.LossWarn, DownAfter: req.DownAfter, SpikeMult: req.SpikeMult,
			State: "paused", Status: "up", CreatedAt: now,
		})

	default:
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// validSensorName rejects sensor names that are empty, overlong, or contain
// characters that would let a stored value escape its string context when the
// dashboard interpolates it into an inline event handler or alert card.
// Names are operator labels, not free text: no quotes, angle brackets,
// backslash, or control characters. Belt-and-braces alongside the
// frontend escJs() — it keeps the stored data clean for every consumer
// (alert cards, logs, the inspector) and stops a malicious account from
// planting a sensor whose name runs JS in other operators' browsers.
//
// This is a defense-in-depth INPUT gate, NOT the primary XSS mitigation:
// the frontend already does context-aware OUTPUT encoding — esc()
// (index.html) HTML-escapes every name render site and escJs() escapes
// names interpolated into JS string literals (the deleteSensor / setTag
// inline handlers). Removing the input gate would leave those still safe,
// but would let a malicious name through to the non-HTML consumers (alert
// cards, logs, the inspector) where output encoding does not apply.
//
// Why a blacklist and NOT the suggested whitelist (dismissed): a narrow whitelist like ^[a-zA-Z0-9_\-. ]+$ is more idiomatic
// but a REGRESSION — it rejects legitimate operator labels this gate is
// meant to allow: non-ASCII names (ÜberNAS) and benign punctuation
// (wifi:guest, nas/01, camera@front), all pinned VALID in
// TestValidSensorName. A broad whitelist that re-admits those characters is
// more complex, not less, and no safer: the ContainsAny below already blocks
// the exact string-escape metacharacters (' " ` \ < >) plus control chars —
// the complete set needed to prevent string-context escape in every consumer.
// As a defense-in-depth gate behind output encoding, it needs to be precise,
// not exhaustive.
//
// The length cap is in RUNES, not bytes: the
// UI's maxlength="60" counts characters, so a byte cap silently truncated
// CJK/emoji names to ~20 chars and the server 400'd what the form allowed.
// Invalid UTF-8 is refused at the write path so SQLite never stores a
// mojibake name.
func validSensorName(name string) bool {
	if name == "" || utf8.RuneCountInString(name) > 60 {
		return false
	}
	if !utf8.ValidString(name) {
		return false
	}
	// Reject the string-escape-relevant characters (quotes, backslash, angle
	// brackets, backtick) so a stored name can't break out of its string
	// context in any consumer.
	if strings.ContainsAny(name, "'\"`\\<>") {
		return false
	}
	// No control characters (newlines, tabs, NUL, …).
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// cleanTags trims, dedupes and caps sensor tags.
//
// Tags also pass the same string-escape gate as sensor names
// (validSensorName): they are interpolated into JS string literals in inline
// handlers (setTag / removeFormTag, index.html), so a tag like
// x');alert(1);// must not be storable — the output escaping (escJs) is the
// second layer, and the input gate keeps the non-HTML consumers (alert cards,
// logs, inspector) clean too.
func cleanTags(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range in {
		t = strings.TrimSpace(t)
		// 30-RUNE cap, matching the UI maxlength="30".
		if t == "" || utf8.RuneCountInString(t) > 30 || !validSensorName(t) || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
		if len(out) >= 8 {
			break
		}
	}
	return out
}

func (s *Server) handleSensorByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	switch r.Method {
	case http.MethodGet:
		var sn Sensor
		err := s.db.QueryRowContext(r.Context(), "SELECT id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at FROM sensors WHERE id = ?", id).
			Scan(&sn.ID, &sn.Name, &sn.Target, &sn.Type, &sn.IntervalS, &sn.TimeoutMS, &sn.LossWarn, &sn.DownAfter, &sn.SpikeMult, &sn.State, &sn.Status, &sn.CreatedAt)
		if err != nil {
			if err == sql.ErrNoRows {
				respondWithError(w, http.StatusNotFound, "sensor not found")
			} else {
				respondInternal(w, "get sensor "+id, err)
			}
			return
		}
		if sn.Type == "" {
			sn.Type = "icmp"
		}
		sn.Tags = s.db.SensorTags(id)
		v := SensorView{Sensor: sn}
		if sn.State == "active" {
			v.Stats = s.probeWorker.GetStats(id)
		}
		s.fillHTTPView(&v)
		respondWithJSON(w, http.StatusOK, v)

	case http.MethodPatch:
		var req struct {
			Name      *string   `json:"name"`
			Target    *string   `json:"target"`
			Type      *string   `json:"type"`
			Tags      *[]string `json:"tags"`
			IntervalS *int      `json:"interval_s"`
			TimeoutMS *int      `json:"timeout_ms"`
			LossWarn  *int      `json:"loss_warn"`
			DownAfter *int      `json:"down_after"`
			SpikeMult *int      `json:"spike_mult"`
			State     *string   `json:"state"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			code, msg := requestBodyErr(err)
			respondWithError(w, code, msg)
			return
		}

		// Target and type validate as a pair against the RESULTING type —
		// INSIDE the ImmediateTx below, where the row is read under the
		// write lock: the dashboard edits both in one modal, so a target
		// must be valid for the type the sensor will end up with (URL for
		// http, host for icmp), whether the user changed the target, the
		// type, or both. (here against a pre-lock snapshot fed by up to two extra
		// SELECTs, and in-tx against fresh values. The in-tx check is a
		// superset returning the identical 400s, so only pure
		// request-shape checks — empty fields, ranges — run before the
		// write lock.)
		resultType := ""
		if req.Type != nil {
			resultType = normalizeProbeType(*req.Type)
		}
		resultTarget := ""
		if req.Target != nil {
			resultTarget = strings.TrimSpace(*req.Target)
		}

		sets, args := []string{}, []interface{}{}
		// newTags holds the cleaned tag list when req.Tags was sent; the
		// write happens after ALL validation, in the UPDATE transaction.
		newTags := []string{}
		add := func(col string, val interface{}) {
			sets = append(sets, col+" = ?")
			args = append(args, val)
		}
		if req.Name != nil {
			if strings.TrimSpace(*req.Name) == "" {
				respondWithError(w, http.StatusBadRequest, "name cannot be empty")
				return
			}
			trimmed := strings.TrimSpace(*req.Name)
			if !validSensorName(trimmed) {
				respondWithError(w, http.StatusBadRequest, "name must be 1-60 characters and may not contain quotes, angle brackets, backslash, or control characters")
				return
			}
			add("name", trimmed)
		}
		if req.Target != nil {
			if resultTarget == "" {
				respondWithError(w, http.StatusBadRequest, "target cannot be empty")
				return
			}
			// Format validation against the RESULTING type runs in-tx (see
			// above): the pre-tx copy validated a possibly-stale pair.
			add("target", resultTarget)
		}
		if req.Type != nil {
			add("type", resultType)
		}
		if req.Tags != nil {
			// Validated (cleanTags) but NOT written yet: the tag write moves
			// to after ALL field validation, into the same transaction as
			// the UPDATE — a 400 on a later field must not leave the tag
			// set changed (repro: {"tags":["sneaky"],"interval_s":0} used to
			// persist the tags and then 400).
			newTags = cleanTags(*req.Tags)
		}
		if req.IntervalS != nil {
			if *req.IntervalS < minIntervalS || *req.IntervalS > 3600 {
				respondWithError(w, http.StatusBadRequest, "interval_s must be 5-3600")
				return
			}
			add("interval_s", *req.IntervalS)
		}
		if req.TimeoutMS != nil {
			if *req.TimeoutMS < 100 || *req.TimeoutMS > 30000 {
				respondWithError(w, http.StatusBadRequest, "timeout_ms must be 100-30000")
				return
			}
			add("timeout_ms", *req.TimeoutMS)
		}
		// The effective timeout-vs-interval cross-check runs in-tx against
		// the fresh stored values: the pre-tx copy
		// existed only to fast-fail, and the in-tx check returns the
		// identical 400.
		if req.LossWarn != nil {
			if *req.LossWarn < 1 || *req.LossWarn > 100 {
				respondWithError(w, http.StatusBadRequest, "loss_warn must be 1-100")
				return
			}
			add("loss_warn", *req.LossWarn)
		}
		if req.DownAfter != nil {
			if *req.DownAfter < 1 || *req.DownAfter > 100 {
				respondWithError(w, http.StatusBadRequest, "down_after must be 1-100")
				return
			}
			add("down_after", *req.DownAfter)
		}
		if req.SpikeMult != nil {
			if *req.SpikeMult < 2 || *req.SpikeMult > 10 {
				respondWithError(w, http.StatusBadRequest, "spike_mult must be 2-10")
				return
			}
			add("spike_mult", *req.SpikeMult)
		}
		if req.State != nil {
			if *req.State != "active" && *req.State != "paused" {
				respondWithError(w, http.StatusBadRequest, "state must be active or paused")
				return
			}
			add("state", *req.State)
		}
		if len(sets) == 0 && req.Tags == nil {
			respondWithError(w, http.StatusBadRequest, "no fields to update")
			return
		}
		// One BEGIN IMMEDIATE transaction (single-read shape): the row is read ONCE,
		// INSIDE it, and the type/target pair (plus the effective
		// interval/timeout cross-check) validated against those FRESH
		// values before the UPDATE — this read also carries the 404. A
		// concurrent PATCH that changed the target/type between a pre-lock
		// read and the write used to slip through validated against the
		// stale pair; BEGIN IMMEDIATE holds the write lock from the start,
		// so no concurrent writer can change the row between the read and
		// the UPDATE. The UPDATE and the tag replace commit together, so a
		// constraint failure (rename) or a crash can't leave the tags
		// changed while the row is not (or vice versa).
		var patchErr error
		patchErr = s.db.ImmediateTx(r.Context(), func(c *sql.Conn) error {
			ctx := r.Context()
			var txType, txTarget string
			var txIntervalS, txTimeoutMS int
			if err := c.QueryRowContext(ctx,
				"SELECT type, target, interval_s, timeout_ms FROM sensors WHERE id = ?", id).
				Scan(&txType, &txTarget, &txIntervalS, &txTimeoutMS); err != nil {
				return errPatchSensorGone
			}
			if txType == "" {
				txType = "icmp"
			}
			freshType := txType
			if req.Type != nil {
				freshType = normalizeProbeType(*req.Type)
			}
			freshTarget := txTarget
			if req.Target != nil {
				freshTarget = strings.TrimSpace(*req.Target)
			}
			if freshType == "http" {
				if !validURL(freshTarget) {
					return errPatchTargetNotURL
				}
			} else if !validTarget(freshTarget) {
				return errPatchTargetInvalid
			}
			feffIntervalS := txIntervalS
			if req.IntervalS != nil {
				feffIntervalS = *req.IntervalS
			}
			feffTimeoutMS := txTimeoutMS
			if req.TimeoutMS != nil {
				feffTimeoutMS = *req.TimeoutMS
			}
			if feffTimeoutMS > feffIntervalS*1000 {
				return errPatchTimeoutExceedsInterval
			}

			if len(sets) > 0 {
				args = append(args, id)
				res, err := c.ExecContext(ctx, "UPDATE sensors SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...)
				if err != nil {
					// A rename hitting the UNIQUE name constraint is a 409,
					// exactly like POST — not a 500 with raw SQL text. Exact
					// constraint text.
					if strings.Contains(err.Error(), "UNIQUE constraint failed: sensors.name") {
						return errPatchNameConflict
					}
					return err
				}
				if n, _ := res.RowsAffected(); n == 0 {
					return errPatchSensorGone
				}
			}
			if req.Tags != nil {
				return setSensorTagsInConn(r.Context(), c, id, newTags)
			}
			return nil
		})
		switch {
		case errors.Is(patchErr, errPatchSensorGone):
			respondWithError(w, http.StatusNotFound, "sensor not found")
		case errors.Is(patchErr, errPatchTargetNotURL):
			respondWithError(w, http.StatusBadRequest, "target must be an http:// or https:// URL (e.g. https://example.com/health)")
		case errors.Is(patchErr, errPatchTargetInvalid):
			respondWithError(w, http.StatusBadRequest, "target must be an IPv4 address or hostname")
		case errors.Is(patchErr, errPatchTimeoutExceedsInterval):
			respondWithError(w, http.StatusBadRequest, "timeout_ms must not exceed interval_s*1000")
		case errors.Is(patchErr, errPatchNameConflict):
			respondWithError(w, http.StatusConflict, "sensor name already exists")
		case patchErr != nil:
			respondInternal(w, "update sensor "+id, patchErr)
		}
		if patchErr != nil {
			return
		}

		// Sync probe worker: paused flag, or (re)spawn the loop on resume so the
		// sensor picks up new config immediately instead of waiting for restart.
		if req.State != nil {
			s.probeWorker.SetPaused(id, *req.State == "paused")
		}
		// A config change requires respawning the loop so the running probe
		// picks up the new values: target/interval/timeout are read by the
		// loop itself, type by probeTarget, and loss_warn/down_after by
		// deriveStatus — all from the spawn-time config copy, none are
		// hot-reloaded. name and tags respawn too: the
		// alert path reads c.name (alert text) and c.tags (alertGates routing)
		// from the same spawn-time copy, so a name/tags PATCH without a respawn
		// left stale alert behavior until process restart.
		if req.Target != nil || req.Type != nil || req.IntervalS != nil || req.TimeoutMS != nil ||
			req.LossWarn != nil || req.DownAfter != nil || req.Name != nil || req.Tags != nil {
			s.probeWorker.Restart(id)
		}

		respondWithJSON(w, http.StatusOK, map[string]string{"status": "updated"})

	case http.MethodDelete:
		res, err := s.db.ExecContext(r.Context(), "DELETE FROM sensors WHERE id = ?", id)
		if err != nil {
			respondInternal(w, "delete sensor "+id, err)
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			respondWithError(w, http.StatusNotFound, "sensor not found")
			return
		}
		s.probeWorker.Remove(id)
		w.WriteHeader(http.StatusNoContent)

	default:
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// setSensorTagsInConn replaces the sensor's tags (DELETE + INSERTs) on the
// CALLER's pinned connection, for the PATCH sensor write path that runs
// inside a BEGIN IMMEDIATE ImmediateTxa *sql.Tx
// from db.Begin can't join it because the transaction lives on the pinned
// connection (db.SetSensorTags keeps its own transaction and can't join one
// either, so the in-conn twin lives here rather than in db.go). The caller's
// ctx is threaded through: every statement on
// this path honors request cancellation, matching the ImmediateTx boundary.
func setSensorTagsInConn(ctx context.Context, c *sql.Conn, id string, tags []string) error {
	if _, err := c.ExecContext(ctx, "DELETE FROM sensor_tags WHERE sensor_id = ?", id); err != nil {
		return err
	}
	for _, tag := range tags {
		if _, err := c.ExecContext(ctx, "INSERT OR IGNORE INTO sensor_tags (sensor_id, tag) VALUES (?, ?)", id, tag); err != nil {
			return err
		}
	}
	return nil
}

// handleSensorPing performs one immediate probe ("Pulse Now"). Works while
// paused (SPEC §2). The probe IS recorded in history (a manual pulse is a real
// sample the dashboard should reflect) but does not drive status, alerts, or
// the loss/uptime aggregates — see ProbeWorker.PingNow. It runs with the
// sensor's own configured timeout (the pulse is the same probe the sensor
// runs on schedule; 1s fallback for a legacy zeroed row).
func (s *Server) handleSensorPing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := r.PathValue("id")

	o, err := s.probeWorker.PingNow(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondWithError(w, http.StatusNotFound, "sensor not found")
			return
		}
		if errors.Is(err, errPulseCoolingDown) {
			respondWithError(w, http.StatusTooManyRequests, "pulse too soon — try again in a moment")
			return
		}
		respondInternal(w, "pulse sensor "+id, err)
		return
	}
	respondWithJSON(w, http.StatusOK, pulseResponse(o))
}

// pulseResponse shapes a "Pulse Now" diagnostic result. rtt_ms is null (not
// 0) for a dropped probe: 0 ms is a real (if implausible) RTT, and a lost
// probe has NO measured round-trip — reporting 0 would read as "instant". The
// dashboard keys off `lost` for the toast. http_status is present only for
// HTTP sensors that got a response, so an HTTP card's toast can say
// "HTTP 503" instead of a bare loss.
func pulseResponse(o probeOutcome) map[string]interface{} {
	var rttMs *float64
	if !o.lost {
		v := o.rttMs
		rttMs = &v
	}
	resp := map[string]interface{}{
		"rtt_ms": rttMs, // null when lost
		"lost":   o.lost,
	}
	if o.httpCode != nil {
		resp["http_status"] = *o.httpCode
	}
	return resp
}

// handleSensorHistory returns the last N probe records (SPEC §4, fix #4).
func (s *Server) handleSensorHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := r.PathValue("id")
	n := 60
	if v := r.URL.Query().Get("n"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			n = p
		}
	}
	if n > 500 {
		n = 500
	}

	var exists int
	if err := s.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM sensors WHERE id = ?", id).Scan(&exists); err != nil || exists == 0 {
		respondWithError(w, http.StatusNotFound, "sensor not found")
		return
	}

	rows, err := s.db.QueryContext(r.Context(), "SELECT ts, rtt_ms FROM probes WHERE sensor_id = ? ORDER BY ts DESC LIMIT ?", id, n)
	if err != nil {
		respondInternal(w, "sensor history "+id, err)
		return
	}
	defer rows.Close()

	out := []ProbeRow{}
	for rows.Next() {
		var ts time.Time
		var rtt *float64
		if err := rows.Scan(&ts, &rtt); err != nil {
			// A corrupt row (e.g. a non-RFC3339 ts after a bad
			// migration) must be visible in the service log, not a
			// silently truncated history with a 200 — same contract
			// as fetchSensors' per-row scan log.
			log.Printf("API: skipping corrupt probe row for %s: %v", id, err)
			continue
		}
		out = append(out, ProbeRow{
			TS:   ts.UTC().Format(time.RFC3339Nano),
			RTT:  rtt,
			Lost: rtt == nil,
		})
	}
	if err := rows.Err(); err != nil {
		respondInternal(w, "sensor history "+id, err)
		return
	}
	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"sensor_id": id,
		"count":     len(out),
		"probes":    out, // newest first
	})
}

// handleSensorClearHistory wipes one sensor's probe history, events, and
// alert state and resets its status to up — the next probe tick rebuilds
// the 60-probe window from scratch. Use after changing a sensor's target,
// or to flush bad data (e.g. from a period when probing was broken).
func (s *Server) handleSensorClearHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := r.PathValue("id")

	var name string
	if err := s.db.QueryRowContext(r.Context(), "SELECT name FROM sensors WHERE id = ?", id).Scan(&name); err != nil {
		respondWithError(w, http.StatusNotFound, "sensor not found")
		return
	}

	var probes, events int64
	var err error
	// The two LARGE deletes run batched (the purgeOld idiom, review
	// 2026-10-24): one DELETE of a long-lived sensor's rows held the WAL
	// write lock for its whole duration, stalling probe INSERTs and (via
	// syncSensors' deliberate under-lock fresh reads) every probe loop up
	// to the 15s busy_timeout. Batching caps each statement at a few ms.
	// Partial completion is harmless here — the target is a WIPE, so a
	// retry just deletes the remainder — so atomicity of these two is NOT
	// worth the lock hold. The small state-consistency steps below stay
	// atomic: alert_state removal and the status reset either all commit
	// or none (the old code ran everything autocommit and ignored the last
	// two errors — that is the half-cleared bug the tx still fixes).
	if probes, err = deleteRowsBatched(r.Context(), s.db, "probes", "sensor_id = ?", []any{id}); err != nil {
		respondInternal(w, "clear probes "+id, err)
		return
	}
	if events, err = deleteRowsBatched(r.Context(), s.db, "events", "sensor_id = ?", []any{id}); err != nil {
		respondInternal(w, "clear events "+id, err)
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondInternal(w, "clear history begin "+id, err)
		return
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit succeeds

	if _, err := tx.ExecContext(r.Context(), "DELETE FROM alert_state WHERE sensor_id = ?", id); err != nil {
		respondInternal(w, "clear alert_state "+id, err)
		return
	}
	if _, err := tx.ExecContext(r.Context(), "UPDATE sensors SET status = 'up' WHERE id = ?", id); err != nil {
		respondInternal(w, "reset status "+id, err)
		return
	}
	if err := tx.Commit(); err != nil {
		respondInternal(w, "clear history commit "+id, err)
		return
	}
	// Keep the in-memory state in step with the DB: the cleared sensor's
	// series AND its ProbeState (lastStatus/fastRetry/lastHTTPStatus/
	// lastCertExpiry) are gone from the DB, so both must go from memory
	// too (else the card would show the just-deleted history, and a stale
	// "HTTP 503" badge on an "up" sensor, until the next probe). Commit
	// first: if the DB write fails the cache is kept (its rows are still
	// there); if the reset failed, the next tick rebuilds the cache entry.
	s.probeWorker.ResetStatsFor(id)

	log.Printf("API: cleared history for %s (%d probes, %d events)", name, probes, events)
	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"sensor":  name,
		"cleared": map[string]int64{"probes": probes, "events": events},
	})
}

// deleteRowsBatched deletes a table's rows (optionally filtered) in
// purgeBatchSize chunks — the purgeOld idiom (probe.go): each statement is
// its own autocommit delete of a bounded row set, so the WAL write lock is
// held for milliseconds per statement instead of for a whole-million-row
// sweep (probe INSERTs and syncSensors' under-lock reads stay responsive
// up to, but not through, the 15s busy_timeout). Returns the total rows
// deleted. The table/where strings are fixed call-site literals, never
// user input.
func deleteRowsBatched(ctx context.Context, db *DB, table, where string, args []any) (int64, error) {
	w := ""
	if where != "" {
		w = " WHERE " + where
	}
	q := "DELETE FROM " + table + " WHERE id IN (SELECT id FROM " + table + w + " LIMIT ?)"
	var total int64
	for {
		res, err := db.ExecContext(ctx, q, append(append([]any{}, args...), purgeBatchSize)...)
		if err != nil {
			return total, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, err
		}
		total += n
		if n < purgeBatchSize {
			return total, nil
		}
	}
}

// handleClearAllHistory is the bulk version of handleSensorClearHistory:
// every sensor's probes/events/alert_state are wiped and statuses reset,
// so the whole fleet rebuilds its windows from the next probe tick.
func (s *Server) handleClearAllHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var probes, events int64
	// Batched large deletes + atomic small steps: see
	// handleSensorClearHistory for the reasoning (review 2026-10-24). At
	// 100 sensors @ 5s the probes table holds ~1.7M rows — this wipe was
	// the worst single-statement write lock holder in the app, exactly the
	// class purgeOld was rewritten for.
	var err error
	if probes, err = deleteRowsBatched(r.Context(), s.db, "probes", "", nil); err != nil {
		respondInternal(w, "clear all probes", err)
		return
	}
	if events, err = deleteRowsBatched(r.Context(), s.db, "events", "", nil); err != nil {
		respondInternal(w, "clear all events", err)
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondInternal(w, "clear all history begin", err)
		return
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit succeeds

	if _, err := tx.ExecContext(r.Context(), "DELETE FROM alert_state"); err != nil {
		respondInternal(w, "clear all alert_state", err)
		return
	}
	if _, err := tx.ExecContext(r.Context(), "UPDATE sensors SET status = 'up'"); err != nil {
		respondInternal(w, "clear all reset status", err)
		return
	}
	if err := tx.Commit(); err != nil {
		respondInternal(w, "clear all history commit", err)
		return
	}
	// Wipe the whole in-memory state too: every sensor's series AND
	// ProbeState (see ResetStatsAll for the fields and why).
	s.probeWorker.ResetStatsAll()

	log.Printf("API: cleared ALL history (%d probes, %d events)", probes, events)
	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"cleared": map[string]int64{"probes": probes, "events": events},
	})
}

// cloneMaxAttempts bounds the INSERT retries when concurrent clones race for
// the same name.
const cloneMaxAttempts = 5

// Sentinel errors from the PATCH sensor write transaction: the re-validation runs inside the BEGIN IMMEDIATE tx, so its
// failures are returned as sentinels and mapped to HTTP codes by the
// handler (the response can't be written from inside the closure without
// tangling the commit/rollback path).
var (
	errPatchSensorGone             = errors.New("sensor not found")
	errPatchTargetNotURL           = errors.New("target must be a URL")
	errPatchTargetInvalid          = errors.New("target is invalid for the probe type")
	errPatchTimeoutExceedsInterval = errors.New("timeout exceeds interval")
	errPatchNameConflict           = errors.New("sensor name already exists")
)

// handleSensorClone creates a copy of a sensor with a new unique name
// (name-copy, name-copy2, ...). The clone starts PAUSED, like a new sensor.
func (s *Server) handleSensorClone(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := r.PathValue("id")

	var src Sensor
	err := s.db.QueryRowContext(r.Context(), "SELECT id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at FROM sensors WHERE id = ?", id).
		Scan(&src.ID, &src.Name, &src.Target, &src.Type, &src.IntervalS, &src.TimeoutMS, &src.LossWarn, &src.DownAfter, &src.SpikeMult, &src.State, &src.Status, &src.CreatedAt)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "sensor not found")
		return
	}
	if src.Type == "" {
		src.Type = "icmp"
	}
	src.Tags = s.db.SensorTags(id)

	// Pick the first free name and insert it. The existing clone names are
	// fetched in ONE query and the first free suffix is picked in memory
	// (the old loop ran up to 100 sequential SELECT COUNT(*) round-trips
	// before the first INSERT). Another
	// request can take the name between the fetch and the INSERT (the
	// sensors.name UNIQUE index is the real arbiter), so a UNIQUE failure
	// marks the name taken and moves on to the next candidate: at most
	// cloneMaxAttempts inserts, then 409.
	//
	// GLOB, not LIKE: the UNIQUE index is case-sensitive (BINARY
	// collation) and GLOB matches case-sensitively, while LIKE folds ASCII
	// case — a LIKE match set would drift from the uniqueness semantics.
	// GLOB metacharacters in the base name (* ? [ are legal —
	// validSensorName is a blacklist) can only distort the match set,
	// never the outcome: an over-match skips free names (we pick a higher
	// suffix), an under-match (a "[" class) lets a taken name through to
	// the INSERT, where the UNIQUE index rejects it and the retry below
	// moves on — the same contract the old exact-match loop had.
	newID := newID()
	now := tsNow()
	created := false
	next := 1 // candidate suffix: 1 -> "-copy", n>=2 -> "-copyN"
	// The clone name must itself satisfy validSensorName (≤60 runes) —
	// otherwise the API would reject a later PATCH that renames the clone
	// Reserve room for the LONGEST suffix
	// ("-copy100", 8 ASCII runes) by truncating the source name first; the
	// shorter suffixes ("-copy", "-copy2") then always fit. Truncate by
	// RUNES, not bytes: the cap is a rune cap (0c35448), so a byte cut
	// would shrink CJK/emoji names to a third of their allowed length.
	cloneBase := src.Name
	const cloneSuffixCeil = 8 // len("-copy100")
	if r := []rune(cloneBase); len(r) > 60-cloneSuffixCeil {
		cloneBase = string(r[:60-cloneSuffixCeil])
	}
	rows, err := s.db.QueryContext(r.Context(), "SELECT name FROM sensors WHERE name GLOB ?", cloneBase+"-copy*")
	if err != nil {
		respondInternal(w, "clone sensor "+id, err)
		return
	}
	taken := make(map[string]bool)
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			// A skipped name is safe (a taken name that reaches the
			// INSERT is rejected by the UNIQUE index and the retry
			// advances), but log it like the other per-row scans.
			log.Printf("API: skipping corrupt clone name row for %s: %v", id, err)
		} else {
			taken[n] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		respondInternal(w, "clone sensor "+id, err)
		return
	}
	nextFreeName := func() (string, bool) {
		for {
			if next > 100 { // same ceiling as before: the last usable name is -copy100
				return "", false
			}
			cand := cloneBase + "-copy"
			if next > 1 {
				cand = fmt.Sprintf("%s-copy%d", cloneBase, next)
			}
			if !taken[cand] {
				return cand, true
			}
			next++
		}
	}
	name, ok := nextFreeName()
	if !ok {
		respondWithError(w, http.StatusConflict, "too many clones with this name")
		return
	}
	for attempt := 0; attempt < cloneMaxAttempts && !created; attempt++ {
		// Clone starts PAUSED, matching new-sensor behavior. The row
		// INSERT and the tag replace commit in ONE ImmediateTx (the same
		// single-tx idiom as the POST/PATCH paths): a tag-write
		// failure used to be logged and swallowed while the clone was
		// still returned 201 with the source's tags — the UI then showed
		// tags the DB never had, and with alert_scope='tags' the (paused)
		// clone would route no alerts once resumed. Now the INSERT rolls
		// back and the request fails instead of half-committing.
		err = s.db.ImmediateTx(r.Context(), func(c *sql.Conn) error {
			if _, err := c.ExecContext(r.Context(), `INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, created_at, status)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'paused', ?, 'up')`,
				newID, name, src.Target, src.Type, src.IntervalS, src.TimeoutMS, src.LossWarn, src.DownAfter, src.SpikeMult, now); err != nil {
				return err
			}
			if len(src.Tags) > 0 {
				return setSensorTagsInConn(r.Context(), c, newID, src.Tags)
			}
			return nil
		})
		if err == nil {
			created = true
			break
		}
		// Only a name collision is retryable — exact constraint text

		if !strings.Contains(err.Error(), "UNIQUE constraint failed: sensors.name") {
			respondInternal(w, "clone sensor "+id, err)
			return
		}
		// Lost the race for this name: the racer owns it now, so mark it
		// taken in the snapshot and advance (no re-query — the UNIQUE
		// index is the arbiter, the same contract the old loop had).
		taken[name] = true
		name, ok = nextFreeName()
		if !ok {
			respondWithError(w, http.StatusConflict, "too many clones with this name")
			return
		}
	}
	if !created {
		respondWithError(w, http.StatusConflict, "too many clones with this name")
		return
	}
	respondWithJSON(w, http.StatusCreated, Sensor{
		ID: newID, Name: name, Target: src.Target, Type: src.Type, Tags: src.Tags,
		IntervalS: src.IntervalS, TimeoutMS: src.TimeoutMS,
		LossWarn: src.LossWarn, DownAfter: src.DownAfter, SpikeMult: src.SpikeMult,
		State: "paused", Status: "up", CreatedAt: now,
	})
}

// handleTags lists every tag in use (with sensor counts) and supports
// DELETE for removing a tag from all its sensors.
func (s *Server) handleTags(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		respondWithJSON(w, http.StatusOK, s.db.AllTags())
		return
	case http.MethodDelete:
		// Destructive and fleet-wide: strips the tag from EVERY sensor
		// and respawns every affected probe loop. Admin-only for
		// consistency with DELETE /api/history (review 2026-10-24) —
		// per-sensor edits stay operator-scoped; all-sensors rewrites
		// are admin surface.
		if s.auth.Enabled() && !s.auth.IsAdmin(s.sessionFrom(r)) {
			respondWithError(w, http.StatusForbidden, "admin only")
			return
		}
		tag := r.URL.Query().Get("tag")
		if tag == "" {
			respondWithError(w, http.StatusBadRequest, "tag query parameter is required")
			return
		}
		// Collect the tagged sensors BEFORE the delete: each probe loop
		// holds a spawn-time copy of its tag set (alert routing reads
		// c.tags from that copy), so every affected loop must be respawned
		// to pick up the new setwithout this, a
		// sensor that just left the alert_filter's tag scope keeps the
		// stale routing (alerts it shouldn't send, or silence it should
		// have) until the next process restart.
		var tagged []string
		rows, err := s.db.QueryContext(r.Context(), "SELECT sensor_id FROM sensor_tags WHERE tag = ?", tag)
		if err != nil {
			respondInternal(w, "delete tag "+tag, err)
			return
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				// A skipped id is safe (the rows.Err() check below 500s a
				// mid-stream failure), but log it like the other per-row
				// scans.
				log.Printf("API: skipping corrupt sensor_tags row for tag %s: %v", logSafe(tag), err)
			} else {
				tagged = append(tagged, id)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			// Fail before DeleteTag: a truncated tagged list would delete
			// the tag while leaving some loops un-respawned with stale
			// alert routing.
			respondInternal(w, "delete tag "+tag, err)
			return
		}
		n, err := s.db.DeleteTag(tag)
		if err != nil {
			respondInternal(w, "delete tag "+tag, err)
			return
		}
		for _, id := range tagged {
			s.probeWorker.Restart(id)
		}
		respondWithJSON(w, http.StatusOK, map[string]interface{}{"status": "deleted", "sensors_updated": n})
	default:
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

type GraphPoint struct {
	T       int64    `json:"t"` // bucket start, epoch seconds
	Total   int      `json:"total"`
	Lost    int      `json:"lost"`
	Avg     *float64 `json:"avg"`
	Max     *float64 `json:"max"`
	LossPct float64  `json:"loss_pct"`
}

// handleSensorGraph returns bucketed RTT/loss points for a 1h or 24h range.
func (s *Server) handleSensorGraph(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := r.PathValue("id")
	var bucketSecs int
	var from string
	var dur time.Duration
	switch r.URL.Query().Get("range") {
	case "24h":
		bucketSecs, from, dur = 900, "-24 hours", 24*time.Hour
	case "1h":
		bucketSecs, from, dur = 60, "-1 hour", time.Hour
	default:
		respondWithError(w, http.StatusBadRequest, "range must be 1h or 24h")
		return
	}

	var exists int
	if err := s.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM sensors WHERE id = ?", id).Scan(&exists); err != nil || exists == 0 {
		respondWithError(w, http.StatusNotFound, "sensor not found")
		return
	}

	// Time windows MUST compare epoch values, not raw strings: ts is stored
	// as RFC3339 ('2026-10-04T20:47:28.530Z') while datetime('now', ?)
	// returns space-separated ('2026-10-04 19:47:28'), so a plain
	// `ts >= datetime('now', ?)` string comparison matched nearly every row
	// and the "1h"/"24h" graphs silently showed the ENTIRE history.
	// CAST(strftime('%s', ...)) normalizes both sides to epoch seconds.
	//
	// PERF NOTE (dismissed): a covering index
	// probes(sensor_id, ts, rtt_ms) was proposed to avoid the base-table row
	// fetches for COUNT/SUM/AVG/MAX. Measured at the review's own worst-case
	// scale (72,000 rows = 50 sensors x 24h @ 60s): the query takes 0.74 ms
	// as-is, the covering index saves ~0.06 ms (8%), and costs +48% on every
	// probe INSERT (4.4 -> 6.5 ms per 2000 rows) plus index storage. The
	// probes table is retention-bounded (24h, hourly purgeOld) so there is no
	// growth trajectory, and the graph endpoint is on-demand, not the 5s poll
	// hot path (that one is served from the in-memory stats cache). Net: a
	// constant write-path tax to shave 0.06 ms off an occasional read — not
	// worth it.
	//
	// SECOND PROPOSAL (same review pass — rejected as UNSAFE): binding a
	// Go-formatted RFC3339 cutoff and comparing `ts >= ?` as a string to
	// unlock an index range seek. ts is stored as RFC3339Nano (tsNow, db.go),
	// which STRIPS trailing zeros — the live DB contains rows with 6-9 digit
	// fractional widths. Variable-width fractions break lexicographic ==
	// chronological: '...T01:57:25.13Z' (25.130s) compares GREATER than
	// '...T01:57:25.134241458Z' (25.134s) because 'Z' > '4', so the window
	// mis-filters by up to a second in both directions. This is the exact
	// bug class the epoch-normalization comment above was written for (plain
	// string comparison once made the graphs show the ENTIRE history). The
	// strftime-epoch form is the format-robust comparison. And the range
	// seek would save no rows anyway: the 24h graph window equals the 24h
	// retention, so every row of a sensor is inside the window.
	//
	// THIRD PROPOSAL (APPLIED): a seekable
	// string bound ADDED ALONGSIDE the epoch filter, which the epoch filter
	// alone cannot express. The strftime filter stays the EXACT arbiter;
	// `ts >= ?` only lets the planner range-seek idx_probes_sensor_ts to
	// the 1h tail instead of scanning the sensor's full 24h slice
	// (17,280 rows @ 5s minIntervalS -> 720). The 1s slack makes the bound
	// safe against legacy variable-width fractional rows: any row the
	// epoch filter includes has strictly greater integer seconds than the
	// bound's instant (cutoff >= bound + 1s), so the seconds digits decide
	// the string comparison regardless of fractional width; extras inside
	// the slack are dropped by the epoch filter. Replacing the epoch
	// filter with a string compare remains UNSAFE (second proposal). The
	// 24h query gains nothing (window == retention), which is why the
	// bound is harmless there. FORMAT CONTRACT: the bound only compares
	// correctly against the single-writer fmtTS format (Z-suffix, 9-digit
	// fraction — db.go tsLayout). Rows written in other RFC3339
	// renderings (e.g. "+00:00" offsets, which sort BELOW the bound)
	// would be silently excluded — test seeders must use fmtTS.
	// Measured (17,280 rows, one sensor): plan goes from "scan sensor
	// slice + strftime per row" to a B-tree range seek; see commit
	// message for timings.
	cutoffStr := fmtTS(time.Now().UTC().Add(-dur - time.Second))
	// manual = 0: "Pulse Now" rows are diagnostic clicks, not scheduled
	// samples — the card's loss/uptime aggregates (computeSensorStats)
	// skip them, so the graph must too: // a lost pulse on a healthy sensor must not draw a loss bucket here.
	rows, err := s.db.QueryContext(r.Context(), `SELECT (strftime('%s', ts) / ?) * ? AS bucket,
		COUNT(*) AS total,
		COALESCE(SUM(rtt_ms IS NULL), 0) AS lost,
		AVG(rtt_ms) AS avg_rtt,
		MAX(rtt_ms) AS max_rtt
		FROM probes WHERE sensor_id = ?
			AND manual = 0
			AND ts >= ?
			AND CAST(strftime('%s', ts) AS INTEGER) >= CAST(strftime('%s', datetime('now', ?)) AS INTEGER)
		GROUP BY bucket ORDER BY bucket`, bucketSecs, bucketSecs, id, cutoffStr, from)
	if err != nil {
		respondInternal(w, "graph query", err)
		return
	}
	defer rows.Close()

	points := []GraphPoint{}
	for rows.Next() {
		var p GraphPoint
		if err := rows.Scan(&p.T, &p.Total, &p.Lost, &p.Avg, &p.Max); err != nil {
			// Defensive: the WHERE clause already drops NULL-bucket
			// rows, so a scan failure here means a schema-level
			// type change — log it, don't ship a silently truncated
			// graph (same contract as fetchSensors).
			log.Printf("API: skipping corrupt graph bucket row for %s: %v", id, err)
			continue
		}
		if p.Total > 0 {
			p.LossPct = float64(p.Lost) / float64(p.Total) * 100
		}
		points = append(points, p)
	}
	if err := rows.Err(); err != nil {
		respondInternal(w, "graph query", err)
		return
	}

	var total, lostTotal int
	for _, p := range points {
		total += p.Total
		lostTotal += p.Lost
	}
	uptime := 0.0
	if total > 0 {
		uptime = float64(total-lostTotal) / float64(total) * 100
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"sensor_id":   id,
		"range":       r.URL.Query().Get("range"),
		"bucket_secs": bucketSecs,
		"points":      points,
		"total":       total,
		"lost_total":  lostTotal,
		"uptime_pct":  uptime,
	})
}

type EventView struct {
	ID       int64     `json:"id"`
	SensorID string    `json:"sensor_id"`
	Sensor   string    `json:"sensor"`
	TS       time.Time `json:"ts"`
	From     string    `json:"from"`
	To       string    `json:"to"`
	Note     string    `json:"note"`
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		// Fleet-wide data wipe — admin-only, exactly like DELETE
		// /api/history (requireAdmin). A regular (lower-trust) account
		// must not be able to erase the audit/event log (review
		// 2026-10-24). The GET branch below stays open to any session:
		// the event feed is dashboard data, not an admin surface.
		if s.auth.Enabled() && !s.auth.IsAdmin(s.sessionFrom(r)) {
			respondWithError(w, http.StatusForbidden, "admin only")
			return
		}
		// Batched (purgeOld idiom): a single unbatched DELETE FROM events
		// held the WAL write lock across the whole table, stalling probe
		// INSERTs and every probe loop up to the 15s busy_timeout.
		n, err := deleteRowsBatched(r.Context(), s.db, "events", "", nil)
		if err != nil {
			respondInternal(w, "delete events", err)
			return
		}
		respondWithJSON(w, http.StatusOK, map[string]interface{}{"status": "cleared", "events_deleted": n})
		return
	}
	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	n := 50
	if v := r.URL.Query().Get("n"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			n = p
		}
	}
	// Cap like the sensor-history endpoint (500): a huge n must not turn this
	// into an unbounded full-table read on a long-running instance.
	if n > 500 {
		n = 500
	}
	rows, err := s.db.QueryContext(r.Context(), `SELECT e.id, e.sensor_id, COALESCE(s.name, e.sensor_id), e.ts, e.from_status, e.to_status, e.note
		FROM events e LEFT JOIN sensors s ON s.id = e.sensor_id
		ORDER BY e.ts DESC LIMIT ?`, n)
	if err != nil {
		respondInternal(w, "query events", err)
		return
	}
	defer rows.Close()

	events := []EventView{}
	for rows.Next() {
		var e EventView
		if err := rows.Scan(&e.ID, &e.SensorID, &e.Sensor, &e.TS, &e.From, &e.To, &e.Note); err != nil {
			// A corrupt row must be visible in the service log, not a
			// silently truncated event feed with a 200 (same contract
			// as fetchSensors).
			log.Printf("API: skipping corrupt event row: %v", err)
			continue
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		respondInternal(w, "query events", err)
		return
	}
	respondWithJSON(w, http.StatusOK, events)
}

// webhookMasked shows only scheme://host/*** — the path and query carry the credential for every supported provider.
func webhookMasked(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "***"
	}
	return u.Scheme + "://" + u.Host + "/***" // path/query is the credential for every provider here
}

// settingsPayload is the shared GET/PUT response shape for /api/settings.
func (s *Server) settingsPayload() map[string]interface{} {
	scope := s.db.GetSetting("alert_scope")
	if scope == "" {
		scope = "all"
	}
	filter := []string{}
	if f := s.db.GetSetting("alert_filter"); f != "" {
		_ = json.Unmarshal([]byte(f), &filter)
	}
	if filter == nil {
		filter = []string{}
	}
	realert := 30
	if v := s.db.GetSetting("realert_min"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 1440 {
			realert = n
		}
	}
	// Legacy single-webhook fields stay for backward compat with older
	// dashboards (and the env-configured Google Chat URL, which has no
	// settings row). The multi-provider "providers" array is the real data.
	chatURL := s.db.GetSetting("google_chat_url")
	chatSource := "none"
	if chatURL != "" {
		chatSource = "dashboard"
	} else if os.Getenv("GOOGLE_CHAT_WEBHOOK_URL") != "" {
		chatURL = os.Getenv("GOOGLE_CHAT_WEBHOOK_URL")
		chatSource = "env"
	}
	return map[string]interface{}{
		"webhook_url":        webhookMasked(chatURL),
		"webhook_configured": chatURL != "",
		"source":             chatSource,
		"providers":          s.probeWorker.providerStatuses(),
		"alert_scope":        scope,
		"alert_filter":       filter,
		"realert_min":        realert,
		"maintenance_mode":   s.db.GetSetting("maintenance_mode") == "1",
		"tls":                s.tlsPayload(),
	}
}

func (s *Server) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	respondWithJSON(w, http.StatusOK, s.settingsPayload())
}

func (s *Server) handleSettingsPut(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		WebhookURL *string `json:"webhook_url"` // legacy alias for the google_chat URL
		Providers  []struct {
			Kind    string            `json:"kind"`
			URL     *string           `json:"url"`     // nil = keep existing; "" = clear; full URL = set
			Enabled *bool             `json:"enabled"` // nil = keep; else set
			Extra   map[string]string `json:"extra"`   // non-URL fields (e.g. telegram chat_id)
		} `json:"providers"`
		AlertScope  *string   `json:"alert_scope"`  // nil = keep; else all|tags|sensors
		AlertFilter *[]string `json:"alert_filter"` // nil = keep; else set
		RealertMin  *int      `json:"realert_min"`  // nil = keep; 0 = alert once only
		MaintMode   *bool     `json:"maintenance_mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		code, msg := requestBodyErr(err)
		respondWithError(w, code, msg)
		return
	}

	// Validate EVERYTHING before any write: the old code applied provider
	// writes as it went and reset alert_scope/alert_filter unconditionally
	// (a partial save like {"realert_min":10} silently wiped the tag
	// routing), and one bad field could leave a partial save behind. Now a
	// 400 leaves the store exactly as it was.
	if req.AlertScope != nil && *req.AlertScope != "all" && *req.AlertScope != "tags" && *req.AlertScope != "sensors" {
		respondWithError(w, http.StatusBadRequest, "alert_scope must be all, tags or sensors")
		return
	}
	if req.RealertMin != nil && (*req.RealertMin < 0 || *req.RealertMin > 1440) {
		respondWithError(w, http.StatusBadRequest, "realert_min must be 0-1440 (0 = alert once only)")
		return
	}
	// alert_filter items are tag names (scope=tags) or sensor ids
	// (scope=sensors): bound and validate them like every other field in
	// this handler. The 1 MiB body cap alone would let a caller store a
	// near-1 MiB blob (thousands of unbounded strings) that GET
	// /api/settings and every alert decision (shouldAlert) unmarshal on
	// each read, and unvalidated strings in the store are a standing
	// stored-XSS risk for any future render site. The UI only ever selects
	// existing tags/ids — both validSensorName-clean (tags through
	// cleanTags, ids are 36-char UUIDs) — so this never rejects a
	// dashboard save. Trimmed, deduped, and capped like cleanTags; an
	// invalid entry 400s the whole save (validate-everything-first).
	if req.AlertFilter != nil {
		if len(*req.AlertFilter) > 500 {
			respondWithError(w, http.StatusBadRequest, "alert_filter cannot exceed 500 entries")
			return
		}
		cleaned := make([]string, 0, len(*req.AlertFilter))
		seen := make(map[string]bool, len(*req.AlertFilter))
		for _, item := range *req.AlertFilter {
			item = strings.TrimSpace(item)
			if item == "" || utf8.RuneCountInString(item) > 60 || !validSensorName(item) {
				respondWithError(w, http.StatusBadRequest, "invalid entry in alert_filter")
				return
			}
			if !seen[item] {
				seen[item] = true
				cleaned = append(cleaned, item)
			}
		}
		req.AlertFilter = &cleaned
	}
	// One stored-state snapshot per provider, taken BEFORE the tx and
	// reused by the apply pass below, so validation and apply evaluate the
	// same effective state and the two paths can't drift. (A concurrent
	// settings PUT can interleave between the snapshot and the tx — the
	// same read-then-write window the rest of this handler has.)
	storedExtras := make([]map[string]string, len(req.Providers))
	for i, prov := range req.Providers {
		storedExtras[i] = s.storedProviderExtra(prov.Kind)
		if err := validateProviderUpdate(prov.Kind, prov.URL, prov.Enabled, prov.Extra, storedExtras[i]); err != nil {
			respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.WebhookURL != nil {
		if err := validateProviderUpdate("google_chat", req.WebhookURL, nil, nil, nil); err != nil {
			respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	// Maintenance-mode entry validation runs BEFORE the settings tx opens
	// "no active sensors to pause" is a derived
	// check, and a 400 must leave the store exactly as it was — the old
	// order committed the other settings first, then 400'd on the empty
	// snapshot. The snapshot ids computed here are reused by the apply
	// phase (nothing mutates the sensors table in between).
	//
	// Re-enable (mode already ON) takes NO new snapshot: the snapshot belongs to the original off→on transition. A fresh
	// snapshot would capture the currently-ACTIVE set, which excludes any
	// sensor the operator resumed during maintenance — and those sensors
	// would be left paused forever, because resume restores only the
	// snapshot.
	maintAlreadyOn := s.db.GetSetting("maintenance_mode") == "1"
	var maintIDs []string
	if req.MaintMode != nil && *req.MaintMode && !maintAlreadyOn {
		ids, err := s.db.ActiveSensorIDs()
		if err != nil {
			respondInternal(w, "snapshot active sensors", err)
			return
		}
		if len(ids) == 0 {
			respondWithError(w, http.StatusBadRequest, "no active sensors to pause")
			return
		}
		maintIDs = ids
	}

	// All valid: apply. Provider writes first (the dashboard saves them
	// alongside the routing fields), then ONLY the routing fields that were
	// sent — nil means keep, so a partial save no longer resets routing.
	// The whole apply phase is ONE transaction: validation can't rule out a
	// mid-sequence write failure (disk full, SQLITE_BUSY), and the old
	// autocommit writes left a partial save behind a 500. Maintenance mode below stays outside — it has its own atomic
	// snapshot transaction (SetMaintenanceMode).
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondInternal(w, "begin settings update", err)
		return
	}
	defer tx.Rollback() // no-op after Commit succeeds
	// Pin the write lock BEFORE anything reads (review 2026-10-24): a
	// SQLite deferred transaction takes a read snapshot on its first
	// SELECT (the smtp tls_mode guard below), and upgrading that to a
	// write AFTER another writer committed fails fast with
	// SQLITE_BUSY_SNAPSHOT (517) — busy_timeout does not retry it. That
	// turned a normal concurrent-PUT collision into a spurious 500 and
	// made the guard's read see a snapshot that can go stale. A zero-row
	// UPDATE acquires the write lock immediately (busy_timeout applies
	// to the ACQUIRE), so the two PUTs serialize and the guard reads the
	// committed state — wait-then-400 instead of 500.
	if _, err := tx.ExecContext(r.Context(), "UPDATE settings SET value = value WHERE setting_key = ?", "\x00pulsemon-txlock"); err != nil {
		respondInternal(w, "lock settings", err)
		return
	}
	for i, prov := range req.Providers {
		if err := applyProviderUpdateInTx(tx, prov.Kind, prov.URL, prov.Enabled, prov.Extra, storedExtras[i]); err != nil {
			if errors.Is(err, errSMTPNoneWithCreds) {
				// Reachable now (in-tx re-check): a concurrent admin PUT
				// committed between this request's pre-flight validation
				// and its write tx, so the EFFECTIVE state this save would
				// complete violates the rule. 400; deferred rollback leaves
				// the store untouched.
				respondWithError(w, http.StatusBadRequest, err.Error())
				return
			}
			// Other validation errors stay unreachable after the pass
			// above; a 500 covers write failures.
			respondInternal(w, "apply provider "+prov.Kind, err)
			return
		}
	}
	if req.WebhookURL != nil {
		if err := applyProviderUpdateInTx(tx, "google_chat", req.WebhookURL, nil, nil, nil); err != nil {
			respondInternal(w, "apply provider google_chat", err)
			return
		}
	}
	if req.RealertMin != nil {
		if err := setSettingInTx(tx, "realert_min", strconv.Itoa(*req.RealertMin)); err != nil {
			respondInternal(w, "save setting realert_min", err)
			return
		}
	}
	if req.AlertScope != nil {
		if err := setSettingInTx(tx, "alert_scope", *req.AlertScope); err != nil {
			respondInternal(w, "save setting alert_scope", err)
			return
		}
	}
	if req.AlertFilter != nil {
		filterJSON, _ := json.Marshal(*req.AlertFilter)
		if err := setSettingInTx(tx, "alert_filter", string(filterJSON)); err != nil {
			respondInternal(w, "save setting alert_filter", err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		respondInternal(w, "commit settings update", err)
		return
	}
	if req.MaintMode != nil {
		if *req.MaintMode {
			if maintAlreadyOn {
				// Already in maintenance: keep the ORIGINAL snapshot and
				// the existing pause set — re-snapshotting would drop
				// sensors resumed during maintenance from the restore set
				// Nothing to write.
				log.Printf("API: maintenance mode already ON (snapshot preserved)")
			} else {
				// Entering maintenance (off→on): the snapshot is read
				// INSIDE the pause transaction (review nit 2026-10-24) —
				// the read above is only the 400 pre-check; a sensor
				// activated between that read and this transaction used to
				// escape the pause and keep probing under mode=ON.
				//
				// Atomic: pause + snapshot + mode flag in ONE transaction
				// so a crash can't leave sensors paused without the mode
				// flag (or vice versa). See EnterMaintenanceWithFreshSnapshot in db.go.
				ids, err := s.db.EnterMaintenanceWithFreshSnapshot()
				if err != nil {
					respondInternal(w, "enter maintenance mode", err)
					return
				}
				maintIDs = ids
				// Flip the in-memory pause flag immediately — the same
				// SetPaused fast path the single-sensor PATCH uses. Without
				// this the sensor loops keep probing until the next 5s
				// syncSensors tick, landing up to one extra probe row (and
				// a possible transition event) per sensor after maintenance
				// is already ON. Alerts are already blocked in that window
				// — alertGates re-reads the maintenance_mode flag from the
				// DB on every decision — so this closes the probing half of
				// the "paused = no packets, no rows, no alerts" contract
				// (probe.go sensorLoop).
				for _, id := range maintIDs {
					s.probeWorker.SetPaused(id, true)
				}
				// Paused sensors don't probe, so their alert state can't
				// drift; reset it now so resume doesn't instantly re-alert
				// on a stale bad state.
				s.probeWorker.ResetAlertStates()
				log.Printf("API: maintenance mode ON (%d sensors paused)", len(maintIDs))
			}
		} else {
			// Leaving maintenance: reactivate exactly the sensors that were
			// active when maintenance started (the snapshot). Sensors paused
			// BEFORE maintenance (not in the snapshot), or added during
			// maintenance, stay paused. A snapshot sensor the user paused
			// DURING maintenance is resumed with the rest — the snapshot is
			// the restore set, and SetMaintenanceMode resumes it wholesale.
			// Then clear the snapshot and reset alert timers so a still-bad
			// sensor doesn't instantly re-alert on the next tick.
			snap := s.db.GetSetting("maintenance_active_ids")
			var ids []string
			if snap != "" {
				if err := json.Unmarshal([]byte(snap), &ids); err != nil {
					ids = nil
				}
			}
			// Atomic: resume + clear snapshot + mode flag in ONE transaction.
			// See SetMaintenanceMode in db.go.
			if err := s.db.SetMaintenanceMode(false, ids, ""); err != nil {
				respondInternal(w, "leave maintenance mode", err)
				return
			}
			// Flip the in-memory unpause immediately (symmetric fast path, see
			// the enable side above): without this the resumed sensors wait up
			// to 5s for syncSensors before their next probe.
			for _, id := range ids {
				s.probeWorker.SetPaused(id, false)
			}
			s.probeWorker.ResetAlertStates()
			log.Printf("API: maintenance mode off (%d sensors resumed)", len(ids))
		}
	}
	realertLog := 30
	if v := s.db.GetSetting("realert_min"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			realertLog = n
		}
	}
	// Log the EFFECTIVE stored values (the request fields are pointers now:
	// a partial save leaves the others untouched).
	scopeLog := s.db.GetSetting("alert_scope")
	filterLog := 0
	if v := s.db.GetSetting("alert_filter"); v != "" {
		var fl []string
		if json.Unmarshal([]byte(v), &fl) == nil {
			filterLog = len(fl)
		}
	}
	log.Printf("API: settings updated (scope=%s filter=%d realert=%dm)", scopeLog, filterLog, realertLog)
	respondWithJSON(w, http.StatusOK, s.settingsPayload())
}

// validateProviderUpdate checks one provider update WITHOUT writing
// anything. handleSettingsPut runs it over the whole request BEFORE any
// write, so a 400 never leaves a partial save; applyProviderUpdate reuses
// it so the two paths can't drift. storedExtra carries the provider's
// currently-stored extra values (nil = none) so field-combining checks
// evaluate the EFFECTIVE state (incoming value if sent, else stored) —
// see the tls_mode=none guard. The withDNS variants split the URL checks:
// the in-transaction save path must not run the 5s DNS lookup under the
// SQLite write lock.
func validateProviderUpdate(kind string, url *string, enabled *bool, extra, storedExtra map[string]string) error {
	return validateProviderUpdateInternal(kind, url, enabled, extra, storedExtra, true)
}

// validateProviderUpdateNoDNS is the format-only twin for the
// in-transaction save path (see N6 above). DNS reachability is already
// enforced by the pre-transaction pass in handleSettingsPut, so a URL that
// cannot be resolved is rejected before the write begins.
func validateProviderUpdateNoDNS(kind string, url *string, enabled *bool, extra, storedExtra map[string]string) error {
	return validateProviderUpdateInternal(kind, url, enabled, extra, storedExtra, false)
}

func validateProviderUpdateInternal(kind string, url *string, enabled *bool, extra, storedExtra map[string]string, withDNS bool) error {
	if _, ok := providerByKey(kind); !ok {
		return fmt.Errorf("unknown alert provider: %q", kind)
	}
	if url != nil {
		u := strings.TrimSpace(*url)
		if u != "" && kind != "smtp" {
			// SMTP's url field carries the mail-server host (a hostname),
			// not an http(s):// webhook — it is validated against the
			// reserved range blocklist just below (validateSMTPHost), not
			// as a URL.
			var err error
			if withDNS {
				err = validateWebhookURL(u)
			} else {
				_, _, err = validateWebhookURLNoDNS(u)
			}
			if err != nil {
				return fmt.Errorf("%s url: %s", kind, err.Error())
			}
		}
		if kind == "smtp" && u != "" {
			// The host is validated against the reserved-range blocklist
			// (the same check the webhook path applies) before it is
			// stored, so the SMTP transport can never be pointed at
			// loopback, cloud-metadata (169.254.169.254), or other
			// reserved space.
			var err error
			if withDNS {
				err = validateSMTPHost(u)
			} else {
				err = validateSMTPHostNoDNS(u)
			}
			if err != nil {
				return fmt.Errorf("smtp host: %s", err.Error())
			}
		}
	}
	// Non-URL fields (e.g. telegram chat_id): only known keys are accepted,
	// so a client can't write arbitrary settings keys.
	for k, v := range extra {
		if !extraFields[kind][k] {
			return fmt.Errorf("unknown field %q for %s", k, kind)
		}
		vv := strings.TrimSpace(v)
		if kind == "smtp" && k == "port" && vv != "" {
			if _, err := smtpPort(vv); err != nil {
				return fmt.Errorf("smtp %s: %s", k, err.Error())
			}
		}
		if kind == "smtp" && k == "tls_mode" && vv != "" {
			switch vv {
			case "auto", "starttls", "tls", "none":
			default:
				return fmt.Errorf("smtp tls_mode: %q (valid: auto, starttls, tls, none)", vv)
			}
		}
		if kind == "smtp" && (k == "from" || k == "to") {
			// Single RFC 5322 address, no CR/LF (the raw message headers
			// are built by concatenation in sendSMTP). Store the BARE
			// address: net/smtp wraps MAIL/RCPT arguments in <...>, so a
			// display name or a recipient list would 501 at send time.
			if _, err := smtpAddr(vv); err != nil {
				return fmt.Errorf("smtp %s: %s", k, err.Error())
			}
		}
	}
	// tls_mode=none cannot carry credentials: with
	// no TLS the AUTH exchange would ride the wire in plaintext — the
	// transport fails clearly at send time, so the SAVE must fail clearly
	// too, not store a config that can only ever fail per-alert. (The UI's
	// "••••••••" mask counts as a present password: clearing the field is
	// the deliberate act that makes tls_mode=none valid.)
	//
	// The check runs on the EFFECTIVE state, not just the incoming map
	// omitted extra keys keep their stored
	// values (applyProviderUpdateInTx only persists what was sent), so a
	// partial PUT {"tls_mode":"none"} over stored credentials must fail
	// here, not slip through and leave a plaintext-mode config behind.
	if kind == "smtp" {
		eff := func(k string) string {
			if v, ok := extra[k]; ok {
				return strings.TrimSpace(v)
			}
			return strings.TrimSpace(storedExtra[k])
		}
		// Credential PRESENCE is judged on the RAW value (F10):
		// credentials are stored untrimmed, so a spaces-only password is
		// still a credential and must block tls_mode=none. (eff stays
		// trimmed — it also reads tls_mode, which is format-validated in
		// trimmed form.)
		cred := func(k string) string {
			if v, ok := extra[k]; ok {
				return v
			}
			return storedExtra[k]
		}
		if eff("tls_mode") == "none" && (cred("username") != "" || cred("password") != "") {
			return errSMTPNoneWithCreds
		}
	}
	return nil
}

// storedProviderExtra returns the provider's currently-stored extra values
// (only keys in extraFields[kind]), so validation can evaluate the
// effective state of partial updates. Unknown kinds return nil.
func (s *Server) storedProviderExtra(kind string) map[string]string {
	keys, ok := extraFields[kind]
	if !ok {
		return nil
	}
	m := make(map[string]string, len(keys))
	for k := range keys {
		m[k] = s.db.GetSetting(kind + "_" + k)
	}
	return m
}

// errSMTPNoneWithCreds: the tls_mode=none-with-credentials rejection. A
// sentinel (not an inline error) so the settings PUT can map it to 400
// even when it surfaces from the IN-TX re-check.
var errSMTPNoneWithCreds = errors.New("smtp tls_mode=none cannot use credentials (clear username/password)")

// guardSMTPNoCredsOverTLSInTx re-applies the tls_mode=none + credentials
// rule against the LIVE in-tx settings snapshot (review 2026-10-24, found
// independently by two review streams): the handler's pre-flight guard
// evaluated the EFFECTIVE state against a PRE-BeginTx read, so two
// concurrent admin PUTs — one setting tls_mode=none, one storing
// credentials — each passed against the pre-other-commit snapshot and
// JOINTLY committed none+credentials (the runtime send guard still
// refuses to send, so the failure is broken config, not a plaintext
// leak). SQLite serializes write transactions, so the later committer's
// in-tx read sees the earlier write and takes the 400 with the store
// untouched. Mask semantics mirror the write path below: a masked
// incoming password means "keep stored", i.e. credential PRESENT.
func guardSMTPNoCredsOverTLSInTx(tx *sql.Tx, incoming map[string]string) error {
	stored := func(k string) string {
		var v string
		_ = tx.QueryRow("SELECT value FROM settings WHERE setting_key = ?", "smtp_"+k).Scan(&v)
		return v
	}
	effTLS := strings.TrimSpace(incoming["tls_mode"])
	if _, ok := incoming["tls_mode"]; !ok {
		effTLS = strings.TrimSpace(stored("tls_mode"))
	}
	if effTLS != "none" {
		return nil
	}
	credPresent := func(k string) bool {
		if v, ok := incoming[k]; ok {
			if k == "password" && v == "••••••••" { // mask = keep stored
				return stored("password") != ""
			}
			return v != ""
		}
		return stored(k) != ""
	}
	if credPresent("username") || credPresent("password") {
		return errSMTPNoneWithCreds
	}
	return nil
}

// applyProviderUpdate persists one provider's URL / enabled flag in its own
// transaction — the standalone entry point the provider tests drive
// (smtp_test.go, telegram_settings_test.go). handleSettingsPut uses
// applyProviderUpdateInTx directly so every provider and the routing field
// commit atomically. URL is a pointer so nil = "don't touch this field" (the
// dashboard only sends what changed); an empty string clears; a non-empty
// value is validated first. This is the single write path for provider
// config, so the validation and key-naming stay consistent no matter how
// many providers exist.
func (s *Server) applyProviderUpdate(kind string, url *string, enabled *bool, extra map[string]string) error {
	// Standalone (non-HTTP) entry point — no request context to thread, so
	// the plain Begin() stays (the HTTP save path uses BeginTx in
	// handleSettingsPut).
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Standalone entry point: read the stored snapshot fresh (there is no
	// pre-tx validation pass to share one with).
	if err := applyProviderUpdateInTx(tx, kind, url, enabled, extra, s.storedProviderExtra(kind)); err != nil {
		return err
	}
	return tx.Commit()
}

// applyProviderUpdateInTx is applyProviderUpdate's body, writing through the
// caller's transaction so handleSettingsPut can apply every provider and
// routing field atomically (mirrors db.SetSensorTags).
func applyProviderUpdateInTx(tx *sql.Tx, kind string, url *string, enabled *bool, extra, storedExtra map[string]string) error {
	// Format-only validation: the DNS reachability
	// check runs in the PRE-transaction pass (handleSettingsPut →
	// validateProviderUpdate with DNS), never under the write lock.
	if err := validateProviderUpdateNoDNS(kind, url, enabled, extra, storedExtra); err != nil {
		return err
	}
	if kind == "smtp" {
		// In-tx effective-state re-check (TOCTOU, review 2026-10-24): the
		// handler's guard ran on a pre-BeginTx snapshot; this one sees the
		// serialized write state, so two racing admin PUTs can no longer
		// jointly commit tls_mode=none over credentials.
		if err := guardSMTPNoCredsOverTLSInTx(tx, extra); err != nil {
			return err
		}
	}
	if url != nil {
		u := strings.TrimSpace(*url)
		if kind == "smtp" {
			// Persist the host under smtp_host (not smtp_url) so the SMTP
			// transport reads it from the right key.
			if err := setSettingInTx(tx, "smtp_host", u); err != nil {
				return fmt.Errorf("failed to save smtp host: %s", err.Error())
			}
		} else {
			if err := setSettingInTx(tx, kind+"_url", u); err != nil {
				return fmt.Errorf("failed to save %s url: %s", kind, err.Error())
			}
		}
	}
	if enabled != nil {
		val := "0"
		if *enabled {
			val = "1"
		}
		if err := setSettingInTx(tx, kind+"_enabled", val); err != nil {
			return fmt.Errorf("failed to save %s enable flag: %s", kind, err.Error())
		}
	}
	// Non-URL fields (e.g. telegram chat_id): validated above; the loop
	// persists the accepted keys.
	for k, v := range extra {
		// Credentials (username/password) are stored RAW, not trimmed
		// a leading/trailing space in
		// an SMTP credential is part of the value, and trimming it would
		// silently change the AUTH exchange. Every other extra field
		// keeps the trim.
		vv := v
		if k != "username" && k != "password" {
			vv = strings.TrimSpace(v)
		}
		// SMTP password: the mask value means "unchanged" (the UI returns
		// the fixed mask for a stored password). Skip the write so we never
		// clobber the real credential with the mask string. Compared on the
		// RAW value — the exact mask is the token; a masked value with
		// surrounding spaces is a (weird) literal password, not the mask.
		if kind == "smtp" && k == "password" && v == "••••••••" {
			continue
		}
		if kind == "smtp" && (k == "from" || k == "to") {
			// Store the BARE address (validated above): a display name or
			// list would 501 at send time (see smtpAddr).
			if addr, err := smtpAddr(vv); err == nil {
				vv = addr
			}
		}
		if err := setSettingInTx(tx, kind+"_"+k, vv); err != nil {
			return fmt.Errorf("failed to save %s %s: %s", kind, k, err.Error())
		}
	}
	return nil
}

// extraFields maps a provider kind to the non-URL settings keys it accepts.
// chat_id is free-form (a numeric user/group ID or an @channel name); no URL
// validation applies.
//
// The SMTP host is deliberately NOT an extra field: it travels in the url
// field, where validateSMTPHost enforces the reserved-range blocklist before
// it is stored. The extra loop below persists its keys without host
// validation, so accepting "host" here let a client write smtp_host — e.g.
// 127.0.0.1 or 169.254.169.254 — straight to SQLite, bypassing the check.
var extraFields = map[string]map[string]bool{
	"telegram": {"chat_id": true},
	"smtp": {"port": true, "from": true, "to": true,
		"username": true, "password": true, "tls_mode": true},
}

func (s *Server) handleSettingsTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Body: {"kind":"google_chat"|"discord"}. The dashboard tests the provider
	// whose URL is being verified, so kind is required — and must be a known
	// provider. An unknown/missing kind is a 400 naming the valid kinds, so
	// the endpoint is self-documenting instead of answering 200 {"ok":false,
	// "detail":"unknown provider"}. (A known kind with no URL still gets a
	// 200 {"ok":false} — that is "the test ran, nothing configured", which
	// the UI displays as a hint, not an error.)
	var req struct {
		Kind string `json:"kind"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		code, msg := requestBodyErr(err)
		respondWithError(w, code, msg)
		return
	}
	if _, ok := providerByKey(strings.TrimSpace(req.Kind)); !ok {
		var valid []string
		for _, p := range providerList {
			valid = append(valid, p.Kind)
		}
		respondWithError(w, http.StatusBadRequest,
			fmt.Sprintf("unknown alert provider %q (valid: %s)", req.Kind, strings.Join(valid, ", ")))
		return
	}
	ok, detail := s.probeWorker.TestWebhook(r.Context(), req.Kind)
	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"ok":     ok,
		"detail": detail,
	})
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/" {
		path = "/index.html"
	}
	path = strings.TrimPrefix(path, "/")

	data, err := content.ReadFile("web/" + path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// Every asset revalidates (no-cache) against a strong ETag, so an update
	// is never served stale and an unchanged asset costs a 304 with no body.
	// The hash behind that ETag is MEMOIZED per path for the process life
	// (static_etag.go, v0.3.17): the one-time sha256 of the ~110KB
	// index.html measures ~54µs, paid once, not per request). The remaining per-request
	// cost is the in-memory embed copy (~6.5µs), which the 200 path needs
	// for the body; skipping it on 304 was measured not worth the extra
	// code path.
	tag := staticETag(path, data)
	w.Header().Set("ETag", tag)
	w.Header().Set("Cache-Control", "no-cache")
	switch {
	case strings.HasSuffix(path, ".html"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
	case strings.HasSuffix(path, ".js"):
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case strings.HasSuffix(path, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(path, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	case strings.HasSuffix(path, ".png"):
		w.Header().Set("Content-Type", "image/png")
	case strings.HasSuffix(path, ".woff2"):
		w.Header().Set("Content-Type", "font/woff2")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	if inm := r.Header.Get("If-None-Match"); inm != "" && etagMatches(inm, tag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(data)
}

// normalizeProbeType maps any incoming probe type to the canonical set:
// "http" (case-insensitive) or "icmp" (the default for empty/unknown values,
// so old dashboards that omit the field keep creating ICMP sensors).
func normalizeProbeType(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "http":
		return "http"
	default:
		return "icmp"
	}
}
