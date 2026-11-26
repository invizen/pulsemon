package main

import (
	"embed"
	"log"
	"net/http"
	"os"
	"pulsemon/internal/store"
	"strings"
	"sync"
	"time"
)

// The embed is an EXPLICIT list, not `web/*`: the wildcard pulled
// web/test/*.mjs (the frontend test harness) into the release binary,
// where handleStatic served it at /test/... — the app's test files
// shipped on every dashboard. web/vendor is intentional (fonts + icon
// CSS; the .woff2 Content-Type case in handleStatic exists for it).
// History: docs/DECISIONS.md → embed-explicit-list.
//
//go:embed web/index.html web/app.js web/styles.css web/theme.js web/favicon.svg web/favicon-16x16.png web/favicon-32x32.png web/favicon-48x48.png web/apple-touch-icon.png web/vendor
var content embed.FS

type APIError struct {
	Error string `json:"error"`
}

type Server struct {
	db          *store.Store
	probeWorker *ProbeWorker
	mux         *http.ServeMux
	auth        *AuthState
	// allowedHosts is the parsed PULSEMON_ALLOWED_HOSTS list (lower-cased
	// host or host:port entries). Empty = no Host check (LAN-trust default).
	// Enforced only on the setup-mode bootstrap POST — see authGate.
	allowedHosts []string
	// tlsCert memoizes the parsed cert for tlsPayload;
	// see tlsCertCached in tls_settings.go.
	tlsCert tlsCertMemo
	// sensorCountCache memoizes the healthz sensor count for a short window
	// so frequent unauthenticated health checks don't do a DB COUNT per hit.
	sensorCountMu    sync.Mutex
	sensorCountCache int
	sensorCountAt    time.Time
}

func NewServer(db *store.Store, pw *ProbeWorker) *Server {
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

func (s *Server) Mux() *http.ServeMux {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/healthz", s.handleHealthz)
	// Authorization rule for the whole API surface:
	// EVERY /api/ route carries an explicit session wrapper — requireAuth
	// for the authed-user surface, requireAdmin for the admin surface —
	// except the four public endpoints (healthz, auth/status, auth/login,
	// auth/logout) that must be reachable sessionless by definition. The
	// gate (authGate) enforces sessions on /api/ as well, so the wrappers
	// are defense-in-depth, not the primary line: a handler must never
	// depend on the gate having run to be safe on its own (the
	// sessionFrom contract). api_routes_auth_test.go audits this rule at
	// the source level.
	// GET /api/update-check is requireAuth, NOT requireAdmin: the result is
	// read-only, its response (running/latest versions) is
	// non-secret — rendered in the header pill for every user — it hits
	// a fixed upstream URL (no SSRF), and ?refresh=1 is throttled to
	// one outbound fetch per 60s globally. A viewer (or any LAN host on
	// an auth-off install, where requireAdmin stands down anyway) can at
	// most degrade the version readout for ≤1h. The admin gate belongs
	// on POST /api/update, where the action is downloading + executing
	// new code. docs/DECISIONS.md → update-check-refresh-throttle.
	s.mux.HandleFunc("GET /api/update-check", s.requireAuth(s.handleUpdateCheck))
	s.mux.HandleFunc("POST /api/update", s.requireAdmin(s.handleUpdate))
	// Sensor routes: reads and Pulse Now are open to EVERY authenticated
	// session (non-admins are viewers + manual-pulse operators); every
	// sensor MUTATION — create, edit (incl. pause/resume + target
	// repoint), delete, clone, per-sensor history wipe — is admin-only
	// (a lower-trust account must not administer
	// sensors or erase per-sensor events rows, which the requireAdmin-
	// gated DELETE /api/events exists to protect). The GET/ping routes are
	// wrapped in requireAuth explicitly (rule above), not left to the gate.
	// requireAuth/requireAdmin stand down with the auth gate, so the
	// "auth off = fully open" contract is unchanged.
	s.mux.HandleFunc("GET /api/sensors", s.requireAuth(s.handleSensors))
	s.mux.HandleFunc("POST /api/sensors", s.requireAdmin(s.handleSensors))
	s.mux.HandleFunc("GET /api/sensors/{id}", s.requireAuth(s.handleSensorByID))
	s.mux.HandleFunc("PATCH /api/sensors/{id}", s.requireAdmin(s.handleSensorByID))
	s.mux.HandleFunc("DELETE /api/sensors/{id}", s.requireAdmin(s.handleSensorByID))
	s.mux.HandleFunc("POST /api/sensors/{id}/ping", s.requireAuth(s.handleSensorPing))
	s.mux.HandleFunc("POST /api/sensors/{id}/clone", s.requireAdmin(s.handleSensorClone))
	s.mux.HandleFunc("GET /api/sensors/{id}/history", s.requireAuth(s.handleSensorHistory))
	s.mux.HandleFunc("GET /api/sensors/{id}/graph", s.requireAuth(s.handleSensorGraph))
	s.mux.HandleFunc("DELETE /api/sensors/{id}/history", s.requireAdmin(s.handleSensorClearHistory))
	s.mux.HandleFunc("DELETE /api/history", s.requireAdmin(s.handleClearAllHistory))
	// /api/tags and /api/events intentionally use BARE (method-less)
	// patterns: the `/` catch-all below (handleStatic) matches EVERY
	// method, so method-prefixed patterns would NOT earn ServeMux's
	// canonical 405 + Allow — the catch-all wins and returns an HTML
	// 404, regressing the handler's JSON 405. The handler switches on
	// r.Method; that is the correct form under this architecture. Do
	// not "fix" to method-prefixed (docs/DECISIONS.md → bare-routes).
	// requireAuth per the rule above (the pattern these GET branches were
	// written for): the GET branches of handleTags/handleEvents carry no
	// session check of their own, so their authorization must not rest on
	// authGate having run (the sessionFrom contract — "a route registered
	// without the gate, or a future gate change, must not silently widen
	// authorization"). The inline admin check in each DELETE branch is
	// unchanged; requireAuth only adds the session requirement the GET
	// branch was missing. The routes stay BARE (the 405 annotation above).
	s.mux.HandleFunc("/api/tags", s.requireAuth(s.handleTags))
	s.mux.HandleFunc("/api/events", s.requireAuth(s.handleEvents))
	// Settings READS are admin-only too: the payload carries operator
	// PII and infrastructure metadata (smtp_from/to/username,
	// telegram_chat_id, webhook scheme+host, TLS cert metadata) that a
	// lower-trust viewer account must not see — the same privilege
	// boundary GET /api/auth/users enforces on the roster. The UI
	// already hides the settings modal from non-admins, so nothing
	// consumes this for them. requireAdmin stands down with the auth
	// gate, so the "auth off = fully open" contract is unchanged.
	s.mux.HandleFunc("GET /api/settings", s.requireAdmin(s.handleSettingsGet))
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
	s.mux.HandleFunc("DELETE /api/auth/users/{username}", s.requireAdmin(s.handleAuthUserDelete))
	s.mux.HandleFunc("POST /api/auth/disable", s.requireAdmin(s.handleAuthDisable))
	s.mux.HandleFunc("/", s.handleStatic)
}

// handleHealthz is a real check: DB must be reachable (SPEC §8, fix #5).
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	// The sensor count is a liveness signal, not a precise gauge: cache it for
	// ~2s so frequent unauthenticated health checks don't do a DB COUNT per hit.
	// A DB that goes down is detected on the next (uncached) query, up to 2s
	// later.
	n, err := s.cachedSensorCount(r.Context())
	if err != nil {
		// 503, not 500: the API process is healthy, the DB is down. Keep
		// the "db unreachable" wording (operators and health checks read
		// it) and log the driver detail instead of leaking it.
		log.Printf("API: healthz db check: %v", err)
		respondWithError(w, http.StatusServiceUnavailable, "db unreachable")
		return
	}
	hz := map[string]any{
		"status":  "ok",
		"sensors": n,
		"probing": s.probeWorker.ActiveCount(),
		"time":    time.Now().UTC().Format(time.RFC3339),
	}
	// The exact version is a targeting signal for known bugs: reveal it only to
	// an authenticated session, not to any unauthenticated LAN host polling
	// /api/healthz. When auth is disabled there is no session to check (and the
	// whole dashboard is open to the LAN anyway), so reveal it — otherwise the
	// dashboard's version pill is blank on auth-disabled installs.
	if !s.auth.Enabled() {
		hz["version"] = Version
	} else if _, ok := s.sessionCookieFrom(r); ok {
		hz["version"] = Version
	}
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

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
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
	// index.html measures ~54µs, paid once, not per request. The remaining
	// per-request cost is the in-memory embed copy (~6.5µs). DO NOT add a
	// pre-read ETag fast path to skip that copy on 304: the dashboard
	// revalidates every ~5s, so the copy is a
	// young-gen ~110KB alloc — ~1.8 GB/day of short-lived garbage the GC
	// reclaims for ~112 ms/day of CPU (0.00013% of a core) — and the 200
	// path needs the read for the body anyway, so a separate
	// lookup+branch buys nothing measurable. Measured not worth the extra
	// code path (v0.3.17).
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
// "http", "tcp" (both case-insensitive), or "icmp" (the default for
// empty/unknown values, so old dashboards that omit the field keep
// creating ICMP sensors).
