package main

import (
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

//go:embed web/*
var content embed.FS

// maxRequestBytes bounds every incoming request body (authGate wraps
// r.Body with http.MaxBytesReader). The largest real payload — a TLS
// cert+key upload — is ~16 KB; sensor/user/settings payloads are bytes.
// Anything past 1 MiB is either a bug or a DoS attempt.
const maxRequestBytes = 1 << 20

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
	SpikeMult int      `json:"spike_mult"`
	State     string   `json:"state"`  // active | paused
	Status    string   `json:"status"` // up | warning | error
	CreatedAt string   `json:"created_at"`
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
}

func NewServer(db *DB, pw *ProbeWorker) *Server {
	s := &Server{
		db:          db,
		probeWorker: pw,
		mux:         http.NewServeMux(),
		auth:        NewAuthState(db),
	}
	s.routes()
	return s
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
// Every request body is additionally bounded to maxRequestBytes via
// http.MaxBytesReader: a malformed or malicious client can no longer stream
// an arbitrarily large body into the JSON decoders (sensors, users, TLS
// upload, settings). The largest real payload — a TLS cert+key upload — fits
// in ~16 KB, so 1 MiB is generous. Oversized bodies surface as a clean 413
// instead of a generic decode error.
func (s *Server) authGate() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
		}
		if !s.auth.Enabled() || r.URL.Path == "/api/healthz" {
			s.mux.ServeHTTP(w, r)
			return
		}
		if c, err := r.Cookie(authSessionName); err == nil && s.auth.ValidSession(c.Value) {
			s.mux.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			// The login/status endpoints must be reachable WITHOUT a
			// session — the UI's gate calls them to decide whether to
			// show the login form.
			if r.URL.Path == "/api/auth/login" || r.URL.Path == "/api/auth/status" || r.URL.Path == "/api/auth/logout" {
				s.mux.ServeHTTP(w, r)
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
	s.mux.HandleFunc("/api/sensors", s.handleSensors)
	s.mux.HandleFunc("/api/sensors/{id}", s.handleSensorByID)
	s.mux.HandleFunc("POST /api/sensors/{id}/ping", s.handleSensorPing)
	s.mux.HandleFunc("POST /api/sensors/{id}/clone", s.handleSensorClone)
	s.mux.HandleFunc("GET /api/sensors/{id}/history", s.handleSensorHistory)
	s.mux.HandleFunc("GET /api/sensors/{id}/graph", s.handleSensorGraph)
	s.mux.HandleFunc("DELETE /api/sensors/{id}/history", s.handleSensorClearHistory)
	s.mux.HandleFunc("DELETE /api/history", s.handleClearAllHistory)
	s.mux.HandleFunc("/api/tags", s.handleTags)
	s.mux.HandleFunc("/api/events", s.handleEvents)
	s.mux.HandleFunc("GET /api/settings", s.handleSettingsGet)
	s.mux.HandleFunc("PUT /api/settings", s.handleSettingsPut)
	s.mux.HandleFunc("POST /api/settings/test", s.handleSettingsTest)
	s.mux.HandleFunc("POST /api/settings/tls", s.handleTLSSettingsPut)
	s.mux.HandleFunc("DELETE /api/settings/tls", s.handleTLSSettingsDelete)
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
	if err := s.db.QueryRow("SELECT COUNT(*) FROM sensors").Scan(&n); err != nil {
		respondWithError(w, http.StatusServiceUnavailable, "db unreachable: "+err.Error())
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
		hz["icmp_hint"] = "ICMP socket unavailable: this uid is outside net.ipv4.ping_group_range and CAP_NET_RAW is not granted. Fix: sudo sysctl -w net.ipv4.ping_group_range=\"0 65535\" (persist via /etc/sysctl.d/90-pulsemon-ping.conf) and restart pulsemon — or grant CAP_NET_RAW. See `journalctl -u pulsemon` for the exact error."
	}
	if e := LastProbeError(); e != "" {
		hz["probe_error"] = e
	}
	respondWithJSON(w, http.StatusOK, hz)
}

// sensorStats was the pre-v0.1.18 per-sensor SQL aggregator (4 queries per
// call: 60-probe window, 1h loss/avg, 24h uptime, 1h sparkline). It is
// superseded by ProbeWorker.GetStats, which computes the identical
// SensorStats from the in-memory cache with zero DB round-trips. Kept in
// git history for reference; do not call.

func (s *Server) fetchSensors() []Sensor {
	rows, err := s.db.Query(`SELECT id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at FROM sensors ORDER BY name`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	out := []Sensor{} // non-nil even when empty: nil is the error sentinel
	// the handler distinguishes from a genuinely empty fleet.
	for rows.Next() {
		var sn Sensor
		if err := rows.Scan(&sn.ID, &sn.Name, &sn.Target, &sn.Type, &sn.IntervalS, &sn.TimeoutMS, &sn.LossWarn, &sn.DownAfter, &sn.SpikeMult, &sn.State, &sn.Status, &sn.CreatedAt); err != nil {
			continue
		}
		if sn.Type == "" {
			sn.Type = "icmp"
		}
		out = append(out, sn)
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
		sensors := s.fetchSensors()
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
		if req.IntervalS < 1 || req.IntervalS > 3600 {
			respondWithError(w, http.StatusBadRequest, "interval_s must be 1-3600")
			return
		}
		if req.TimeoutMS <= 0 {
			req.TimeoutMS = 1000
		}
		if req.TimeoutMS < 100 || req.TimeoutMS > 30000 {
			respondWithError(w, http.StatusBadRequest, "timeout_ms must be 100-30000")
			return
		}
		if req.LossWarn <= 0 {
			req.LossWarn = 25
		}
		if req.DownAfter <= 0 {
			req.DownAfter = 2
		}
		if req.SpikeMult <= 0 {
			req.SpikeMult = 3
		}
		if req.SpikeMult < 2 || req.SpikeMult > 10 {
			respondWithError(w, http.StatusBadRequest, "spike_mult must be 2-10")
			return
		}

		id := newID()
		now := time.Now().UTC().Format(time.RFC3339Nano)
		// New sensors start PAUSED (no probing) so a freshly-added, possibly
		// mistyped, target can't fire down alerts before the user has a chance
		// to review it. The user resumes it from the dashboard.
		_, err := s.db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, created_at, status)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'paused', ?, 'up')`,
			id, req.Name, req.Target, req.Type, req.IntervalS, req.TimeoutMS, req.LossWarn, req.DownAfter, req.SpikeMult, now)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				respondWithError(w, http.StatusConflict, "sensor name already exists")
				return
			}
			respondWithError(w, http.StatusInternalServerError, "failed to create sensor: "+err.Error())
			return
		}
		if len(req.Tags) > 0 {
			if err := s.db.SetSensorTags(id, req.Tags); err != nil {
				log.Printf("API: failed to set tags for %s: %v", req.Name, err)
			}
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
func validSensorName(name string) bool {
	if name == "" || len(name) > 60 {
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
func cleanTags(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" || len(t) > 30 || seen[t] {
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
		err := s.db.QueryRow("SELECT id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at FROM sensors WHERE id = ?", id).
			Scan(&sn.ID, &sn.Name, &sn.Target, &sn.Type, &sn.IntervalS, &sn.TimeoutMS, &sn.LossWarn, &sn.DownAfter, &sn.SpikeMult, &sn.State, &sn.Status, &sn.CreatedAt)
		if err != nil {
			if err == sql.ErrNoRows {
				respondWithError(w, http.StatusNotFound, "sensor not found")
			} else {
				respondWithError(w, http.StatusInternalServerError, err.Error())
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

		// Target and type validate as a pair against the RESULTING type:
		// the dashboard edits both in one modal, so a target must be valid
		// for the type the sensor will end up with (URL for http, host for
		// icmp), whether the user changed the target, the type, or both.
		var currentType string
		if err := s.db.QueryRow("SELECT type FROM sensors WHERE id = ?", id).Scan(&currentType); err != nil {
			respondWithError(w, http.StatusNotFound, "sensor not found")
			return
		}
		if currentType == "" {
			currentType = "icmp"
		}
		resultType := currentType
		if req.Type != nil {
			resultType = normalizeProbeType(*req.Type)
		}
		resultTarget := ""
		if req.Target != nil {
			resultTarget = strings.TrimSpace(*req.Target)
		}

		sets, args := []string{}, []interface{}{}
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
			if resultType == "http" {
				if !validURL(resultTarget) {
					respondWithError(w, http.StatusBadRequest, "target must be an http:// or https:// URL (e.g. https://example.com/health)")
					return
				}
			} else if !validTarget(resultTarget) {
				respondWithError(w, http.StatusBadRequest, "target must be an IPv4 address or hostname")
				return
			}
			add("target", resultTarget)
		}
		if req.Type != nil {
			add("type", resultType)
			// Type changed: re-validate the EXISTING target against it.
			// (Both target+type changed is already covered above.)
			if req.Target == nil {
				var existing string
				_ = s.db.QueryRow("SELECT target FROM sensors WHERE id = ?", id).Scan(&existing)
				if resultType == "http" {
					if !validURL(existing) {
						respondWithError(w, http.StatusBadRequest, "existing target is not an http:// or https:// URL")
						return
					}
				} else if !validTarget(existing) {
					respondWithError(w, http.StatusBadRequest, "existing target is not an IPv4 address or hostname")
					return
				}
			}
		}
		if req.Tags != nil {
			if err := s.db.SetSensorTags(id, cleanTags(*req.Tags)); err != nil {
				respondWithError(w, http.StatusInternalServerError, "failed to update tags: "+err.Error())
				return
			}
		}
		if req.IntervalS != nil {
			if *req.IntervalS < 1 || *req.IntervalS > 3600 {
				respondWithError(w, http.StatusBadRequest, "interval_s must be 1-3600")
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
		if req.LossWarn != nil {
			add("loss_warn", *req.LossWarn)
		}
		if req.DownAfter != nil {
			if *req.DownAfter < 1 {
				respondWithError(w, http.StatusBadRequest, "down_after must be >= 1")
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
		if len(sets) == 0 {
			respondWithError(w, http.StatusBadRequest, "no fields to update")
			return
		}
		args = append(args, id)
		res, err := s.db.Exec("UPDATE sensors SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			respondWithError(w, http.StatusNotFound, "sensor not found")
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
		// hot-reloaded.
		if req.Target != nil || req.Type != nil || req.IntervalS != nil || req.TimeoutMS != nil ||
			req.LossWarn != nil || req.DownAfter != nil {
			s.probeWorker.Restart(id)
		}

		respondWithJSON(w, http.StatusOK, map[string]string{"status": "updated"})

	case http.MethodDelete:
		res, err := s.db.Exec("DELETE FROM sensors WHERE id = ?", id)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, err.Error())
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

// handleSensorPing performs one immediate probe ("Pulse Now"). Works while
// paused (SPEC §2). The probe IS recorded in history (a manual pulse is a real
// sample the dashboard should reflect) but does not drive status or alerts —
// see ProbeWorker.PingNow. It uses a fixed 1s timeout (pingNowTimeout),
// independent of the sensor's configured timeout: a manual pulse is a quick
// diagnostic, not a scheduled probe.
func (s *Server) handleSensorPing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := r.PathValue("id")

	o, err := s.probeWorker.PingNow(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondWithError(w, http.StatusNotFound, "sensor not found")
			return
		}
		respondWithError(w, http.StatusInternalServerError, err.Error())
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
	if err := s.db.QueryRow("SELECT COUNT(*) FROM sensors WHERE id = ?", id).Scan(&exists); err != nil || exists == 0 {
		respondWithError(w, http.StatusNotFound, "sensor not found")
		return
	}

	rows, err := s.db.Query("SELECT ts, rtt_ms FROM probes WHERE sensor_id = ? ORDER BY ts DESC LIMIT ?", id, n)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	out := []ProbeRow{}
	for rows.Next() {
		var ts time.Time
		var rtt *float64
		if err := rows.Scan(&ts, &rtt); err != nil {
			continue
		}
		out = append(out, ProbeRow{
			TS:   ts.UTC().Format(time.RFC3339Nano),
			RTT:  rtt,
			Lost: rtt == nil,
		})
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
	if err := s.db.QueryRow("SELECT name FROM sensors WHERE id = ?", id).Scan(&name); err != nil {
		respondWithError(w, http.StatusNotFound, "sensor not found")
		return
	}

	var probes, events int64
	if res, err := s.db.Exec("DELETE FROM probes WHERE sensor_id = ?", id); err == nil {
		probes, _ = res.RowsAffected()
	}
	if res, err := s.db.Exec("DELETE FROM events WHERE sensor_id = ?", id); err == nil {
		events, _ = res.RowsAffected()
	}
	_, _ = s.db.Exec("DELETE FROM alert_state WHERE sensor_id = ?", id)
	_, _ = s.db.Exec("UPDATE sensors SET status = 'up' WHERE id = ?", id)
	// Keep the in-memory stats cache in step with the DB: the cleared sensor's
	// series is gone, so its cache must be too (else the card would show the
	// just-deleted history until the next probe).
	s.probeWorker.ResetStatsFor(id)

	log.Printf("API: cleared history for %s (%d probes, %d events)", name, probes, events)
	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"sensor":  name,
		"cleared": map[string]int64{"probes": probes, "events": events},
	})
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
	if res, err := s.db.Exec("DELETE FROM probes"); err == nil {
		probes, _ = res.RowsAffected()
	}
	if res, err := s.db.Exec("DELETE FROM events"); err == nil {
		events, _ = res.RowsAffected()
	}
	_, _ = s.db.Exec("DELETE FROM alert_state")
	_, _ = s.db.Exec("UPDATE sensors SET status = 'up'")
	s.probeWorker.ResetStatsAll() // wipe the whole in-memory stats cache too

	log.Printf("API: cleared ALL history (%d probes, %d events)", probes, events)
	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"cleared": map[string]int64{"probes": probes, "events": events},
	})
}

// handleSensorClone creates a copy of a sensor with a new unique name
// (name-copy, name-copy2, ...). The clone starts PAUSED, like a new sensor.
func (s *Server) handleSensorClone(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := r.PathValue("id")

	var src Sensor
	err := s.db.QueryRow("SELECT id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at FROM sensors WHERE id = ?", id).
		Scan(&src.ID, &src.Name, &src.Target, &src.Type, &src.IntervalS, &src.TimeoutMS, &src.LossWarn, &src.DownAfter, &src.SpikeMult, &src.State, &src.Status, &src.CreatedAt)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "sensor not found")
		return
	}
	if src.Type == "" {
		src.Type = "icmp"
	}
	src.Tags = s.db.SensorTags(id)

	// Find a free clone name.
	name := src.Name + "-copy"
	for i := 2; ; i++ {
		var exists int
		_ = s.db.QueryRow("SELECT COUNT(*) FROM sensors WHERE name = ?", name).Scan(&exists)
		if exists == 0 {
			break
		}
		name = fmt.Sprintf("%s-copy%d", src.Name, i)
		if i > 100 {
			respondWithError(w, http.StatusConflict, "too many clones with this name")
			return
		}
	}

	newID := newID()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	// Clone starts PAUSED, matching new-sensor behavior.
	_, err = s.db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, created_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'paused', ?, 'up')`,
		newID, name, src.Target, src.Type, src.IntervalS, src.TimeoutMS, src.LossWarn, src.DownAfter, src.SpikeMult, now)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to clone sensor: "+err.Error())
		return
	}
	if len(src.Tags) > 0 {
		if err := s.db.SetSensorTags(newID, src.Tags); err != nil {
			log.Printf("API: failed to set tags on clone %s: %v", name, err)
		}
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
		tag := r.URL.Query().Get("tag")
		if tag == "" {
			respondWithError(w, http.StatusBadRequest, "tag query parameter is required")
			return
		}
		n, err := s.db.DeleteTag(tag)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, err.Error())
			return
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
	switch r.URL.Query().Get("range") {
	case "24h":
		bucketSecs, from = 900, "-24 hours"
	case "1h":
		bucketSecs, from = 60, "-1 hour"
	default:
		respondWithError(w, http.StatusBadRequest, "range must be 1h or 24h")
		return
	}

	var exists int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM sensors WHERE id = ?", id).Scan(&exists); err != nil || exists == 0 {
		respondWithError(w, http.StatusNotFound, "sensor not found")
		return
	}

	// Time windows MUST compare epoch values, not raw strings: ts is stored
	// as RFC3339 ('2026-10-04T20:47:28.530Z') while datetime('now', ?)
	// returns space-separated ('2026-10-04 19:47:28'), so a plain
	// `ts >= datetime('now', ?)` string comparison matched nearly every row
	// and the "1h"/"24h" graphs silently showed the ENTIRE history.
	// CAST(strftime('%s', ...)) normalizes both sides to epoch seconds.
	rows, err := s.db.Query(`SELECT (strftime('%s', ts) / ?) * ? AS bucket,
		COUNT(*) AS total,
		COALESCE(SUM(rtt_ms IS NULL), 0) AS lost,
		AVG(rtt_ms) AS avg_rtt,
		MAX(rtt_ms) AS max_rtt
		FROM probes WHERE sensor_id = ?
			AND CAST(strftime('%s', ts) AS INTEGER) >= CAST(strftime('%s', datetime('now', ?)) AS INTEGER)
		GROUP BY bucket ORDER BY bucket`, bucketSecs, bucketSecs, id, from)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	points := []GraphPoint{}
	for rows.Next() {
		var p GraphPoint
		if err := rows.Scan(&p.T, &p.Total, &p.Lost, &p.Avg, &p.Max); err != nil {
			continue
		}
		if p.Total > 0 {
			p.LossPct = float64(p.Lost) / float64(p.Total) * 100
		}
		points = append(points, p)
	}

	var total, lostTotal int
	_ = s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(rtt_ms IS NULL), 0)
		FROM probes WHERE sensor_id = ?
			AND CAST(strftime('%s', ts) AS INTEGER) >= CAST(strftime('%s', datetime('now', ?)) AS INTEGER)`, id, from).Scan(&total, &lostTotal)
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
		res, err := s.db.Exec("DELETE FROM events")
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}
		n, _ := res.RowsAffected()
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
	rows, err := s.db.Query(`SELECT e.id, e.sensor_id, COALESCE(s.name, e.sensor_id), e.ts, e.from_status, e.to_status, e.note
		FROM events e LEFT JOIN sensors s ON s.id = e.sensor_id
		ORDER BY e.ts DESC LIMIT ?`, n)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	events := []EventView{}
	for rows.Next() {
		var e EventView
		if err := rows.Scan(&e.ID, &e.SensorID, &e.Sensor, &e.TS, &e.From, &e.To, &e.Note); err != nil {
			continue
		}
		events = append(events, e)
	}
	respondWithJSON(w, http.StatusOK, events)
}

// webhookMasked shows the URL with the secret masked so the dashboard and
// the settings API never echo credentials. Google Chat keeps its key in a
// query string (mask the query); Discord embeds the token in the path
// (mask the last path segment). Without the path mask a Discord webhook
// would be fully exposed — the token in the path is the credential.
func webhookMasked(url string) string {
	if url == "" {
		return ""
	}
	if i := strings.Index(url, "?"); i >= 0 {
		return url[:i] + "?***"
	}
	slash := strings.LastIndex(url, "/")
	if slash >= 0 && slash < len(url)-1 {
		return url[:slash] + "/***"
	}
	return url
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
			Kind    string  `json:"kind"`
			URL     *string `json:"url"`     // nil = keep existing; "" = clear; full URL = set
			Enabled *bool   `json:"enabled"` // nil = keep; else set
		} `json:"providers"`
		AlertScope  string   `json:"alert_scope"`
		AlertFilter []string `json:"alert_filter"`
		RealertMin  *int     `json:"realert_min"` // nil = keep; 0 = alert once only
		MaintMode   *bool    `json:"maintenance_mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		code, msg := requestBodyErr(err)
		respondWithError(w, code, msg)
		return
	}
	// Per-provider updates. The legacy top-level webhook_url maps to the
	// google_chat provider so an older dashboard keeps working.
	for _, prov := range req.Providers {
		if err := s.applyProviderUpdate(prov.Kind, prov.URL, prov.Enabled); err != nil {
			respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.WebhookURL != nil {
		if err := s.applyProviderUpdate("google_chat", req.WebhookURL, nil); err != nil {
			respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.AlertScope == "" {
		req.AlertScope = "all"
	}
	if req.AlertScope != "all" && req.AlertScope != "tags" && req.AlertScope != "sensors" {
		respondWithError(w, http.StatusBadRequest, "alert_scope must be all, tags or sensors")
		return
	}
	if req.RealertMin != nil {
		if *req.RealertMin < 0 || *req.RealertMin > 1440 {
			respondWithError(w, http.StatusBadRequest, "realert_min must be 0-1440 (0 = alert once only)")
			return
		}
		if err := s.db.SetSetting("realert_min", strconv.Itoa(*req.RealertMin)); err != nil {
			respondWithError(w, http.StatusInternalServerError, "failed to save: "+err.Error())
			return
		}
	}
	if req.AlertFilter == nil {
		req.AlertFilter = []string{}
	}
	if err := s.db.SetSetting("alert_scope", req.AlertScope); err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to save: "+err.Error())
		return
	}
	filterJSON, _ := json.Marshal(req.AlertFilter)
	if err := s.db.SetSetting("alert_filter", string(filterJSON)); err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to save: "+err.Error())
		return
	}
	if req.MaintMode != nil {
		if *req.MaintMode {
			// Entering maintenance: remember which sensors are ACTIVE right
			// now, then pause all of them so they stop probing (not just
			// alerting). Sensors already paused by the user are not active,
			// so they are left alone. The snapshot is what resume restores.
			ids, err := s.db.ActiveSensorIDs()
			if err != nil {
				respondWithError(w, http.StatusInternalServerError, "failed to snapshot active sensors: "+err.Error())
				return
			}
			// Nothing active: the snapshot would be empty and resume would have
			// nothing to restore. Refuse instead of silently entering a
			// maintenance state that can't be cleanly undone.
			if len(ids) == 0 {
				respondWithError(w, http.StatusBadRequest, "no active sensors to pause")
				return
			}
			if _, err := s.db.SetSensorStates(ids, "paused"); err != nil {
				respondWithError(w, http.StatusInternalServerError, "failed to pause sensors: "+err.Error())
				return
			}
			snapJSON, _ := json.Marshal(ids)
			if err := s.db.SetSetting("maintenance_active_ids", string(snapJSON)); err != nil {
				respondWithError(w, http.StatusInternalServerError, "failed to save: "+err.Error())
				return
			}
			if err := s.db.SetSetting("maintenance_mode", "1"); err != nil {
				respondWithError(w, http.StatusInternalServerError, "failed to save: "+err.Error())
				return
			}
			// Paused sensors don't probe, so their alert state can't drift;
			// reset it now so resume doesn't instantly re-alert on a stale
			// bad state.
			s.probeWorker.ResetAlertStates()
			log.Printf("API: maintenance mode ON (%d sensors paused)", len(ids))
		} else {
			// Leaving maintenance: reactivate exactly the sensors that were
			// active when maintenance started (the snapshot). Sensors the
			// user paused, or that got paused/added during maintenance, stay
			// paused. Then clear the snapshot and reset alert timers so a
			// still-bad sensor doesn't instantly re-alert on the next tick.
			snap := s.db.GetSetting("maintenance_active_ids")
			var ids []string
			if snap != "" {
				if err := json.Unmarshal([]byte(snap), &ids); err != nil {
					ids = nil
				}
			}
			if _, err := s.db.SetSensorStates(ids, "active"); err != nil {
				respondWithError(w, http.StatusInternalServerError, "failed to resume sensors: "+err.Error())
				return
			}
			if err := s.db.SetSetting("maintenance_active_ids", ""); err != nil {
				respondWithError(w, http.StatusInternalServerError, "failed to save: "+err.Error())
				return
			}
			if err := s.db.SetSetting("maintenance_mode", "0"); err != nil {
				respondWithError(w, http.StatusInternalServerError, "failed to save: "+err.Error())
				return
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
	log.Printf("API: settings updated (scope=%s filter=%d realert=%dm)", req.AlertScope, len(req.AlertFilter), realertLog)
	respondWithJSON(w, http.StatusOK, s.settingsPayload())
}

// applyProviderUpdate persists one provider's URL / enabled flag. URL is a
// pointer so nil = "don't touch this field" (the dashboard only sends what
// changed); an empty string clears; a non-empty value is validated first.
// This is the single write path for provider config, so the validation and
// key-naming stay consistent no matter how many providers exist.
func (s *Server) applyProviderUpdate(kind string, url *string, enabled *bool) error {
	if _, ok := providerByKey(kind); !ok {
		return fmt.Errorf("unknown alert provider: %q", kind)
	}
	if url != nil {
		u := strings.TrimSpace(*url)
		if u != "" {
			if err := validateWebhookURL(u); err != nil {
				return fmt.Errorf("%s url: %s", kind, err.Error())
			}
		}
		if err := s.db.SetSetting(kind+"_url", u); err != nil {
			return fmt.Errorf("failed to save %s url: %s", kind, err.Error())
		}
	}
	if enabled != nil {
		val := "0"
		if *enabled {
			val = "1"
		}
		if err := s.db.SetSetting(kind+"_enabled", val); err != nil {
			return fmt.Errorf("failed to save %s enable flag: %s", kind, err.Error())
		}
	}
	return nil
}

func (s *Server) handleSettingsTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Body: {"kind":"google_chat"|"discord"}. The dashboard tests the provider
	// whose URL is being verified, so kind is required.
	var req struct {
		Kind string `json:"kind"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
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
	switch {
	case strings.HasSuffix(path, ".html"):
		w.Header().Set("Content-Type", "text/html")
	case strings.HasSuffix(path, ".js"):
		w.Header().Set("Content-Type", "application/javascript")
	case strings.HasSuffix(path, ".css"):
		w.Header().Set("Content-Type", "text/css")
	case strings.HasSuffix(path, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	case strings.HasSuffix(path, ".png"):
		w.Header().Set("Content-Type", "image/png")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
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
