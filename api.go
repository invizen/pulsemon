package main

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

//go:embed web/*
var content embed.FS

// Sensor mirrors the sensors table. JSON is snake_case per SPEC §4.
type Sensor struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Target    string   `json:"target"`
	Tags      []string `json:"tags"`
	IntervalS int      `json:"interval_s"`
	TimeoutMS int      `json:"timeout_ms"`
	LossWarn  int      `json:"loss_warn"`
	DownAfter int      `json:"down_after"`
	SpikeMult int      `json:"spike_mult"`
	State     string   `json:"state"`    // active | paused
	Status    string   `json:"status"`   // up | degraded | down
	CreatedAt string   `json:"created_at"`
}

// SensorView is what GET /api/sensors returns: sensor + window stats.
type SensorView struct {
	Sensor
	Stats *SensorStats `json:"stats"` // nil when paused or no probes yet
}

// SensorStats is a 60-probe window summary (SPEC §4).
type SensorStats struct {
	RTTLast   *float64   `json:"rtt_last"`
	RTTMin    *float64   `json:"rtt_min"`
	RTTAvg    *float64   `json:"rtt_avg"`
	RTTMax    *float64   `json:"rtt_max"`
	LossPct   float64    `json:"loss_pct"`
	LostCount int        `json:"lost_count"`
	Total     int        `json:"total"`
	Recent    []*float64 `json:"recent"`       // last 30 probes, newest first, null = lost (sparkline)
	Uptime24h float64    `json:"uptime_24h"`   // % of last-24h probes that replied
}

type ProbeRow struct {
	TS     string   `json:"ts"`
	RTT    *float64 `json:"rtt_ms"` // null = lost
	Lost   bool     `json:"lost"`
}

type APIError struct {
	Error string `json:"error"`
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(APIError{Error: message})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}

type Server struct {
	db          *DB
	probeWorker *ProbeWorker
	webhookURL  string
	mux         *http.ServeMux
}

func NewServer(db *DB, pw *ProbeWorker, webhookURL string) *Server {
	s := &Server{
		db:          db,
		probeWorker: pw,
		webhookURL:  webhookURL,
		mux:         http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) Mux() *http.ServeMux {
	return s.mux
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
		"status":   "ok",
		"sensors":  n,
		"probing":  s.probeWorker.ActiveCount(),
		"time":     time.Now().UTC().Format(time.RFC3339),
	}
	if m := EngineMode(); m != "" {
		hz["icmp_mode"] = m
	}
	if e := LastProbeError(); e != "" {
		hz["probe_error"] = e
	}
	respondWithJSON(w, http.StatusOK, hz)
}

// sensorStats computes a 60-probe window summary for one sensor.
func (s *Server) sensorStats(id string) *SensorStats {
	const q = `SELECT rtt_ms,
			COUNT(*) OVER () AS total,
			SUM(CASE WHEN rtt_ms IS NULL THEN 1 ELSE 0 END) OVER () AS lost,
			ROW_NUMBER() OVER (ORDER BY ts DESC) AS rn
		FROM (SELECT rtt_ms, ts FROM probes WHERE sensor_id = ? ORDER BY ts DESC LIMIT 60)`
	rows, err := s.db.Query(q, id)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var st SensorStats
	var min, max, sum float64
	have := false
	for rows.Next() {
		var rtt *float64
		var rn int64
		if err := rows.Scan(&rtt, &st.Total, &st.LostCount, &rn); err != nil {
			continue
		}
		if rn <= 30 {
			st.Recent = append(st.Recent, rtt) // newest first
		}
		if rtt != nil {
			if !have {
				min, max, have = *rtt, *rtt, true
			} else {
				if *rtt < min {
					min = *rtt
				}
				if *rtt > max {
					max = *rtt
				}
			}
			sum += *rtt
			if st.RTTLast == nil { // first row = newest
				v := *rtt
				st.RTTLast = &v
			}
		}
	}
	if st.Total > 0 {
		st.LossPct = float64(st.LostCount) / float64(st.Total) * 100
	}
	if have {
		mn, mx, avg := min, max, sum / float64(st.Total-st.LostCount)
		st.RTTMin, st.RTTMax, st.RTTAvg = &mn, &mx, &avg
	}
	// 24h uptime (independent of the 60-probe stats window).
	var d24, l24 int
	if err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(rtt_ms IS NULL), 0)
		FROM probes WHERE sensor_id = ? AND ts >= datetime('now', '-1 day')`, id).Scan(&d24, &l24); err == nil && d24 > 0 {
		st.Uptime24h = float64(d24-l24) / float64(d24) * 100
	}

	if st.Total == 0 {
		return nil
	}
	return &st
}

func (s *Server) fetchSensors() []Sensor {
	rows, err := s.db.Query("SELECT id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at FROM sensors ORDER BY name")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []Sensor
	for rows.Next() {
		var sn Sensor
		if err := rows.Scan(&sn.ID, &sn.Name, &sn.Target, &sn.IntervalS, &sn.TimeoutMS, &sn.LossWarn, &sn.DownAfter, &sn.SpikeMult, &sn.State, &sn.Status, &sn.CreatedAt); err != nil {
			continue
		}
		sn.Tags = s.db.SensorTags(sn.ID)
		out = append(out, sn)
	}
	return out
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
				v.Stats = s.sensorStats(sn.ID)
			}
			views = append(views, v)
		}
		respondWithJSON(w, http.StatusOK, views)

	case http.MethodPost:
		var req struct {
			Name      string   `json:"name"`
			Target    string   `json:"target"`
			Tags      []string `json:"tags"`
			IntervalS int      `json:"interval_s"`
			TimeoutMS int      `json:"timeout_ms"`
			LossWarn  int      `json:"loss_warn"`
			DownAfter int      `json:"down_after"`
			SpikeMult int      `json:"spike_mult"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		req.Target = strings.TrimSpace(req.Target)
		if req.Name == "" || req.Target == "" {
			respondWithError(w, http.StatusBadRequest, "name and target are required")
			return
		}
		if !validTarget(req.Target) {
			respondWithError(w, http.StatusBadRequest, "target must be an IPv4 address or hostname")
			return
		}
		req.Tags = cleanTags(req.Tags)
		if req.IntervalS <= 0 {
			req.IntervalS = 15
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
			req.DownAfter = 4
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
		_, err := s.db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, created_at, status)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'paused', ?, 'up')`,
			id, req.Name, req.Target, req.IntervalS, req.TimeoutMS, req.LossWarn, req.DownAfter, req.SpikeMult, now)
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
		log.Printf("API: created sensor %s (%s) [paused]", req.Name, id)
		respondWithJSON(w, http.StatusCreated, Sensor{
			ID: id, Name: req.Name, Target: req.Target, Tags: req.Tags,
			IntervalS: req.IntervalS, TimeoutMS: req.TimeoutMS,
			LossWarn: req.LossWarn, DownAfter: req.DownAfter, SpikeMult: req.SpikeMult,
			State: "paused", Status: "up", CreatedAt: now,
		})

	default:
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
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
		err := s.db.QueryRow("SELECT id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at FROM sensors WHERE id = ?", id).
			Scan(&sn.ID, &sn.Name, &sn.Target, &sn.IntervalS, &sn.TimeoutMS, &sn.LossWarn, &sn.DownAfter, &sn.SpikeMult, &sn.State, &sn.Status, &sn.CreatedAt)
		if err != nil {
			if err == sql.ErrNoRows {
				respondWithError(w, http.StatusNotFound, "sensor not found")
			} else {
				respondWithError(w, http.StatusInternalServerError, err.Error())
			}
			return
		}
		sn.Tags = s.db.SensorTags(id)
		v := SensorView{Sensor: sn}
		if sn.State == "active" {
			v.Stats = s.sensorStats(id)
		}
		respondWithJSON(w, http.StatusOK, v)

	case http.MethodPatch:
		var req struct {
			Name      *string   `json:"name"`
			Target    *string   `json:"target"`
			Tags      *[]string `json:"tags"`
			IntervalS *int      `json:"interval_s"`
			TimeoutMS *int      `json:"timeout_ms"`
			LossWarn  *int      `json:"loss_warn"`
			DownAfter *int      `json:"down_after"`
			SpikeMult *int      `json:"spike_mult"`
			State     *string   `json:"state"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
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
			add("name", strings.TrimSpace(*req.Name))
		}
		if req.Target != nil {
			if strings.TrimSpace(*req.Target) == "" {
				respondWithError(w, http.StatusBadRequest, "target cannot be empty")
				return
			}
			if !validTarget(strings.TrimSpace(*req.Target)) {
				respondWithError(w, http.StatusBadRequest, "target must be an IPv4 address or hostname")
				return
			}
			add("target", strings.TrimSpace(*req.Target))
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
		// A config change (target/interval/...) requires respawning the loop.
		if req.Target != nil || req.IntervalS != nil || req.TimeoutMS != nil {
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

// handleSensorPing performs one immediate probe ("Echo Now"). Works while paused
// (SPEC §2) — the result is NOT recorded in history; it is diagnostic only.
func (s *Server) handleSensorPing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := r.PathValue("id")

	var target string
	err := s.db.QueryRow("SELECT target FROM sensors WHERE id = ?", id).Scan(&target)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "sensor not found")
		return
	}

	res := pingHost(target, 2*time.Second)
	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"rtt_ms": rttMillis(res.RTT), // float ms, 0 when lost
		"lost":   res.Lost,
		"error":  errText(res.Error),
	})
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
	err := s.db.QueryRow("SELECT id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at FROM sensors WHERE id = ?", id).
		Scan(&src.ID, &src.Name, &src.Target, &src.IntervalS, &src.TimeoutMS, &src.LossWarn, &src.DownAfter, &src.SpikeMult, &src.State, &src.Status, &src.CreatedAt)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "sensor not found")
		return
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
	_, err = s.db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, created_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'paused', ?, 'up')`,
		newID, name, src.Target, src.IntervalS, src.TimeoutMS, src.LossWarn, src.DownAfter, src.SpikeMult, now)
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
		ID: newID, Name: name, Target: src.Target, Tags: src.Tags,
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

	rows, err := s.db.Query(`SELECT (strftime('%s', ts) / ?) * ? AS bucket,
		COUNT(*) AS total,
		COALESCE(SUM(rtt_ms IS NULL), 0) AS lost,
		AVG(rtt_ms) AS avg_rtt,
		MAX(rtt_ms) AS max_rtt
		FROM probes WHERE sensor_id = ? AND ts >= datetime('now', ?)
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
		FROM probes WHERE sensor_id = ? AND ts >= datetime('now', ?)`, id, from).Scan(&total, &lostTotal)
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

// webhookMasked shows the URL with the key/token query params masked so the
// dashboard can display it without exposing credentials.
func webhookMasked(url string) string {
	if url == "" {
		return ""
	}
	i := strings.Index(url, "?")
	if i < 0 {
		return url
	}
	return url[:i] + "?***"
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
	return map[string]interface{}{
		"webhook_url":        webhookMasked(s.probeWorker.ResolveWebhookURL()),
		"webhook_configured": s.probeWorker.HasWebhook(),
		"source":             s.probeWorker.WebhookSource(),
		"alert_scope":        scope,
		"alert_filter":       filter,
		"realert_min":        realert,
		"maintenance_mode":   s.db.GetSetting("maintenance_mode") == "1",
		"alert_degraded":     s.db.GetSetting("alert_degraded") != "0",
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
		WebhookURL    *string  `json:"webhook_url"` // nil = keep existing
		AlertScope    string   `json:"alert_scope"`
		AlertFilter   []string `json:"alert_filter"`
		RealertMin    *int     `json:"realert_min"` // nil = keep; 0 = alert once only
		MaintMode     *bool    `json:"maintenance_mode"`
		AlertDegraded *bool    `json:"alert_degraded"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.WebhookURL != nil {
		*req.WebhookURL = strings.TrimSpace(*req.WebhookURL)
		if *req.WebhookURL != "" {
			if err := validateWebhookURL(*req.WebhookURL); err != nil {
				respondWithError(w, http.StatusBadRequest, "webhook_url: "+err.Error())
				return
			}
		}
		if err := s.db.SetSetting("webhook_url", *req.WebhookURL); err != nil {
			respondWithError(w, http.StatusInternalServerError, "failed to save: "+err.Error())
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
		val := "0"
		if *req.MaintMode {
			val = "1"
		}
		if err := s.db.SetSetting("maintenance_mode", val); err != nil {
			respondWithError(w, http.StatusInternalServerError, "failed to save: "+err.Error())
			return
		}
		// Coming out of maintenance: reset re-alert timers so sensors that
		// are already in a bad state don't instantly re-alert on the next
		// probe tick.
		if !*req.MaintMode {
			s.probeWorker.ResetAlertStates()
		}
		log.Printf("API: maintenance mode %s", map[string]string{"1": "ON", "0": "off"}[val])
	}
	if req.AlertDegraded != nil {
		val := "1"
		if !*req.AlertDegraded {
			val = "0"
		}
		if err := s.db.SetSetting("alert_degraded", val); err != nil {
			respondWithError(w, http.StatusInternalServerError, "failed to save: "+err.Error())
			return
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

func (s *Server) handleSettingsTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ok, detail := s.probeWorker.TestWebhook()
	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"ok":    ok,
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
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Write(data)
}

func rttMillis(d time.Duration) float64 {
	return d.Seconds() * 1000
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%v", err)
}
