package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"pulsemon/internal/store"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const minIntervalS = 5

// Sensor mirrors the sensors table. JSON is snake_case per SPEC §4.

type Sensor struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Target    string   `json:"target"`
	Type      string   `json:"type"` // "icmp" (default) | "http" | "tcp"
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

// sensorCols is the canonical full-sensor column list, shared by every
// full-sensor SELECT (fetchSensors, handleSensorByID, handleSensorClone) so
// the column order stays in lockstep with scanSensorRow. Adding a column to
// the sensors table means updating this list and scanSensorRow in ONE place
// (the list used to be copy-pasted at all three SELECT sites).

const sensorCols = "id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at"

// sensorScanner is the narrow interface both *sql.Row and *sql.Rows satisfy,
// so scanSensorRow serves the single-row and list queries alike.

type sensorScanner interface{ Scan(dest ...any) error }

// scanSensorRow reads one full-sensor row (the sensorCols columns) into sn.
// The 12-field scan lives here once instead of being repeated at every
// full-sensor SELECT site.

func scanSensorRow(sc sensorScanner, sn *Sensor) error {
	return sc.Scan(&sn.ID, &sn.Name, &sn.Target, &sn.Type, &sn.IntervalS, &sn.TimeoutMS,
		&sn.LossWarn, &sn.DownAfter, &sn.SpikeMult, &sn.State, &sn.Status, &sn.CreatedAt)
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

func (s *Server) cachedSensorCount(ctx context.Context) (int, error) {
	s.sensorCountMu.Lock()
	if time.Since(s.sensorCountAt) < 2*time.Second {
		n := s.sensorCountCache
		s.sensorCountMu.Unlock()
		return n, nil
	}
	s.sensorCountMu.Unlock()

	var n int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sensors").Scan(&n); err != nil {
		return 0, err
	}
	s.sensorCountMu.Lock()
	s.sensorCountCache = n
	s.sensorCountAt = time.Now()
	s.sensorCountMu.Unlock()
	return n, nil
}

func (s *Server) fetchSensors(ctx context.Context) []Sensor {
	// 'deleting' rows are in-flight deletions (marked by the DELETE
	// handler before the cascade runs — see sensor-delete-deleting-state):
	// hide them so the dashboard drops the sensor the moment deletion
	// starts instead of showing a zombie with an unknown state.
	rows, err := s.db.QueryContext(ctx, "SELECT "+sensorCols+" FROM sensors WHERE state <> 'deleting' ORDER BY name")
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
		if err := scanSensorRow(rows, &sn); err != nil {
			log.Printf("API: skipping corrupt sensor row: %v", err)
			continue
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
	tagMap, err := s.db.SensorTagsFor(ctx, ids)
	if err != nil {
		// Nil sentinel: the handler 500s. Returning the fleet with the
		// tags silently missing would render partial data as complete
		//
		log.Printf("API: sensor tag batch query failed: %v", err)
		return nil
	}
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
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			code, msg := requestBodyErr(err)
			respondWithError(w, code, msg)
			return
		}
		spec := sensorSpec{
			Name:      strings.TrimSpace(req.Name),
			Target:    strings.TrimSpace(req.Target),
			Type:      normalizeProbeType(req.Type),
			Tags:      cleanTags(req.Tags),
			IntervalS: req.IntervalS,
			TimeoutMS: req.TimeoutMS,
			LossWarn:  req.LossWarn,
			DownAfter: req.DownAfter,
			SpikeMult: req.SpikeMult,
		}
		spec.applyDefaults()
		if err := spec.validate(); err != nil {
			respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}

		id := store.NewID()
		now := store.Now()
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
				id, spec.Name, spec.Target, spec.Type, spec.IntervalS, spec.TimeoutMS, spec.LossWarn, spec.DownAfter, spec.SpikeMult, now); err != nil {
				return err
			}
			if len(spec.Tags) > 0 {
				return setSensorTagsInConn(r.Context(), c, id, spec.Tags)
			}
			return nil
		})
		if err != nil {
			// A UNIQUE-constraint violation (by result code) is a name
			// collision → 409; any other failure is a 500.
			if isUniqueConstraintErr(err) {
				respondWithError(w, http.StatusConflict, "sensor name already exists")
				return
			}
			respondInternal(w, "create sensor", err)
			return
		}
		log.Printf("API: created sensor %s (%s) [%s] [paused]", spec.Name, id, spec.Type)
		respondWithJSON(w, http.StatusCreated, Sensor{
			ID: id, Name: spec.Name, Target: spec.Target, Type: spec.Type, Tags: spec.Tags,
			IntervalS: spec.IntervalS, TimeoutMS: spec.TimeoutMS,
			LossWarn: spec.LossWarn, DownAfter: spec.DownAfter, SpikeMult: spec.SpikeMult,
			State: "paused", Status: "up", CreatedAt: now,
		})

	default:
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// validSensorName rejects sensor names that are empty, overlong, or contain
// characters that would let a stored value escape its string context in a
// consumer. Names are operator labels, not free text: no quotes, angle
// brackets, backslash, or control characters.
//
// This is a defense-in-depth INPUT gate, NOT the primary XSS mitigation:
// the dashboard's strict CSP (no 'unsafe-inline') plus esc() HTML-escaping
// at every text render site is the primary layer, and the click handlers
// read values from data-* attributes (there are no inline JS string
// interpolations). The input gate keeps the stored data clean for the
// non-HTML consumers (alert cards, logs, the inspector) where output
// encoding does not apply, and stops a malicious account from planting a
// sensor whose name runs JS in other operators' browsers if a render site
// is ever missed.
//
// Why a blacklist and NOT the suggested whitelist: a narrow whitelist like ^[a-zA-Z0-9_\-. ]+$ is more idiomatic
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
// Tags pass the same string-escape gate as sensor names (validSensorName):
// a tag like x');alert(1);// must not be storable. The gate keeps the
// non-HTML consumers (alert cards, logs, inspector) clean and is
// belt-and-braces on top of the CSP + esc() output escaping (see
// validSensorName).

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
		err := scanSensorRow(s.db.QueryRowContext(r.Context(), "SELECT "+sensorCols+" FROM sensors WHERE id = ?", id), &sn)
		if err != nil {
			if err == sql.ErrNoRows {
				respondWithError(w, http.StatusNotFound, "sensor not found")
			} else {
				respondInternal(w, "get sensor "+id, err)
			}
			return
		}
		sn.Tags, err = s.db.SensorTags(r.Context(), id)
		if err != nil {
			// A failed tag read is not "sensor has no tags" — fail the
			// request instead of rendering the swallow as truth
			respondInternal(w, "get sensor tags "+id, err)
			return
		}
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
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
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

		sets, args := []string{}, []any{}
		// newTags holds the cleaned tag list when req.Tags was sent; the
		// write happens after ALL validation, in the UPDATE transaction.
		newTags := []string{}
		add := func(col string, val any) {
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
			if err := validateSensorRange("interval_s", *req.IntervalS); err != nil {
				respondWithError(w, http.StatusBadRequest, err.Error())
				return
			}
			add("interval_s", *req.IntervalS)
		}
		if req.TimeoutMS != nil {
			if err := validateSensorRange("timeout_ms", *req.TimeoutMS); err != nil {
				respondWithError(w, http.StatusBadRequest, err.Error())
				return
			}
			add("timeout_ms", *req.TimeoutMS)
		}
		// The effective timeout-vs-interval cross-check runs in-tx against
		// the fresh stored values: the pre-tx copy
		// existed only to fast-fail, and the in-tx check returns the
		// identical 400.
		if req.LossWarn != nil {
			if err := validateSensorRange("loss_warn", *req.LossWarn); err != nil {
				respondWithError(w, http.StatusBadRequest, err.Error())
				return
			}
			add("loss_warn", *req.LossWarn)
		}
		if req.DownAfter != nil {
			if err := validateSensorRange("down_after", *req.DownAfter); err != nil {
				respondWithError(w, http.StatusBadRequest, err.Error())
				return
			}
			add("down_after", *req.DownAfter)
		}
		if req.SpikeMult != nil {
			if err := validateSensorRange("spike_mult", *req.SpikeMult); err != nil {
				respondWithError(w, http.StatusBadRequest, err.Error())
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
			var txIntervalS, txTimeoutMS, txDownAfter int
			scanErr := c.QueryRowContext(ctx,
				"SELECT type, target, interval_s, timeout_ms, down_after FROM sensors WHERE id = ?", id).
				Scan(&txType, &txTarget, &txIntervalS, &txTimeoutMS, &txDownAfter)
			if patchScanHook != nil {
				scanErr = patchScanHook(scanErr)
			}
			if scanErr != nil {
				// Only a missing row is a 404. A transient SQLITE_BUSY, a
				// canceled context, or an I/O failure must surface as a
				// logged 500 (respondInternal) — collapsing it into
				// errPatchSensorGone told the client "sensor not found"
				// and dropped the error from the service log.
				// (2026-11-19 external review F17)
				// History: docs/DECISIONS.md -> patch-scan-error-404-vs-500
				if errors.Is(scanErr, sql.ErrNoRows) {
					return errPatchSensorGone
				}
				return scanErr
			}
			freshType := txType
			if req.Type != nil {
				freshType = normalizeProbeType(*req.Type)
			}
			freshTarget := txTarget
			if req.Target != nil {
				freshTarget = strings.TrimSpace(*req.Target)
			}
			feffIntervalS := txIntervalS
			if req.IntervalS != nil {
				feffIntervalS = *req.IntervalS
			}
			feffTimeoutMS := txTimeoutMS
			if req.TimeoutMS != nil {
				feffTimeoutMS = *req.TimeoutMS
			}
			feffDownAfter := txDownAfter
			if req.DownAfter != nil {
				feffDownAfter = *req.DownAfter
			}
			crossField := sensorSpec{
				Target:    freshTarget,
				Type:      freshType,
				IntervalS: feffIntervalS,
				TimeoutMS: feffTimeoutMS,
				DownAfter: feffDownAfter,
			}
			if err := crossField.validateCrossField(); err != nil {
				// The rule's sentinel travels inside the error
				// (crossFieldError.Unwrap); the outer errors.Is switch
				// maps it — no message-substring re-derivation
				return err
			}

			if len(sets) > 0 {
				args = append(args, id)
				res, err := c.ExecContext(ctx, "UPDATE sensors SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...)
				if err != nil {
					// A rename hitting the UNIQUE name constraint is a 409,
					// exactly like POST — not a 500 with raw SQL text.
					if isUniqueConstraintErr(err) {
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
			// patchErr is a *crossFieldError whose Error() carries the
			// probe-type-specific message (ICMP: "IPv4 address or hostname";
			// TCP: "host:port with an explicit port 1-65535"). Hardcoding the
			// ICMP text here mis-told TCP targets what to fix.
			respondWithError(w, http.StatusBadRequest, patchErr.Error())
		case errors.Is(patchErr, errPatchTimeoutExceedsInterval):
			respondWithError(w, http.StatusBadRequest, "timeout_ms must not exceed interval_s*1000")
		case errors.Is(patchErr, errPatchDownAfterExceedsRetention):
			respondWithError(w, http.StatusBadRequest, "down_after × interval_s must not exceed 24h (probe retention)")
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
		// Existence check up front drives the 404 (and skips the batched
		// no-op deletes) — the sensor row's PK lookup is cheap. Scan yields
		// sql.ErrNoRows (not a zero value) when the id is absent, so that
		// error is the 404 signal. The current state is captured for the
		// compensating restore below.
		var one int
		var curState string
		if err := s.db.QueryRowContext(r.Context(), "SELECT 1, state FROM sensors WHERE id = ?", id).Scan(&one, &curState); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				respondWithError(w, http.StatusNotFound, "sensor not found")
				return
			}
			respondInternal(w, "delete sensor "+id, err)
			return
		}
		// Mark the row 'deleting' BEFORE stopping the loop and cascading
		// the rows: the batched deletes below take seconds (a 5s sensor
		// carries ~17k probe rows), and a 5s syncSensors tick (or a
		// syncReq) landing mid-delete used to see the row still 'active'
		// and RESPAWN the loop Remove had just dropped — the respawned
		// loop wrote new probes/alerts, repopulated statsCache, and then
		// logged FK errors once the sensor row finally went away.
		// 'deleting' is excluded from every state filter (syncSensors,
		// stats rescan, maintenance enter, ActiveSensorIDs) and from the
		// dashboard list, so the sensor is dead to the whole system for
		// the entire cascade window. History:
		// docs/DECISIONS.md → sensor-delete-deleting-state.
		if _, err := s.db.ExecContext(r.Context(), "UPDATE sensors SET state = 'deleting' WHERE id = ?", id); err != nil {
			respondInternal(w, "mark sensor deleting", err)
			return
		}
		// restoreState puts the sensor back to its pre-delete state if any
		// cascade step below fails, so a surviving sensor is never
		// stranded in 'deleting' (no loop, invisible to syncSensors,
		// pulses rejected) with no path back. A concurrent state PATCH
		// that landed in the window is lost — the operator's retry is the
		// expected next action either way.
		restoreState := func() {
			if _, err := s.db.ExecContext(r.Context(), "UPDATE sensors SET state = ? WHERE id = ?", curState, id); err != nil {
				log.Printf("delete sensor %s: restore state failed: %v", id, err)
			}
		}
		// Stop the probe loop FIRST so no new probe/event/alert rows land
		// mid-delete. If a delete below fails and the sensor survives,
		// restoreState revives it and syncSensors respawns the loop on
		// its next 5s pass — Remove only drops the in-memory loop +
		// state, not the DB row.
		s.probeWorker.Remove(id)
		// Batched deletes for the two large cascade tables (a 5s sensor's
		// probes table is ~17k rows) — the purgeOld idiom: each statement is
		// its own bounded autocommit, so the WAL write lock is held for
		// milliseconds per chunk instead of one long lock over the whole
		// cascade. The small cascade tables (sensor_tags, alert_state — a
		// few rows each) ride the final sensor-row DELETE's ON DELETE CASCADE.
		if _, err := deleteRowsBatched(r.Context(), s.db, "probes", "sensor_id = ?", []any{id}); err != nil {
			restoreState()
			respondInternal(w, "delete sensor "+id, err)
			return
		}
		if _, err := deleteRowsBatched(r.Context(), s.db, "events", "sensor_id = ?", []any{id}); err != nil {
			restoreState()
			respondInternal(w, "delete sensor "+id, err)
			return
		}
		if _, err := s.db.ExecContext(r.Context(), "DELETE FROM sensors WHERE id = ?", id); err != nil {
			restoreState()
			respondInternal(w, "delete sensor "+id, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// setSensorTagsInConn replaces the sensor's tags (DELETE + INSERTs) on the
// CALLER's pinned connection, for the PATCH sensor write path that runs
// inside a BEGIN IMMEDIATE transaction. A *sql.Tx from db.Begin can't join
// it because the transaction lives on the pinned connection, and
// db.SetSensorTags keeps its own transaction (so it can't join one either);
// that is why this in-conn twin lives here rather than in the store package.
// The caller's ctx is threaded through, so every statement on this path
// honors request cancellation, matching the ImmediateTx boundary.

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
		if errors.Is(err, errPulseBusy) {
			respondWithError(w, http.StatusTooManyRequests, "too many pulses in flight — try again in a moment")
			return
		}
		if errors.Is(err, errSensorDeleting) {
			respondWithError(w, http.StatusConflict, "sensor is being deleted")
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

func pulseResponse(o probeOutcome) map[string]any {
	var rttMs *float64
	if !o.lost {
		v := o.rttMs
		rttMs = &v
	}
	resp := map[string]any{
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
	if err := s.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM sensors WHERE id = ?", id).Scan(&exists); err != nil {
		// A DB error (canceled ctx, SQLITE_BUSY, I/O) is a transient 500,
		// not "sensor not found" — only a zero count means the sensor is
		// genuinely gone (the handleSensorByID/handleSensorPing contract).
		respondInternal(w, "sensor history existence "+id, err)
		return
	}
	if exists == 0 {
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
	respondWithJSON(w, http.StatusOK, map[string]any{
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
		if errors.Is(err, sql.ErrNoRows) {
			respondWithError(w, http.StatusNotFound, "sensor not found")
		} else {
			// A DB error (canceled ctx, SQLITE_BUSY, I/O) is a transient
			// 500, not "sensor not found" (the handleSensorByID contract).
			respondInternal(w, "clear history existence "+id, err)
		}
		return
	}

	var probes, events int64
	var err error
	// The two LARGE deletes run batched (the purgeOld idiom): one DELETE of
	// a long-lived sensor's rows would hold the WAL write lock for its whole
	// duration, stalling probe INSERTs and any concurrent reader up to the
	// 15s busy_timeout. Batching caps each statement at a few ms. Partial
	// completion is harmless — the target is a WIPE, so a retry just deletes
	// the remainder — so atomicity of these two is NOT worth the lock hold.
	// The small state-consistency steps below stay atomic: alert_state
	// removal and the status reset commit all-or-none (the old autocommit
	// code ignored their errors — the half-cleared bug the tx fixes).
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
	respondWithJSON(w, http.StatusOK, map[string]any{
		"sensor":  name,
		"cleared": map[string]int64{"probes": probes, "events": events},
	})
}

// deleteRowsBatched deletes a table's rows (optionally filtered) in
// purgeBatchSize chunks — the purgeOld idiom (probe.go): each statement is
// its own autocommit delete of a bounded row set, so the WAL write lock is
// held for milliseconds per statement instead of for a whole-million-row
// sweep (probe INSERTs and any concurrent reader stay responsive up to, but
// not through, the 15s busy_timeout). Returns the total rows deleted. The
// table/where strings are fixed call-site literals, never user input.
//
// The `id IN (SELECT id …)` shape is optimal as written (verified by
// EXPLAIN QUERY PLAN): both probes.id and events.id are
// INTEGER PRIMARY KEY — i.e. rowid aliases — so the outer delete already
// seeks by rowid (SEARCH … USING INTEGER PRIMARY KEY (rowid=?)) and the
// sensor_id-filtered subquery is a covering-index seek
// (SEARCH … USING COVERING INDEX idx_*_sensor_ts (sensor_id=?)), NOT a
// PK-B-tree or full-table scan. Rewriting it as `rowid IN (SELECT rowid …)`
// is a byte-identical no-op (id IS rowid here), so the `id` form is kept
// for clarity.
// deleteRowsBatched: the batched cascade-delete as a var so a test can
// force the post-mark failure path (sensor marked 'deleting' → batched
// delete failed → compensating state restore) — the same seam pattern as
// enterMaintenance/leaveMaintenance above.

var deleteRowsBatched = func(ctx context.Context, db *store.Store, table, where string, args []any) (int64, error) {
	w := ""
	if where != "" {
		w = " WHERE " + where
	}
	q := "DELETE FROM " + table + " WHERE id IN (SELECT id FROM " + table + w + " LIMIT ?)"
	// The argument slice is built ONCE per call, not per batch iteration
	//: a full-table wipe loops 1.7M/purgeBatchSize
	// times, and the old in-loop append(append([]any{}, args...),
	// purgeBatchSize) allocated a fresh slice every iteration. ExecContext
	// only reads the args, so the hoisted slice is safe to reuse.
	qArgs := append(append([]any{}, args...), purgeBatchSize)
	var total int64
	for {
		res, err := db.ExecContext(ctx, q, qArgs...)
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
	// handleSensorClearHistory for the reasoning. At
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
	respondWithJSON(w, http.StatusOK, map[string]any{
		"cleared": map[string]int64{"probes": probes, "events": events},
	})
}

// cloneMaxAttempts bounds the INSERT retries when concurrent clones race for
// the same name.

const cloneMaxAttempts = 5

// globEscaper quotes the GLOB wildcards so a base name is matched
// literally. validSensorName is a blacklist, so [ * ? are legal name
// characters; an unescaped pattern distorts the taken-name set ("[b]"
// becomes a character class, an unterminated '[' never matches).

var globEscaper = strings.NewReplacer("[", "[[]", "*", "[*]", "?", "[?]")

// Sentinel errors from the PATCH sensor write transaction: the re-validation runs inside the BEGIN IMMEDIATE tx, so its
// failures are returned as sentinels and mapped to HTTP codes by the
// handler (the response can't be written from inside the closure without
// tangling the commit/rollback path).

var (
	errPatchSensorGone                = errors.New("sensor not found")
	errPatchTargetNotURL              = errors.New("target must be a URL")
	errPatchTargetInvalid             = errors.New("target is invalid for the probe type")
	errPatchTimeoutExceedsInterval    = errors.New("timeout exceeds interval")
	errPatchDownAfterExceedsRetention = errors.New("down_after × interval_s exceeds probe retention")
	errPatchNameConflict              = errors.New("sensor name already exists")
)

// patchScanHook is a TEST SEAM: when non-nil, it transforms the
// PATCH-sensor in-tx sensor-read scan error before the handler classifies
// it, so a non-ErrNoRows failure (SQLITE_BUSY, canceled context, I/O) is
// exercisable without a real DB fault. Production always leaves it nil.

var patchScanHook func(err error) error

// handleSensorClone creates a copy of a sensor with a new unique name
// (name-copy, name-copy2, ...). The clone starts PAUSED, like a new sensor.

func (s *Server) handleSensorClone(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := r.PathValue("id")

	var src Sensor
	err := scanSensorRow(s.db.QueryRowContext(r.Context(), "SELECT "+sensorCols+" FROM sensors WHERE id = ?", id), &src)
	if err != nil {
		// Existence-check contract (pinned by
		// TestSensorExistenceCheckDistinguishesErrors): only sql.ErrNoRows
		// means "sensor not found". A canceled ctx, SQLITE_BUSY, or I/O
		// failure is a transient server error — it must not read as
		// "the sensor was deleted", and must reach the service log.
		// (The same handler's later queries already answered these with
		// respondInternal; this was the last collapsed site of the class.)
		if errors.Is(err, sql.ErrNoRows) {
			respondWithError(w, http.StatusNotFound, "sensor not found")
		} else {
			respondInternal(w, "clone sensor "+id, err)
		}
		return
	}
	src.Tags, err = s.db.SensorTags(r.Context(), id)
	if err != nil {
		respondInternal(w, "clone sensor tags "+id, err)
		return
	}

	// The clone is a NEW write, so it must honor the CURRENT new-write
	// floors/caps — the same ones the create and PATCH paths enforce
	// (minIntervalS, the timeout/loss/down/spike ranges, and the
	// timeout <= interval*1000 cross-field rule) — NOT copy the source's
	// values verbatim. A legacy row can hold out-of-range values: those
	// floors were added after the row existed and are deliberately not
	// migrated (see minIntervalS — "a legacy 1s sensor keeps running until
	// the operator edits it"). Copying verbatim let an operator multiply a
	// legacy 1s sensor (or any out-of-range param) indefinitely via clone,
	// bypassing the API floor. Clamp each copied
	// numeric into its valid range; the clone starts PAUSED, so the operator
	// reviews the normalized values before resuming it.
	spec := sensorSpec{
		Name:      src.Name,
		Target:    src.Target,
		Type:      src.Type,
		Tags:      src.Tags,
		IntervalS: src.IntervalS,
		TimeoutMS: src.TimeoutMS,
		LossWarn:  src.LossWarn,
		DownAfter: src.DownAfter,
		SpikeMult: src.SpikeMult,
	}
	spec.clamp()

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
	// The base name is GLOB-escaped (globEscaper) so it matches
	// literally. The old exact-match loop probed each candidate
	// individually, so metacharacters there were harmless; under the
	// one-query design an unescaped under-match (an unterminated '['
	// never matches, "[b]" becomes a class) empties the taken set, every
	// existing clone then burns one of the cloneMaxAttempts INSERT
	// retries, and the 6th clone of a base like "nas[01]" died with 409
	// "too many clones" while -copy6..-copy100 sat free.
	// Over-matching was benign, so this closed the only half
	// that distorted the outcome; the UNIQUE index stays the arbiter for
	// the concurrent-race retries.
	cloneID := store.NewID()
	now := store.Now()
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
	rows, err := s.db.QueryContext(r.Context(), "SELECT name FROM sensors WHERE name GLOB ?", globEscaper.Replace(cloneBase)+"-copy*")
	if err != nil {
		respondInternal(w, "clone sensor "+id, err)
		return
	}
	defer rows.Close()
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
				cloneID, name, spec.Target, spec.Type, spec.IntervalS, spec.TimeoutMS, spec.LossWarn, spec.DownAfter, spec.SpikeMult, now); err != nil {
				return err
			}
			if len(spec.Tags) > 0 {
				return setSensorTagsInConn(r.Context(), c, cloneID, spec.Tags)
			}
			return nil
		})
		if err == nil {
			created = true
			break
		}
		// Only a name collision (UNIQUE-constraint violation, by result
		// code) is retryable; anything else is a real failure.
		if !isUniqueConstraintErr(err) {
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
		ID: cloneID, Name: name, Target: spec.Target, Type: spec.Type, Tags: spec.Tags,
		IntervalS: spec.IntervalS, TimeoutMS: spec.TimeoutMS,
		LossWarn: spec.LossWarn, DownAfter: spec.DownAfter, SpikeMult: spec.SpikeMult,
		State: "paused", Status: "up", CreatedAt: now,
	})
}

// handleTags lists every tag in use (with sensor counts) and supports
// DELETE for removing a tag from all its sensors.

func (s *Server) handleTags(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tags, err := s.db.AllTags(r.Context())
		if err != nil {
			// The query result IS the payload: a failure must surface as a
			// 500, not render as an empty tag fleet
			respondInternal(w, "list tags", err)
			return
		}
		respondWithJSON(w, http.StatusOK, tags)
		return
	case http.MethodDelete:
		// Destructive and fleet-wide: strips the tag from EVERY sensor and
		// respawns every affected probe loop, so it is admin-only (like the
		// other fleet-wide mutations, e.g. DELETE /api/history).
		if s.auth.Enabled() && !s.auth.IsAdmin(s.sessionFrom(r)) {
			respondWithError(w, http.StatusForbidden, "admin only")
			return
		}
		tag := r.URL.Query().Get("tag")
		if tag == "" {
			respondWithError(w, http.StatusBadRequest, "tag query parameter is required")
			return
		}
		// Collect the tagged sensors atomically WITH the delete: each
		// probe loop holds a spawn-time copy of its tag set (alert
		// routing reads c.tags from that copy), so every affected loop
		// must be respawned to pick up the new set. DELETE ... RETURNING
		// hands back exactly the rows removed — no SELECT→DELETE window
		// in which a sensor gaining/losing the tag could stale the list
		// (a loop keeping alert routing for a tag it no longer has).
		// History: docs/DECISIONS.md → db-ctx-torn-reads-resources
		tagged, err := s.db.DeleteTagReturning(r.Context(), tag)
		if err != nil {
			respondInternal(w, "delete tag "+tag, err)
			return
		}
		// One Restart per tagged sensor is deliberate, not an oversight.
		// Each Restart does a NON-BLOCKING send on the buffered-1 syncReq,
		// so the N signals coalesce into a single syncSensors pass: this
		// loop is fast (map ops, no I/O) and completes before Run can
		// consume the buffer. Even if Run wakes mid-loop, the extra pass is
		// ONE idempotent full-fleet reconciliation (the buffer drains once
		// per syncSensors cycle, so it's bounded to ~1, not N) and the
		// final state is correct. A RestartMany batch (one lock + one
		// signal) would save at most that one rare extra pass for a rare
		// operation (tag delete) — not worth the added surface.
		for _, id := range tagged {
			s.probeWorker.Restart(id)
		}
		respondWithJSON(w, http.StatusOK, map[string]any{"status": "deleted", "sensors_updated": len(tagged)})
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
	var bucketSecs, rangeSecs int
	switch r.URL.Query().Get("range") {
	case "24h":
		bucketSecs, rangeSecs = 900, 24*3600
	case "1h":
		bucketSecs, rangeSecs = 60, 3600
	default:
		respondWithError(w, http.StatusBadRequest, "range must be 1h or 24h")
		return
	}

	var exists int
	if err := s.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM sensors WHERE id = ?", id).Scan(&exists); err != nil {
		// A DB error (canceled ctx, SQLITE_BUSY, I/O) is a transient 500,
		// not "sensor not found" — only a zero count means the sensor is
		// genuinely gone (the handleSensorByID/handleSensorPing contract).
		respondInternal(w, "sensor graph existence "+id, err)
		return
	}
	if exists == 0 {
		respondWithError(w, http.StatusNotFound, "sensor not found")
		return
	}

	// Serve the buckets from the in-memory stats series (raw entries +
	// per-minute buckets) instead of a per-request SQL aggregate (finding
	// #8): the 24h graph folds the minute buckets into 15-min buckets and
	// the 1h graph reads the raw hour, so neither touches the probes table.
	// The series is the same data the warm-up loaded (the full 24h UNION),
	// so the buckets match what the SQL path returned — including the
	// epoch-based window (the series only holds entries within 24h of the
	// newest probe) and the `manual = 0` exclusion (graphPoints skips
	// manual rows). A sensor not in the cache (added after boot, before
	// its first probe) has no series and serves an empty graph — the same
	// as a zero-probe window. The cache lock lives inside ProbeWorker.Graph
	// (nit: handlers must not touch statsMu/statsCache directly).
	points := s.probeWorker.Graph(id, bucketSecs, rangeSecs)
	if points == nil {
		points = []GraphPoint{}
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

	respondWithJSON(w, http.StatusOK, map[string]any{
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
		// must not be able to erase the audit/event log.
		// The GET branch below stays open to any session:
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
		respondWithJSON(w, http.StatusOK, map[string]any{"status": "cleared", "events_deleted": n})
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

func normalizeProbeType(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "http":
		return "http"
	case "tcp":
		return "tcp"
	default:
		return "icmp"
	}
}
