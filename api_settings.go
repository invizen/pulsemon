package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"pulsemon/internal/store"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

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

// settingsPayload assembles the GET /api/settings body (and the PUT
// response echo). All settings reads go through GetSettingErr:
// the swallow-to-"" shape made a transient DB failure render as
// CONCRETE DEFAULTS (alert_scope "all", realert_min 30, maintenance off)
// with a 200 — and the dashboard's alerts form seeds itself from this
// payload and PUTs the fields back on save, so a swallowed read could be
// written back as the operator's intent, overwriting the real settings.
// A read failure is now an error: the handlers 500 and the UI shows
// "Failed to load settings" instead of an editable form of fabrications.
func (s *Server) settingsPayload() (map[string]any, error) {
	// ONE settings snapshot, not six: each GetSettingErr was its own
	// query on its own pool connection, so a concurrent PUT
	// /api/settings could land between reads and mix pre- and
	// post-update values in one payload (e.g. alert_scope "tagged"
	// beside a stale empty alert_filter). GetAllSettings is a single
	// statement — one consistent row-set, one round trip. History:
	// docs/DECISIONS.md → db-ctx-torn-reads-resources
	settings, err := s.db.GetAllSettings()
	if err != nil {
		return nil, fmt.Errorf("read settings: %w", err)
	}
	scope := settings["alert_scope"]
	if scope == "" {
		scope = "all"
	}
	filter := []string{}
	if f := settings["alert_filter"]; f != "" {
		_ = json.Unmarshal([]byte(f), &filter)
	}
	if filter == nil {
		filter = []string{}
	}
	realert := 30
	if rv := settings["realert_min"]; rv != "" {
		if n, err := strconv.Atoi(rv); err == nil && n >= 0 && n <= 1440 {
			realert = n
		}
	}
	// Legacy single-webhook fields stay for backward compat with older
	// dashboards (and the env-configured Google Chat URL, which has no
	// settings row). The multi-provider "providers" array is the real data.
	chatURL := settings["google_chat_url"]
	chatSource := "none"
	if chatURL != "" {
		chatSource = "dashboard"
	} else if os.Getenv("GOOGLE_CHAT_WEBHOOK_URL") != "" {
		chatURL = os.Getenv("GOOGLE_CHAT_WEBHOOK_URL")
		chatSource = "env"
	}
	maint := settings["maintenance_mode"]
	unauth := settings["allow_unauth_update"]
	// The providers array is built fail-loud too: it
	// embeds every provider's enabled/has_url/url/extra reads, and a
	// swallowed DB error there answered 200 with silent "false" provider
	// states inside an otherwise fail-loud payload.
	providers, err := s.probeWorker.providerStatuses()
	if err != nil {
		return nil, fmt.Errorf("read provider statuses: %w", err)
	}
	return map[string]any{
		"webhook_url":         webhookMasked(chatURL),
		"webhook_configured":  chatURL != "",
		"source":              chatSource,
		"providers":           providers,
		"alert_scope":         scope,
		"alert_filter":        filter,
		"realert_min":         realert,
		"maintenance_mode":    maint == "1",
		"allow_unauth_update": unauth == "1",
		"tls":                 s.tlsPayload(),
	}, nil
}

func (s *Server) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	payload, err := s.settingsPayload()
	if err != nil {
		respondInternal(w, "settings payload", err)
		return
	}
	respondWithJSON(w, http.StatusOK, payload)
}

// enterMaintenance / leaveMaintenance: the two maintenance-mode store calls
// as vars so a test can force the post-commit failure path:
// settings tx committed, maintenance tx failed → the
// alert snapshot must still reload. Production is a plain method call
// (same seam pattern as deliverDestinations in alerts.go).
var enterMaintenance = func(db *store.Store, ctx context.Context) ([]string, error) {
	return db.EnterMaintenanceWithFreshSnapshot(ctx)
}

var leaveMaintenance = func(db *store.Store, ctx context.Context) ([]string, error) {
	return db.LeaveMaintenanceFromSnapshot(ctx)
}

// settingsPutProvider is one provider entry in the PUT /api/settings body.
// URL is a pointer so nil = "don't touch this field" (the dashboard only
// sends what changed); "" clears; a non-empty value is validated first.
type settingsPutProvider struct {
	Kind    string            `json:"kind"`
	URL     *string           `json:"url"`     // nil = keep existing; "" = clear; full URL = set
	Enabled *bool             `json:"enabled"` // nil = keep; else set
	Extra   map[string]string `json:"extra"`   // non-URL fields (e.g. telegram chat_id)
}

// settingsPutReq is the PUT /api/settings body. Every field is a pointer so
// nil = "keep the stored value" (a partial save no longer resets the others);
// a non-nil value is validated and written.
type settingsPutReq struct {
	WebhookURL  *string               `json:"webhook_url"` // legacy alias for the google_chat URL
	Providers   []settingsPutProvider `json:"providers"`
	AlertScope  *string               `json:"alert_scope"`  // nil = keep; else all|tags|sensors
	AlertFilter *[]string             `json:"alert_filter"` // nil = keep; else set
	RealertMin  *int                  `json:"realert_min"`  // nil = keep; 0 = alert once only
	MaintMode   *bool                 `json:"maintenance_mode"`
	AllowUnauth *bool                 `json:"allow_unauth_update"`
}

// validateSettingsPut checks the ENTIRE request before any write and returns
// the pre-flight settings snapshot (pre) plus the per-provider stored extras
// the apply pass reuses, so validation and apply evaluate the same effective
// state (the two paths can't drift). It 400s w and returns ok=false on the
// first invalid field; the store is untouched. History:
// docs/DECISIONS.md → settings-put-validate-first
func (s *Server) validateSettingsPut(w http.ResponseWriter, r *http.Request, req *settingsPutReq) (pre map[string]string, storedExtras []map[string]string, ok bool) {
	// allow_unauth_update re-allows the in-dashboard self-update button on an
	// auth-off install (update_api.go) — i.e. it hands any LAN host the power
	// to download a binary, overwrite the running one, and restart the service.
	// It must therefore be changeable ONLY while an account exists (auth on):
	// with auth off, requireAdmin/requireAuth stand down, so without this guard
	// any LAN host could PUT {"allow_unauth_update":true} and then POST
	// /api/update. The stored VALUE is untouched — an
	// install that already has it on keeps working; only the CHANGE is gated.
	// A save that does NOT send the field (the general "save alerts" flow) is
	// unaffected. The in-tx user-count re-check below covers this guard's
	// Enabled() cache staleness window (out-of-band last-account removal).
	if req.AllowUnauth != nil && !s.auth.Enabled() {
		respondWithError(w, http.StatusForbidden, "allow_unauth_update can only be changed while authentication is enabled")
		return nil, nil, false
	}

	// Validate EVERYTHING before any write: the old code applied provider
	// writes as it went and reset alert_scope/alert_filter unconditionally
	// (a partial save like {"realert_min":10} silently wiped the tag
	// routing), and one bad field could leave a partial save behind. Now a
	// 400 leaves the store exactly as it was.
	if req.AlertScope != nil && *req.AlertScope != "all" && *req.AlertScope != "tags" && *req.AlertScope != "sensors" {
		respondWithError(w, http.StatusBadRequest, "alert_scope must be all, tags or sensors")
		return nil, nil, false
	}
	if req.RealertMin != nil && (*req.RealertMin < 0 || *req.RealertMin > 1440) {
		respondWithError(w, http.StatusBadRequest, "realert_min must be 0-1440 (0 = alert once only)")
		return nil, nil, false
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
			return nil, nil, false
		}
		cleaned := make([]string, 0, len(*req.AlertFilter))
		seen := make(map[string]bool, len(*req.AlertFilter))
		for _, item := range *req.AlertFilter {
			item = strings.TrimSpace(item)
			if item == "" || utf8.RuneCountInString(item) > 60 || !validSensorName(item) {
				respondWithError(w, http.StatusBadRequest, "invalid entry in alert_filter")
				return nil, nil, false
			}
			if !seen[item] {
				seen[item] = true
				cleaned = append(cleaned, item)
			}
		}
		req.AlertFilter = &cleaned
	}
	// One pre-flight snapshot of the settings table for EVERY pre-tx read
	// in this handler (dead-filter guard, provider stored-state,
	// maintenance pre-check), fail-loud: these reads
	// used the error-swallowing GetSetting, so a transient SQLite failure
	// silently MISCOMPUTED the guard inputs — stored scope read as ""
	// let the guard wave a scope=tags + filter=[] save through (silent
	// stop of ALL alerting, the exact state the guard exists to refuse),
	// and a maintenance re-enable whose stored mode read as "off" took a
	// FRESH snapshot, replacing the entry-time restore set. The bulk read
	// also keeps every pre-check on a single commit of the settings
	// table (same reason as the snapshot/statuses reads in alerts.go).
	pre, err := getAllSettings(s.db)
	if err != nil {
		respondInternal(w, "read current settings", err)
		return nil, nil, false
	}
	// Reject the dead-alert state on save: with scope=tags/sensors and an
	// EMPTY effective filter, shouldAlert matches no sensor — the monitor
	// silently stops alerting for everything, the worst failure mode for
	// a monitor. The UI can produce it (scope switched to "tags" with no
	// tag selected stores alert_filter=[]), so the server refuses the
	// state. Effective = incoming value if sent, else stored — the same
	// read-then-400 posture as the rest of this handler, before any write.
	effScope := pre["alert_scope"]
	if req.AlertScope != nil {
		effScope = *req.AlertScope
	}
	if effScope == "" {
		effScope = "all"
	}
	if effScope != "all" {
		effFilter := []string{}
		if req.AlertFilter != nil {
			effFilter = *req.AlertFilter
		} else if f := pre["alert_filter"]; f != "" {
			_ = json.Unmarshal([]byte(f), &effFilter)
		}
		if len(effFilter) == 0 {
			respondWithError(w, http.StatusBadRequest, "alert_filter cannot be empty when alert_scope is tags or sensors")
			return nil, nil, false
		}
	}
	// One stored-state snapshot per provider, taken from the pre-flight
	// bulk read above (BEFORE the tx) and reused by the apply pass below,
	// so validation and apply evaluate the same effective state and the
	// two paths can't drift. (A concurrent settings PUT can interleave
	// between the snapshot and the tx — the same read-then-write window
	// the rest of this handler has; the in-tx SMTP guard is the backstop
	// for the one rule where stored state is security-relevant.)
	storedExtras = make([]map[string]string, len(req.Providers))
	for i, prov := range req.Providers {
		storedExtras[i] = providerExtrasFrom(pre, prov.Kind)
		if err := validateProviderUpdate(prov.Kind, prov.URL, prov.Enabled, prov.Extra, storedExtras[i]); err != nil {
			respondWithError(w, http.StatusBadRequest, err.Error())
			return nil, nil, false
		}
	}
	if req.WebhookURL != nil {
		if err := validateProviderUpdate("google_chat", req.WebhookURL, nil, nil, nil); err != nil {
			respondWithError(w, http.StatusBadRequest, err.Error())
			return nil, nil, false
		}
	}
	return pre, storedExtras, true
}

// applySettingsTx writes the validated settings in ONE transaction
// (provider writes first, then only the routing fields that were sent;
// nil means keep, so a partial save no longer resets routing) and
// commits. It pins the write lock before any read so a concurrent PUT
// serializes (wait-then-400) instead of failing with a spurious
// SQLITE_BUSY_SNAPSHOT 500. Returns false after 400/500ing w; the
// deferred rollback leaves the store untouched on any error path.
func (s *Server) applySettingsTx(w http.ResponseWriter, r *http.Request, req *settingsPutReq, storedExtras []map[string]string) bool {
	// All valid: apply. Provider writes first (the dashboard saves them
	// alongside the routing fields), then ONLY the routing fields that were
	// sent — nil means keep, so a partial save no longer resets routing.
	// The whole apply phase is ONE transaction: validation can't rule out a
	// mid-sequence write failure (disk full, SQLITE_BUSY), and the old
	// autocommit writes left a partial save behind a 500. Maintenance mode below stays outside — each transition has its own atomic
	// snapshot transaction (EnterMaintenanceWithFreshSnapshot /
	// LeaveMaintenanceFromSnapshot).
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondInternal(w, "begin settings update", err)
		return false
	}
	defer tx.Rollback() // no-op after Commit succeeds
	// Pin the write lock BEFORE anything reads: a
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
		return false
	}
	for i, prov := range req.Providers {
		if err := applyProviderUpdateInTx(r.Context(), tx, prov.Kind, prov.URL, prov.Enabled, prov.Extra, storedExtras[i]); err != nil {
			if errors.Is(err, errSMTPNoneWithCreds) {
				// Reachable now (in-tx re-check): a concurrent admin PUT
				// committed between this request's pre-flight validation
				// and its write tx, so the EFFECTIVE state this save would
				// complete violates the rule. 400; deferred rollback leaves
				// the store untouched.
				respondWithError(w, http.StatusBadRequest, err.Error())
				return false
			}
			// Other validation errors stay unreachable after the pass
			// above; a 500 covers write failures.
			respondInternal(w, "apply provider "+prov.Kind, err)
			return false
		}
	}
	if req.WebhookURL != nil {
		if err := applyProviderUpdateInTx(r.Context(), tx, "google_chat", req.WebhookURL, nil, nil, nil); err != nil {
			respondInternal(w, "apply provider google_chat", err)
			return false
		}
	}
	if req.RealertMin != nil {
		if err := store.SetSettingInTx(r.Context(), tx, "realert_min", strconv.Itoa(*req.RealertMin)); err != nil {
			respondInternal(w, "save setting realert_min", err)
			return false
		}
	}
	if req.AlertScope != nil {
		if err := store.SetSettingInTx(r.Context(), tx, "alert_scope", *req.AlertScope); err != nil {
			respondInternal(w, "save setting alert_scope", err)
			return false
		}
	}
	if req.AlertFilter != nil {
		filterJSON, _ := json.Marshal(*req.AlertFilter)
		if err := store.SetSettingInTx(r.Context(), tx, "alert_filter", string(filterJSON)); err != nil {
			respondInternal(w, "save setting alert_filter", err)
			return false
		}
	}
	if req.AllowUnauth != nil {
		// In-tx re-check: the pre-flight guard's s.auth.Enabled() is a
		// 2s-TTL cache — an out-of-band last-account removal stays
		// invisible to it (stale true), and with 0 users requireAuth
		// stands down, so the stale window would accept an
		// unauthenticated change of the unauth-update privilege. The
		// count under the write-lock pin is the authoritative gate for
		// the write (a concurrent removal serializes behind the pin).
		var userCount int
		if err := tx.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM users").Scan(&userCount); err != nil {
			respondInternal(w, "check user count", err)
			return false
		}
		if userCount == 0 {
			respondWithError(w, http.StatusForbidden, "allow_unauth_update can only be changed while authentication is enabled")
			return false
		}
		val := "0"
		if *req.AllowUnauth {
			val = "1"
		}
		if err := store.SetSettingInTx(r.Context(), tx, "allow_unauth_update", val); err != nil {
			respondInternal(w, "save setting allow_unauth_update", err)
			return false
		}
	}
	if err := tx.Commit(); err != nil {
		respondInternal(w, "commit settings update", err)
		return false
	}
	return true
}

// applyMaintenanceTransition runs the maintenance-mode transition AFTER the
// settings tx commits. It takes the pre-check inputs (maintAlreadyOn and the
// pre-snapshot maintIDs) and 500s w on a failed maintenance tx (the settings
// save already committed). Returns false after responding; the caller returns
// so the echo/read-back is skipped.
func (s *Server) applyMaintenanceTransition(w http.ResponseWriter, r *http.Request, maintMode *bool, maintAlreadyOn bool, maintIDs []string) bool {
	if maintMode != nil {
		if *maintMode {
			if maintAlreadyOn {
				// Already in maintenance: keep the ORIGINAL snapshot and
				// the existing pause set (re-snapshotting would drop the
				// sensors resumed during maintenance from the restore
				// set). Nothing to write.
				log.Printf("API: maintenance mode already ON (snapshot preserved)")
			} else {
				// Entering maintenance (off→on): pause + snapshot + mode
				// flag in ONE transaction
				// (EnterMaintenanceWithFreshSnapshot). The snapshot is read
				// INSIDE the tx, so a sensor activated between the
				// pre-check above and the pause cannot escape it and keep
				// probing under mode=ON; a crash cannot leave sensors
				// paused without the mode flag (or vice versa).
				ids, err := enterMaintenance(s.db, r.Context())
				if err != nil {
					respondInternal(w, "enter maintenance mode", err)
					return false
				}
				maintIDs = ids
				// Swap the alert snapshot BEFORE the pause is visible to the
				// loops: in-flight probes that finish after the swap read
				// maintenance:true from the fresh snapshot and stay silent.
				// The old order reloaded only in the handler-exit defer, so
				// those probes fired under a stale maintenance:false — an
				// alert during a maintenance the operator just asked for.
				// History: docs/DECISIONS.md → maintenance-transition-ordering.
				s.probeWorker.reloadAlertSettings()
				// Flip the in-memory pause flag immediately — the same
				// SetPaused fast path the single-sensor PATCH uses: without
				// it, each sensor lands up to one extra probe row (and a
				// possible transition event) in the window before the next
				// 5s syncSensors tick, breaking "paused = no packets, no
				// rows, no alerts" (probe.go sensorLoop).
				for _, id := range maintIDs {
					s.probeWorker.SetPaused(id, true)
				}
				// Paused sensors don't probe, so their alert state can't
				// drift; reset it now so resume doesn't instantly re-alert
				// on a stale bad state.
				s.probeWorker.ResetAlertStates()
				if len(maintIDs) > 0 {
					log.Printf("API: maintenance mode ON (%d sensors paused)", len(maintIDs))
				} else {
					// A concurrent enter already took the snapshot (the
					// in-tx mode re-check no-op'd this one), or no sensors
					// were active — the existing snapshot stands.
					log.Printf("API: maintenance mode ON (no additional sensors paused — snapshot preserved)")
				}
			}
		} else {
			// Leaving maintenance: reactivate exactly the snapshot set —
			// sensors paused BEFORE maintenance (not in the snapshot) or
			// added during it stay paused, and a snapshot sensor the user
			// paused DURING maintenance is resumed with the rest. The
			// snapshot is read INSIDE the resume tx
			// (LeaveMaintenanceFromSnapshot): a failed read/decode 500s
			// with mode still ON and the snapshot intact — banner up,
			// alerts gated, the operator's retry can succeed. History:
			// docs/DECISIONS.md → maintenance-leave-fails-loud.
			ids, err := leaveMaintenance(s.db, r.Context())
			if err != nil {
				respondInternal(w, "leave maintenance mode", err)
				return false
			}
			// Reset the alert state and swap the alert snapshot BEFORE
			// the resume: SetPaused(false) kicks the loops, and a fast
			// sensor recovering in the old window (between the resume
			// and the handler-exit deferred reload) read a stale
			// maintenance:true from the snapshot and dropped its
			// recovery alert permanently. The sensors are still paused
			// here, so nothing can recover before the gate opens.
			// History: docs/DECISIONS.md → maintenance-transition-ordering.
			s.probeWorker.ResetAlertStates()
			s.probeWorker.reloadAlertSettings()
			// Flip the in-memory unpause immediately (symmetric fast path, see
			// the enable side above): without this the resumed sensors wait up
			// to 5s for syncSensors before their next probe.
			for _, id := range ids {
				s.probeWorker.SetPaused(id, false)
			}
			log.Printf("API: maintenance mode off (%d sensors resumed)", len(ids))
		}
	}
	return true
}

func (s *Server) handleSettingsPut(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req settingsPutReq
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		code, msg := requestBodyErr(err)
		respondWithError(w, code, msg)
		return
	}

	pre, storedExtras, ok := s.validateSettingsPut(w, r, &req)
	if !ok {
		return
	}
	// Maintenance-mode entry validation runs BEFORE the settings tx
	// opens: "no active sensors to pause" is a derived check, and a 400
	// must leave the store exactly as it was — the old order committed
	// the other settings first, then 400'd on the empty snapshot. The ids
	// read here are the 400 pre-check only; the authoritative snapshot
	// is taken inside the pause tx below.
	//
	// Re-enable (mode already ON) takes NO new snapshot: a fresh snapshot
	// would capture the currently-ACTIVE set, which excludes any sensor
	// the operator resumed during maintenance — those sensors would then
	// be stranded paused forever, because resume restores only the
	// snapshot.
	maintAlreadyOn := pre["maintenance_mode"] == "1"
	var maintIDs []string
	if req.MaintMode != nil && *req.MaintMode && !maintAlreadyOn {
		ids, err := s.db.ActiveSensorIDs(r.Context())
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

	if !s.applySettingsTx(w, r, &req, storedExtras) {
		return
	}
	// Swap the alert settings snapshot on EVERY path past the commit —
	// including the two maintenance-tx 500 returns below, so a PUT that
	// committed provider/routing/realert_min changes but failed on the
	// maintenance tx never leaves pw.alertCfg stale until the next
	// successful save. The alert hot path (alertsEnabled, shouldAlert,
	// realertMin, resolveDestinations) reads this snapshot lock-free;
	// reloadAlertSettings keeps the last good snapshot on a read error,
	// so a hiccup here leaves the previous snapshot in place rather than
	// installing a half-read state. History: docs/DECISIONS.md →
	// alert-settings-snapshot, settings-put-snapshot-reload-deferred.
	// The maintenance transitions below ALSO reload explicitly at the
	// point their pause/resume ordering requires it; this defer is then
	// an idempotent re-read of the same committed state.
	defer s.probeWorker.reloadAlertSettings()
	if !s.applyMaintenanceTransition(w, r, req.MaintMode, maintAlreadyOn, maintIDs) {
		return
	}
	// (The alert settings snapshot was already reloaded by the defer after
	// the settings tx committed — see there.)
	echo, err := s.settingsPayload()
	if err != nil {
		// The save committed; only the read-back echo failed. Say so with
		// a 500 (the write IS durable) rather than echoing fabricated
		// defaults the UI would adopt as truth
		respondInternal(w, "settings echo", err)
		return
	}
	// Log the EFFECTIVE stored values from the echo (the request fields are
	// pointers: a partial save leaves the others untouched). Sourcing the
	// log from echo drops three redundant GetSetting re-reads —
	// settingsPayload() just read those exact keys — and logs the
	// validated/defaulted values (scope "all", realert 0-1440 default 30,
	// filter count) the alert hot path will actually use, instead of raw
	// stored strings an out-of-band edit could have left inconsistent.
	scopeLog, _ := echo["alert_scope"].(string)
	filterLog, _ := echo["alert_filter"].([]string)
	realertLog, _ := echo["realert_min"].(int)
	log.Printf("API: settings updated (scope=%s filter=%d realert=%dm)", scopeLog, len(filterLog), realertLog)
	respondWithJSON(w, http.StatusOK, echo)
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
// effective state of partial updates. Unknown kinds return nil. The read
// is fail-loud: this snapshot feeds the effective-
// state validation, so a swallowed DB failure must not degrade it to
// "nothing stored". The settings-PUT path shares its one bulk pre-flight
// read via providerExtrasFrom; this is the standalone twin.
func (s *Server) storedProviderExtra(kind string) (map[string]string, error) {
	m, err := getAllSettings(s.db)
	if err != nil {
		return nil, err
	}
	return providerExtrasFrom(m, kind), nil
}

// providerExtrasFrom filters a settings snapshot down to a provider's
// extra keys (the pure half of storedProviderExtra).
func providerExtrasFrom(m map[string]string, kind string) map[string]string {
	keys, ok := extraFields[kind]
	if !ok {
		return nil
	}
	out := make(map[string]string, len(keys))
	for k := range keys {
		out[k] = m[kind+"_"+k]
	}
	return out
}

// errSMTPNoneWithCreds: the tls_mode=none-with-credentials rejection. A
// sentinel (not an inline error) so the settings PUT can map it to 400
// even when it surfaces from the IN-TX re-check.
var errSMTPNoneWithCreds = errors.New("smtp tls_mode=none cannot use credentials (clear username/password)")

// guardSMTPNoCredsOverTLSInTx re-applies the tls_mode=none + credentials
// rule against the LIVE in-tx settings snapshot (found independently by two
// review streams): the handler's pre-flight guard
// evaluated the EFFECTIVE state against a PRE-BeginTx read, so two
// concurrent admin PUTs — one setting tls_mode=none, one storing
// credentials — each passed against the pre-other-commit snapshot and
// JOINTLY committed none+credentials (the runtime send guard still
// refuses to send, so the failure is broken config, not a plaintext
// leak). SQLite serializes write transactions, so the later committer's
// in-tx read sees the earlier write and takes the 400 with the store
// untouched. Mask semantics mirror the write path below: a masked
// incoming password means "keep stored", i.e. credential PRESENT.
//
// ctx bounds every in-tx read (same request-context contract as the writes).
// Read failures FAIL CLOSED: sql.ErrNoRows means "key absent → empty value"
// (normal on a fresh DB), any other scan error is returned, so the guard
// can never answer "no stored credentials" off a read that never ran (a
// canceled ctx, disk I/O) and wave tls_mode=none through over real ones.
func guardSMTPNoCredsOverTLSInTx(ctx context.Context, tx *sql.Tx, incoming map[string]string) error {
	stored := func(k string) (string, error) {
		var v string
		err := tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE setting_key = ?", "smtp_"+k).Scan(&v)
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		return v, nil
	}
	effTLS := strings.TrimSpace(incoming["tls_mode"])
	if _, ok := incoming["tls_mode"]; !ok {
		v, err := stored("tls_mode")
		if err != nil {
			return err
		}
		effTLS = strings.TrimSpace(v)
	}
	if effTLS != "none" {
		return nil
	}
	credPresent := func(k string) (bool, error) {
		if v, ok := incoming[k]; ok {
			if k == "password" && v == "••••••••" { // mask = keep stored
				p, err := stored("password")
				if err != nil {
					return false, err
				}
				return p != "", nil
			}
			return v != "", nil
		}
		v, err := stored(k)
		if err != nil {
			return false, err
		}
		return v != "", nil
	}
	userHas, err := credPresent("username")
	if err != nil {
		return err
	}
	if userHas {
		return errSMTPNoneWithCreds
	}
	passHas, err := credPresent("password")
	if err != nil {
		return err
	}
	if passHas {
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
	// the plain Begin() stays and statements run under context.Background()
	// (the HTTP save path uses BeginTx in handleSettingsPut).
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Standalone entry point: read the stored snapshot fresh (there is no
	// pre-tx validation pass to share one with), fail-loud.
	stored, err := s.storedProviderExtra(kind)
	if err != nil {
		return fmt.Errorf("read stored provider state: %w", err)
	}
	if err := applyProviderUpdateInTx(context.Background(), tx, kind, url, enabled, extra, stored); err != nil {
		return err
	}
	return tx.Commit()
}

// applyProviderUpdateInTx is applyProviderUpdate's body, writing through the
// caller's transaction so handleSettingsPut can apply every provider and
// routing field atomically (mirrors db.SetSensorTags).
func applyProviderUpdateInTx(ctx context.Context, tx *sql.Tx, kind string, url *string, enabled *bool, extra, storedExtra map[string]string) error {
	// Format-only validation: the DNS reachability
	// check runs in the PRE-transaction pass (handleSettingsPut →
	// validateProviderUpdate with DNS), never under the write lock.
	if err := validateProviderUpdateNoDNS(kind, url, enabled, extra, storedExtra); err != nil {
		return err
	}
	if kind == "smtp" {
		// In-tx effective-state re-check (TOCTOU): the
		// handler's guard ran on a pre-BeginTx snapshot; this one sees the
		// serialized write state, so two racing admin PUTs can no longer
		// jointly commit tls_mode=none over credentials.
		if err := guardSMTPNoCredsOverTLSInTx(ctx, tx, extra); err != nil {
			return err
		}
	}
	if url != nil {
		u := strings.TrimSpace(*url)
		if kind == "smtp" {
			// Persist the host under smtp_host (not smtp_url) so the SMTP
			// transport reads it from the right key.
			if err := store.SetSettingInTx(ctx, tx, "smtp_host", u); err != nil {
				return fmt.Errorf("failed to save smtp host: %s", err.Error())
			}
		} else {
			if err := store.SetSettingInTx(ctx, tx, kind+"_url", u); err != nil {
				return fmt.Errorf("failed to save %s url: %s", kind, err.Error())
			}
		}
	}
	if enabled != nil {
		val := "0"
		if *enabled {
			val = "1"
		}
		if err := store.SetSettingInTx(ctx, tx, kind+"_enabled", val); err != nil {
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
		if err := store.SetSettingInTx(ctx, tx, kind+"_"+k, vv); err != nil {
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
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
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
	// A test against a hanging SMTP relay runs up to the SMTP transport
	// budget (~15s), which plus the pre-flight reads can graze the 30s
	// server WriteTimeout: extend this connection's write deadline the way
	// handleUpdate does, so the response lands instead of a broken pipe.
	// History: docs/DECISIONS.md → slow-handler-write-deadlines.
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.SetWriteDeadline(time.Now().Add(45 * time.Second))
	}
	ok, detail := s.probeWorker.TestWebhook(r.Context(), req.Kind)
	respondWithJSON(w, http.StatusOK, map[string]any{
		"ok":     ok,
		"detail": detail,
	})
}
