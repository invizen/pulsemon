package main

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
}

func NewDB(dsn string) (*DB, error) {
	// Pragma settings go in the DSN query string so modernc.org/sqlite applies
	// them to EVERY connection the pool opens. Setting them via db.Exec() would
	// only configure the single connection that call happened to use — the
	// other pooled connections would run with the defaults (no busy_timeout),
	// and concurrent probe writes would fail instantly with SQLITE_BUSY.
	//
	//   journal_mode(WAL)   — concurrent readers alongside a writer
	//   busy_timeout(15000) — a blocked writer waits up to 15s instead of
	//                         failing immediately (critical under write bursts)
	//   foreign_keys(ON)    — enforce ON DELETE CASCADE on probes/events/tags
	//
	// NOTE: the '?' is load-bearing. modernc.org/sqlite treats everything after
	// it as query params; omit it and the whole string becomes a filename and
	// the driver silently opens a brand-new empty database (see v0.1.x incident
	// where a missing '?' caused a fresh seed-DB to be created beside the real
	// one). Verified against the live 22-sensor DB: all three path forms with
	// the '?' return sensors=22, busy_timeout=15000, journal_mode=wal.
	fullDSN := dsn
	if strings.Contains(dsn, "?") {
		fullDSN += "&_pragma=journal_mode(WAL)&_pragma=busy_timeout(15000)&_pragma=foreign_keys(1)"
	} else {
		fullDSN += "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(15000)&_pragma=foreign_keys(1)"
	}

	db, err := sql.Open("sqlite", fullDSN)
	if err != nil {
		return nil, err
	}
	// Pool sizing: SQLite WAL allows concurrent readers and serializes
	// writers internally (busy_timeout above makes a blocked writer wait
	// rather than fail). Ten connections comfortably cover the probe worker
	// plus concurrent HTTP handlers. Nested per-row queries inside rows.Next()
	// are NOT a thing in this codebase — batch them (see SensorTagsFor).
	//
	// DO NOT lower this to 1 (a "single writer" suggestion): a single
	// connection self-deadlocks on ANY nested query inside rows.Next() — the
	// outer cursor holds the only connection and the nested query blocks
	// forever. This exact bug shipped in an early revision and hung the whole
	// server (healthcheck passed, every HTTP request hung). The pool must stay
	// multi-connection so a cursor + nested query can use different
	// connections; "database is locked" is mitigated by busy_timeout (above),
	// not by pool size. Guarded by TestMaxOpenConnsOneSelfDeadlocksOnNestedQuery
	// and TestConcurrentProbeWritesDoNotBusy.
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(4)
	db.SetConnMaxIdleTime(0)
	// Verify the store is reachable and the pragmas applied.
	if _, err := db.Exec("SELECT 1"); err != nil {
		return nil, err
	}
	return &DB{db}, nil
}

func (db *DB) InitSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS sensors (
		id TEXT PRIMARY KEY,
		name TEXT UNIQUE NOT NULL,
		target TEXT NOT NULL,
		type TEXT NOT NULL DEFAULT 'icmp',
		tag TEXT,
		interval_s INTEGER NOT NULL,
		timeout_ms INTEGER NOT NULL,
		loss_warn INTEGER NOT NULL,
		down_after INTEGER NOT NULL,
		spike_mult INTEGER NOT NULL DEFAULT 5,
		state TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at TEXT
	);

	CREATE TABLE IF NOT EXISTS probes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sensor_id TEXT NOT NULL,
		ts DATETIME NOT NULL,
		rtt_ms REAL,
		resolved_ip TEXT,
		http_status INTEGER,
		FOREIGN KEY (sensor_id) REFERENCES sensors(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sensor_id TEXT NOT NULL,
		ts DATETIME NOT NULL,
		from_status TEXT,
		to_status TEXT,
		note TEXT,
		FOREIGN KEY (sensor_id) REFERENCES sensors(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_probes_sensor_ts ON probes(sensor_id, ts);
	CREATE INDEX IF NOT EXISTS idx_events_sensor_ts ON events(sensor_id, ts);

	CREATE TABLE IF NOT EXISTS settings (
		setting_key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at TEXT
	);

	CREATE TABLE IF NOT EXISTS sensor_tags (
		sensor_id TEXT NOT NULL,
		tag TEXT NOT NULL,
		PRIMARY KEY (sensor_id, tag),
		FOREIGN KEY (sensor_id) REFERENCES sensors(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS alert_state (
		sensor_id TEXT PRIMARY KEY,
		status TEXT NOT NULL,
		last_ts TEXT NOT NULL,
		FOREIGN KEY (sensor_id) REFERENCES sensors(id) ON DELETE CASCADE
	);

	-- Dashboard accounts (username/password auth). Auth is enabled iff this
	-- table has at least one row.
	CREATE TABLE IF NOT EXISTS users (
		username TEXT PRIMARY KEY,
		password_hash TEXT NOT NULL,
		created_at TEXT
	);
	`
	_, err := db.Exec(schema)
	if err != nil {
		return err
	}
	// One-time migration: legacy single-tag column → sensor_tags table.
	var tagCol int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sensors') WHERE name = 'tag'`).Scan(&tagCol); err == nil && tagCol > 0 {
		if _, err := db.Exec(`INSERT OR IGNORE INTO sensor_tags (sensor_id, tag)
			SELECT id, tag FROM sensors WHERE tag IS NOT NULL AND TRIM(tag) <> ''`); err != nil {
			return err
		}
		if _, err := db.Exec(`ALTER TABLE sensors DROP COLUMN tag`); err != nil {
			return err
		}
	}
	// One-time migration: add per-sensor latency-spike multiplier (default 5x).
	var spikeCol int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sensors') WHERE name = 'spike_mult'`).Scan(&spikeCol); err == nil && spikeCol == 0 {
		if _, err := db.Exec(`ALTER TABLE sensors ADD COLUMN spike_mult INTEGER NOT NULL DEFAULT 5`); err != nil {
			return err
		}
	}
	// One-time migration: record what each probe resolved to (diagnoses
	// "sensors that never respond" — a NULL/absent resolved_ip means the
	// DNS lookup never returned, the leading cause of a stalled sensor).
	var resolvedCol int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('probes') WHERE name = 'resolved_ip'`).Scan(&resolvedCol); err == nil && resolvedCol == 0 {
		if _, err := db.Exec(`ALTER TABLE probes ADD COLUMN resolved_ip TEXT`); err != nil {
			return err
		}
	}
	// One-time migration: record the HTTP status code for HTTP sensors
	// (NULL for ICMP probes and any probe that got no response). Lets the
	// card show "HTTP 503" vs "no response" for the same loss row.
	var httpStatusCol int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('probes') WHERE name = 'http_status'`).Scan(&httpStatusCol); err == nil && httpStatusCol == 0 {
		if _, err := db.Exec(`ALTER TABLE probes ADD COLUMN http_status INTEGER`); err != nil {
			return err
		}
	}
	// One-time migration: sensor probe type. Existing sensors default to
	// 'icmp' (the original and only type), so this is a no-op data-wise; it
	// just lets the probe worker dispatch the right probe.
	var typeCol int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sensors') WHERE name = 'type'`).Scan(&typeCol); err == nil && typeCol == 0 {
		if _, err := db.Exec(`ALTER TABLE sensors ADD COLUMN type TEXT NOT NULL DEFAULT 'icmp'`); err != nil {
			return err
		}
	}
	// One-time migration (v0.1.13): rename stored statuses. "down" was the
	// old name for error and "degraded" for warning; without this, the first
	// probe after upgrade would log a spurious transition and fire a one-time
	// alert on every already-affected sensor.
	//
	// Each UPDATE is filtered to the legacy rows it actually rewrites. An
	// unfiltered `UPDATE ... SET col = CASE ... ELSE col END` matches EVERY
	// row and, in SQLite, re-assigns+re-writes each one even where the value
	// is unchanged — so on a fully-migrated DB this forced a full-table WAL
	// write on every boot, churning pages and blocking active probe writes
	// (WAL has a single writer). With the WHERE, a no-op boot touches zero
	// rows, so this is a true one-time migration.
	if _, err := db.Exec(`UPDATE sensors SET status = CASE status
		WHEN 'down' THEN 'error'
		WHEN 'degraded' THEN 'warning'
		ELSE status END
		WHERE status IN ('down', 'degraded')`); err != nil {
		return err
	}
	if _, err := db.Exec(`UPDATE events SET from_status = CASE from_status
		WHEN 'down' THEN 'error' WHEN 'degraded' THEN 'warning' ELSE from_status END
		WHERE from_status IN ('down', 'degraded')`); err != nil {
		return err
	}
	if _, err := db.Exec(`UPDATE events SET to_status = CASE to_status
		WHEN 'down' THEN 'error' WHEN 'degraded' THEN 'warning' ELSE to_status END
		WHERE to_status IN ('down', 'degraded')`); err != nil {
		return err
	}
	if _, err := db.Exec(`UPDATE alert_state SET status = CASE status
		WHEN 'down' THEN 'error' WHEN 'degraded' THEN 'warning' ELSE status END
		WHERE status IN ('down', 'degraded')`); err != nil {
		return err
	}
	// Cosmetic: old event notes read "up -> degraded" / "down -> up".
	if _, err := db.Exec(`UPDATE events SET note = replace(replace(replace(note, 'degraded', 'warning'), 'down', 'error'), 'warning -> up', 'recovered') WHERE note LIKE '%degraded%' OR note LIKE '%down%'`); err != nil {
		return err
	}
	// One-time migration (v0.1.14): the settings table gained per-provider
	// keys. The single legacy "webhook_url" was the Google Chat URL, so move
	// it to google_chat_url (idempotent — skipped if a google_chat_url is
	// already set). Without this, existing installs would silently lose their
	// configured alert webhook on upgrade.
	if _, err := db.Exec(`INSERT INTO settings (setting_key, value, updated_at)
		SELECT 'google_chat_url', value, COALESCE(updated_at, datetime('now'))
		FROM settings WHERE setting_key = 'webhook_url' AND TRIM(value) <> ''
		AND NOT EXISTS (SELECT 1 FROM settings WHERE setting_key = 'google_chat_url' AND TRIM(value) <> '')`); err != nil {
		return err
	}
	// Mark the migrated Google Chat provider explicitly enabled, so the new
	// per-provider toggle reflects the pre-existing active config (and a
	// fresh install, which has no legacy row, leaves it unset → off).
	if _, err := db.Exec(`INSERT OR REPLACE INTO settings (setting_key, value, updated_at)
		SELECT 'google_chat_enabled', '1', COALESCE(updated_at, datetime('now'))
		FROM settings WHERE setting_key = 'webhook_url' AND TRIM(value) <> ''
		AND NOT EXISTS (SELECT 1 FROM settings WHERE setting_key = 'google_chat_enabled')`); err != nil {
		return err
	}
	// One-time migration: auth pivoted from a single settings token to the
	// users table (username/password). If a legacy auth_token row exists
	// AND no users exist yet, it becomes the "admin" account (the hash is
	// already bcrypt, so it verifies exactly as before). The row is then
	// cleared either way — the users table is the source of truth.
	if db.GetSetting("auth_token") != "" {
		if n, err := db.UserCount(); err == nil && n == 0 {
			if _, err := db.Exec(`INSERT INTO users (username, password_hash, created_at)
				VALUES ('admin', (SELECT value FROM settings WHERE setting_key = 'auth_token'), ?)`,
				tsNow()); err != nil {
				log.Println("WARNING: legacy auth_token migration to users table failed:", err)
			} else {
				log.Println("Migrated legacy auth token to the 'admin' user; set a new password in Settings")
			}
		}
		if err := db.SetSetting("auth_token", ""); err != nil {
			return err
		}
	}
	return nil
}

// SensorTags returns the sorted tag list for a sensor.
func (db *DB) SensorTags(id string) []string {
	rows, err := db.Query("SELECT tag FROM sensor_tags WHERE sensor_id = ? ORDER BY tag", id)
	if err != nil {
		return []string{}
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var t string
		if rows.Scan(&t) == nil {
			out = append(out, t)
		}
	}
	return out
}

// inQueryChunk is the max number of ids per IN(...) chunk for batch queries.
// modernc.org/sqlite (v1.29.1) accepts up to 32,766 bound parameters
// (verified against the real driver: 32,766 binds, 32,767 fails with "too
// many SQL variables"). A query that repeats an id list N times needs
// N*chunk params, so a fixed 500 stays far under the limit with headroom for
// the repeated lists (warmStats uses its id list twice, once per UNION arm).
// A realistic homelab fleet runs on a single chunk; the cap only engages if
// the fleet ever grows to thousands of sensors, where it prevents the query
// from failing outright with "too many SQL variables".
const inQueryChunk = 500

// SensorTagsFor fetches the sorted tag lists for a batch of sensors. It runs
// in inQueryChunk-sized batches so an unbounded id list can't exceed the
// SQLite host-parameter limit. Batch callers (fetchSensors, syncSensors) must
// not run a per-row SensorTags() inside a rows.Next() loop: the outer
// iteration holds a pooled connection, and per-row queries starve the pool
// under concurrent load. Empty ids → empty map; ids are internal UUIDs (no
// user string injection).
func (db *DB) SensorTagsFor(ids []string) map[string][]string {
	out := make(map[string][]string, len(ids))
	if len(ids) == 0 {
		return out
	}
	// Closure per chunk: defer closes this chunk's cursor when the chunk
	// finishes, before the next chunk's query runs — top-level defer, not a
	// bare close below a loop, so no pooled connection is held across chunks.
	fetchChunk := func(chunk []string) {
		q := make([]string, len(chunk))
		args := make([]any, len(chunk))
		for j, id := range chunk {
			q[j] = "?"
			args[j] = id
		}
		rows, err := db.Query("SELECT sensor_id, tag FROM sensor_tags WHERE sensor_id IN ("+
			strings.Join(q, ",")+") ORDER BY tag", args...)
		if err != nil {
			return
		}
		defer rows.Close()
		for rows.Next() {
			var id, tag string
			if rows.Scan(&id, &tag) == nil {
				out[id] = append(out[id], tag)
			}
		}
	}
	for i := 0; i < len(ids); i += inQueryChunk {
		end := i + inQueryChunk
		if end > len(ids) {
			end = len(ids)
		}
		fetchChunk(ids[i:end])
	}
	return out
}

// SetSensorTags atomically replaces a sensor's tags: DELETE then INSERTs in
// ONE transaction, so a mid-loop error (or a crash) rolls back cleanly and
// the sensor is never left with a partial/empty tag set. A torn tag set is
// worse than stale tags: with alert_scope='tags' it silently changes which
// sensors alert.
func (db *DB) SetSensorTags(id string, tags []string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit succeeds

	if _, err := tx.Exec("DELETE FROM sensor_tags WHERE sensor_id = ?", id); err != nil {
		return err
	}
	for _, t := range tags {
		if _, err := tx.Exec("INSERT OR IGNORE INTO sensor_tags (sensor_id, tag) VALUES (?, ?)", id, t); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AllTags returns each distinct tag with the number of sensors using it.
func (db *DB) AllTags() map[string]int {
	rows, err := db.Query(`SELECT tag, COUNT(DISTINCT sensor_id) FROM sensor_tags GROUP BY tag ORDER BY tag`)
	if err != nil {
		return map[string]int{}
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var t string
		var n int
		if rows.Scan(&t, &n) == nil {
			out[t] = n
		}
	}
	return out
}

// DeleteTag removes a tag from every sensor; returns how many sensors lost it.
func (db *DB) DeleteTag(tag string) (int64, error) {
	res, err := db.Exec("DELETE FROM sensor_tags WHERE tag = ?", tag)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// GetSetting reads a key from the settings table ("" when absent).
func (db *DB) GetSetting(key string) string {
	var v string
	if err := db.QueryRow("SELECT value FROM settings WHERE setting_key = ?", key).Scan(&v); err != nil {
		return ""
	}
	return v
}

// tsNow is the single writer-side timestamp format for every column this app
// writes: RFC3339Nano UTC. The two string-sorted columns (probes.ts,
// events.ts) are already 100% RFC3339Nano in every live DB, so standardizing
// on that (rather than integer-second RFC3339) keeps them uniform — and keeps
// their sub-second precision. Columns that are only parsed (alert_state
// .last_ts) or never read (settings.updated_at, sensors.created_at) now
// match too, so a future ORDER BY on any of them is well-defined.
func tsNow() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func (db *DB) SetSetting(key, value string) error {
	_, err := db.Exec(`INSERT INTO settings (setting_key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(setting_key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, tsNow())
	return err
}

// ---------- dashboard users (username/password auth) ----------

// UserCount returns how many dashboard accounts exist. Auth is enabled
// iff this is > 0.
func (db *DB) UserCount() (int, error) {
	var n int
	err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	return n, err
}

// AddUser creates an account. Returns the driver error (SQLITE_CONSTRAINT
// → "user already exists" in the caller).
func (db *DB) AddUser(username, passwordHash string) error {
	_, err := db.Exec("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
		username, passwordHash, tsNow())
	return err
}

// UserHash returns the stored bcrypt hash for a username ("", sql.ErrNoRows
// when absent).
func (db *DB) UserHash(username string) (string, error) {
	var h string
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&h)
	if err != nil {
		return "", err
	}
	return h, nil
}

// SetUserPassword overwrites a user's hash.
func (db *DB) SetUserPassword(username, passwordHash string) error {
	res, err := db.Exec("UPDATE users SET password_hash = ? WHERE username = ?", passwordHash, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("no such user: %s", username)
	}
	return nil
}

// RemoveUser deletes one account.
func (db *DB) RemoveUser(username string) error {
	_, err := db.Exec("DELETE FROM users WHERE username = ?", username)
	return err
}

// RemoveAllUsers clears every account (the "disable authentication" path).
func (db *DB) RemoveAllUsers() error {
	_, err := db.Exec("DELETE FROM users")
	return err
}

type authUser struct {
	Username  string `json:"username"`
	CreatedAt string `json:"created_at"`
}

// ListUsers returns every account, oldest first (created_at is the standard
// app timestamp, RFC3339Nano).
func (db *DB) ListUsers() ([]authUser, error) {
	rows, err := db.Query("SELECT username, created_at FROM users ORDER BY created_at, username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []authUser{}
	for rows.Next() {
		var u authUser
		if err := rows.Scan(&u.Username, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ActiveSensorIDs lists the ids of every sensor currently in state 'active',
// in name order. Used to snapshot which sensors are running before maintenance
// mode pauses them, so resume can restore exactly that set.
func (db *DB) ActiveSensorIDs() ([]string, error) {
	rows, err := db.Query("SELECT id FROM sensors WHERE state = 'active' ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return ids, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// SetSensorStates sets the state for a batch of sensor ids, running in
// inQueryChunk-sized IN(...) batches so a large snapshot can't exceed the
// SQLite host-parameter limit (same rule as SensorTagsFor). Returns the number
// of rows changed. An empty id list is a no-op.
func (db *DB) SetSensorStates(ids []string, state string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	var total int64
	for start := 0; start < len(ids); start += inQueryChunk {
		end := start + inQueryChunk
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[start:end]
		q := make([]string, len(chunk))
		args := make([]any, 0, len(chunk)+1)
		args = append(args, state)
		for j, id := range chunk {
			q[j] = "?"
			args = append(args, id)
		}
		res, err := db.Exec("UPDATE sensors SET state = ? WHERE id IN ("+strings.Join(q, ",")+")", args...)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

func (db *DB) SeedSensors() error {
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM sensors").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	// Fresh-install demo sensors. Tuning matches the UI-created defaults in
	// the API (POST /api/sensors: 15s / 1000ms / 25% / 4) so a seeded
	// sensor and a dashboard-created one behave identically. They start
	// PAUSED — like UI-created sensors — because the targets are
	// environment-independent placeholders (127.0.0.1: not every host runs
	// a router or a server on 192.168.1.x, and a wrong active target would
	// fire down alerts on day one). The user edits the targets and resumes.
	// spike_mult is written explicitly so the seed row matches the UI
	// default (3) rather than the schema column default (5).
	sensors := []struct {
		name, target, tags string
	}{
		{"router", "127.0.0.1", "Networking"},
		{"server", "127.0.0.1", "Servers"},
	}

	for _, s := range sensors {
		if _, err := db.Exec(`
			INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
			VALUES (?, ?, ?, 60, 1000, 25, 2, 3, 'paused', 'up', ?)`,
			s.name, s.name, s.target, tsNow()); err != nil {
			return err
		}
		if s.tags != "" {
			if _, err := db.Exec("INSERT OR IGNORE INTO sensor_tags (sensor_id, tag) VALUES (?, ?)", s.name, s.tags); err != nil {
				return err
			}
		}
	}
	return nil
}
