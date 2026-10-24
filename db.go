package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
	//   synchronous(NORMAL) — with WAL, commits no longer fsync each time. The
	//                         DB stays consistent across an app crash; only the
	//                         last few commits can be lost on a power cut, which
	//                         is acceptable for probe samples.
	//
	// NOTE: the '?' is load-bearing. modernc.org/sqlite treats everything after
	// it as query params; omit it and the whole string becomes a filename and
	// the driver silently opens a brand-new empty database (see v0.1.x incident
	// where a missing '?' caused a fresh seed-DB to be created beside the real
	// one). Verified against the live 22-sensor DB: all three path forms with
	// the '?' return sensors=22, busy_timeout=15000, journal_mode=wal.
	fullDSN := dsn
	if strings.Contains(dsn, "?") {
		fullDSN += "&_pragma=journal_mode(WAL)&_pragma=busy_timeout(15000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	} else {
		fullDSN += "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(15000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
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
		manual INTEGER NOT NULL DEFAULT 0,
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
		created_at TEXT,
		is_admin INTEGER NOT NULL DEFAULT 0
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
	// One-time migration: add the per-sensor latency-spike multiplier
	// column. LIVE (dashboard-only): sparkline bars at/above
	// spike_mult × the window's average RTT render amber (absolute
	// red >200 ms is unchanged). The probe engine never reads it —
	// status derivation is unaffected — so it is a display tuning
	// knob, editable per sensor in the dashboard modal.
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
	// One-time migration: tag "Pulse Now" manual probes (manual=1). Manual
	// rows stay in history — sparkline, graph, inspector — but are EXCLUDED
	// from status derivation (recentFromDB/recentFromCache filter them),
	// honoring the documented contract that a manual pulse never affects
	// status or alerts (before the tag, one
	// lost manual pulse + one lost scheduled probe tripped the
	// down_after=2 consecutive-loss test into an "error" alert). Existing
	// rows are all scheduled probes, so DEFAULT 0 is exactly right.
	var manualCol int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('probes') WHERE name = 'manual'`).Scan(&manualCol); err == nil && manualCol == 0 {
		if _, err := db.Exec(`ALTER TABLE probes ADD COLUMN manual INTEGER NOT NULL DEFAULT 0`); err != nil {
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
	//
	// INSERT OR IGNORE: the NOT EXISTS guard only
	// checks for a NON-EMPTY google_chat_url, so an install whose operator
	// later CLEARED the Google Chat URL (row exists, value = '') re-ran this
	// INSERT on the next boot and hit the settings.setting_key PRIMARY KEY
	// constraint — InitSchema failed and runServer log.Fatalf'd, crash-
	// looping the service. OR IGNORE makes the re-insert a no-op: a cleared
	// provider stays cleared.
	if _, err := db.Exec(`INSERT OR IGNORE INTO settings (setting_key, value, updated_at)
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
	if err := migrateLegacyAuthToken(db); err != nil {
		return err
	}
	// One-time migration: the users table gained is_admin (the account
	// panel — add/remove user, disable auth — is admin-gated; the first
	// bootstrapped user is the admin). Old DBs get the column added, and
	// the OLDEST user is promoted when no admin exists yet, so an existing
	// install never boots with zero admins (that would lock every
	// account-management endpoint). Idempotent: on a fresh DB the column
	// exists and first accounts are created with the flag, so both
	// statements no-op. Runs AFTER the legacy token migration above so the
	// migrated 'admin' account (inserted without the flag) gets promoted.
	if err := db.migrateUserAdminColumn(); err != nil {
		return err
	}
	return nil
}

// migrateUserAdminColumn adds users.is_admin to pre-admin-flag DBs and
// promotes the oldest user when the table has no admin. Called from
// InitSchema on every boot; both statements are idempotent.
func (db *DB) migrateUserAdminColumn() error {
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name = 'is_admin'").Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := db.Exec("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0"); err != nil {
			return err
		}
	}
	res, err := db.Exec(`UPDATE users SET is_admin = 1
		WHERE rowid = (SELECT rowid FROM users ORDER BY created_at ASC, username ASC LIMIT 1)
		AND (SELECT COUNT(*) FROM users WHERE is_admin = 1) = 0`)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 1 {
		log.Println("Promoted the oldest dashboard user to admin (is_admin migration)")
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
	if err := rows.Err(); err != nil {
		// Mid-stream iteration error (DB file I/O failure): same contract
		// as the query error above — empty list — plus a log so the
		// failure is visible.
		log.Printf("db: sensor tag query failed mid-stream: %v", err)
		return []string{}
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
			// A silently-skipped chunk made the affected sensors route
			// alerts as if they had NO tags (review 2026-10-24) — the
			// mid-stream path below already logs; do the same here.
			log.Printf("db: sensor tag batch query failed for %d sensors (treated as untagged for alert routing): %v", len(chunk), err)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var id, tag string
			if err := rows.Scan(&id, &tag); err != nil {
				log.Printf("db: sensor tag batch skipping corrupt row: %v", err)
				continue
			}
			out[id] = append(out[id], tag)
		}
		if err := rows.Err(); err != nil {
			// Mid-stream chunk failure: log and keep the rows already read
			// — the function has no error channel, and a DB file I/O
			// failure this deep is visible in the service log.
			log.Printf("db: sensor tag batch query failed mid-stream: %v", err)
			return
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

// SetMaintenanceMode atomically applies a maintenance mode transition in ONE
// transaction: pauses/resumes the given sensors AND updates the
// maintenance_mode + maintenance_active_ids settings, so a crash mid-write
// can't leave sensors paused without the mode flag (or vice versa). Without
// this, the three separate autocommit writes (SetSensorStates, snapshot,
// mode) could tear: a crash after pausing but before setting mode=1 orphans
// the sensors in paused state with no maintenance banner and no toggle to
// trigger the resume path. Mirrors the SetSensorTags transaction idiom
// above: a mid-write error (or crash) rolls back cleanly.
//
// on=true:  pause ids, save snapJSON as maintenance_active_ids, set mode=1.
// on=false: resume ids, clear maintenance_active_ids, set mode=0.
//
// The chunked sensor-state UPDATE mirrors SetSensorStates so an unbounded
// id list can't exceed SQLite's parameter limit.
func (db *DB) SetMaintenanceMode(on bool, ids []string, snapJSON string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit succeeds
	return applyMaintenanceTx(tx, on, ids, snapJSON)
}

// EnterMaintenanceWithFreshSnapshot enters maintenance mode with the
// active-sensor snapshot computed INSIDE the pause transaction itself
// (review nit 2026-10-24). The handler used to read ActiveSensorIDs before
// the settings tx and apply that pre-tx list afterwards: a sensor activated
// (or created) between the read and the pause escaped the snapshot and kept
// probing under a mode that reads as ON until the next maintenance cycle.
// One transaction now: SELECT active ids → pause them → write snapshot +
// mode flag. Returns the ids actually paused (the handler feeds them to the
// SetPaused in-memory fast path). The handler's earlier read survives only
// as a UX pre-check (400 "no active sensors"); this read is authoritative.
func (db *DB) EnterMaintenanceWithFreshSnapshot() ([]string, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit succeeds
	rows, err := tx.Query("SELECT id FROM sensors WHERE state = 'active' ORDER BY name")
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	snap, err := json.Marshal(ids)
	if err != nil {
		return nil, err
	}
	if err := applyMaintenanceTx(tx, true, ids, string(snap)); err != nil {
		return nil, err
	}
	return ids, nil
}

// applyMaintenanceTx is the body of both maintenance transitions, running
// on the caller's tx and committing it on success.
func applyMaintenanceTx(tx *sql.Tx, on bool, ids []string, snapJSON string) error {

	state := "paused"
	modeVal := "1"
	if !on {
		state = "active"
		modeVal = "0"
		snapJSON = "" // clear the snapshot on resume
	}

	// 1. Pause/resume the sensors (chunked to stay under SQLite's param limit).
	if len(ids) > 0 {
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
			if _, err := tx.Exec("UPDATE sensors SET state = ? WHERE id IN ("+strings.Join(q, ",")+")", args...); err != nil {
				return err
			}
		}
	}

	// 2. Save/clear the snapshot.
	if _, err := tx.Exec(`INSERT INTO settings (setting_key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(setting_key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		"maintenance_active_ids", snapJSON, tsNow()); err != nil {
		return err
	}

	// 3. Set the mode flag.
	if _, err := tx.Exec(`INSERT INTO settings (setting_key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(setting_key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		"maintenance_mode", modeVal, tsNow()); err != nil {
		return err
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
	if err := rows.Err(); err != nil {
		// Mid-stream iteration error: same contract as the query error
		// above — empty map — plus a log.
		log.Printf("db: all-tags query failed mid-stream: %v", err)
		return map[string]int{}
	}
	return out
}

// ImmediateTx runs fn inside a BEGIN IMMEDIATE transaction on a pinned
// connection: the write lock is acquired at BEGIN, not on the first write
// (db.Begin issues a DEFERRED begin), so two concurrent
// check-then-insert flows cannot both observe the pre-insert state — the
// setup-mode bootstrap race where N unauthenticated first-user POSTs each
// read user_count=0 and all committed. fn receives
// the pinned *sql.Conn and must run its statements through it (the
// transaction lives on that connection); ImmediateTx commits on a nil
// return and rolls back on error. The connection goes back to the pool
// when the function returns.
func (db *DB) ImmediateTx(ctx context.Context, fn func(c *sql.Conn) error) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close() // returns the conn to the pool
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	// A panic inside fn must not hand a conn with an OPEN transaction back
	// to the pool: net/http recovers panics per-connection, the deferred
	// conn.Close() still runs, and the next BEGIN IMMEDIATE on that pooled
	// conn fails "cannot start a transaction within a transaction" —
	// writes wedged until restart (review 2026-10-24, same failure mode the
	// ctx-canceled comment above defends against, via a different route).
	// Registered AFTER the conn.Close defer so it runs BEFORE it (LIFO);
	// the panic is re-raised for the HTTP layer to log.
	defer func() {
		if r := recover(); r != nil {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
			panic(r)
		}
	}()
	if err := fn(conn); err != nil {
		// Rollback on a fresh context: cleanup must reach the driver even
		// when the caller's ctx is already canceled (client disconnect) —
		// a canceled ctx makes ExecContext return before the ROLLBACK is
		// sent, leaving the transaction open on a conn that defer
		// conn.Close() would hand back to the pool, where the next
		// BEGIN IMMEDIATE on it fails "cannot start a transaction within
		// a transaction".
		_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		// Same hazard the rollback above defends against, COMMIT-side
		// (review 2026-10-24): a ctx canceled at the driver skips the
		// statement, and SQLITE_BUSY after busy_timeout leaves the
		// transaction ACTIVE (SQLite semantics) — the conn would go back
		// to the pool holding the write lock with database/sql unaware.
		// Roll back on a fresh context (a no-op if the commit actually
		// landed) before the deferred conn.Close() releases the conn.
		_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		return err
	}
	return nil
}

// migrateLegacyAuthToken converts a pre-accounts auth_token setting into the
// "admin" user (the stored hash is already bcrypt, so it verifies exactly as
// before) and then clears the setting — the users table is the source of
// truth. The token is destroyed ONLY on a confirmed outcome (users already
// exist, or the INSERT committed): on a UserCount error or an INSERT failure
// the token stays in place and the migration retries next boot. Clearing it
// unconditionally (review 2026-10-24) destroyed the operator's only
// credential on a failed migration and left zero users + no
// auth_bootstrapped flag — which the setup gate reads as a FRESH install,
// downgrading the dashboard to unauthenticated setup mode.
func migrateLegacyAuthToken(db *DB) error {
	if db.GetSetting("auth_token") == "" {
		return nil
	}
	n, err := db.UserCount()
	if err != nil {
		log.Printf("WARNING: legacy auth_token migration deferred (user count failed: %v); token kept, retried next start", err)
		return nil
	}
	if n == 0 {
		if _, err := db.Exec(`INSERT INTO users (username, password_hash, created_at)
			VALUES ('admin', (SELECT value FROM settings WHERE setting_key = 'auth_token'), ?)`,
			tsNow()); err != nil {
			log.Printf("WARNING: legacy auth_token migration to users table failed: %v; token kept, retried next start", err)
			return nil
		}
		// This install has been set up — mark it so the gate doesn't
		// treat a later auth-off state as a fresh install.
		if err := db.SetSetting("auth_bootstrapped", "1"); err != nil {
			log.Println("WARNING: failed to set auth_bootstrapped flag:", err)
		}
		log.Println("Migrated legacy auth token to the 'admin' user; set a new password in Settings")
	}
	if err := db.SetSetting("auth_token", ""); err != nil {
		return err
	}
	return nil
}

// DeleteTag removes one tag from every sensor; returns how many sensors lost it.
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

// GetSettingErr is GetSetting that surfaces real DB errors: an absent key is
// ("", nil), any other failure ("", err). GetSetting's 83 call sites keep
// their swallow-to-"" contract; this exists for paths where "unset" and
// "read failed" must not look the same — alert delivery.
func (db *DB) GetSettingErr(key string) (string, error) {
	var v string
	err := db.QueryRow("SELECT value FROM settings WHERE setting_key = ?", key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return v, nil
}

// tsLayout is the single writer-side timestamp format: UTC, ALWAYS 9
// fractional digits. Fixed width is what makes string order equal
// chronological order (time.RFC3339Nano trims trailing zeros, so "…25.13Z"
// sorted AFTER "…25.134Z"), which the string-compared retention purge and
// ORDER BY ts rely on. It still parses under time.RFC3339Nano, and rows
// written by older versions (variable width) remain readable.
const tsLayout = "2006-01-02T15:04:05.000000000Z"

// fmtTS formats t for storage in any ts column.
func fmtTS(t time.Time) string { return t.UTC().Format(tsLayout) }

// tsNow is fmtTS(now).
func tsNow() string { return fmtTS(time.Now()) }

func (db *DB) SetSetting(key, value string) error {
	_, err := db.Exec(`INSERT INTO settings (setting_key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(setting_key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, tsNow())
	return err
}

// setSettingInTx is SetSetting through a caller's transaction (lets handleSettingsPut apply a multi-key save atomically).
func setSettingInTx(tx *sql.Tx, key, value string) error {
	_, err := tx.Exec(`INSERT INTO settings (setting_key, value, updated_at) VALUES (?, ?, ?)
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

// RemoveUser deletes one account, refusing to delete the last one. The
// count guard lives INSIDE the DELETE so check-and-delete is one atomic
// statement: the old COUNT-then-DELETE let two concurrent removals both
// pass the count and delete the last two users, silently turning auth off
// If the removed account was the LAST ADMIN, the
// oldest remaining user is promoted in the SAME transaction — the install
// must never be left without an admin (that would lock every
// account-management endpoint). 0 rows affected = the last user (
// errLastUser) or no such user (errUserNotFound): the sentinel replaced the
// silent no-op, which made the API answer 200 and the
// CLI print "User removed" for a mistyped name).
func (db *DB) RemoveUser(username string) error {
	ctx := context.Background()
	return db.ImmediateTx(ctx, func(c *sql.Conn) error {
		res, err := c.ExecContext(ctx,
			"DELETE FROM users WHERE username = ? AND (SELECT COUNT(*) FROM users) > 1", username)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			var exists int
			if err := c.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&exists); err != nil {
				return err
			}
			if exists == 0 {
				return fmt.Errorf("%w: %s", errUserNotFound, username)
			}
			return errLastUser
		}
		// The removed account was the last admin: hand the flag to the
		// oldest remaining user so the install is never left without an
		// admin (admin-flag fix).
		res, err = c.ExecContext(ctx, `UPDATE users SET is_admin = 1
			WHERE rowid = (SELECT rowid FROM users ORDER BY created_at ASC, username ASC LIMIT 1)
			AND (SELECT COUNT(*) FROM users WHERE is_admin = 1) = 0`)
		if err != nil {
			return err
		}
		if rows, _ := res.RowsAffected(); rows == 1 {
			log.Println("Last admin removed — promoted the oldest remaining user to admin")
		}
		return nil
	})
}

// RemoveAllUsers clears every account (the "disable authentication" path).
func (db *DB) RemoveAllUsers() error {
	_, err := db.Exec("DELETE FROM users")
	return err
}

type authUser struct {
	Username  string `json:"username"`
	CreatedAt string `json:"created_at"`
	IsAdmin   bool   `json:"is_admin"`
}

// ListUsers returns every account, oldest first (created_at is the standard
// app timestamp, RFC3339Nano).
func (db *DB) ListUsers() ([]authUser, error) {
	rows, err := db.Query("SELECT username, created_at, is_admin FROM users ORDER BY created_at, username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []authUser{}
	for rows.Next() {
		var u authUser
		var admin int
		if err := rows.Scan(&u.Username, &u.CreatedAt, &admin); err != nil {
			return nil, err
		}
		u.IsAdmin = admin == 1
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

// SensorIDs lists the ids of every sensor in ANY state, in name order.
// Used by the retention purge: every probes/events row references a current
// sensor (FK ON DELETE CASCADE removes a deleted sensor's rows), so
// per-sensor purging over this set covers the whole table.
func (db *DB) SensorIDs() ([]string, error) {
	rows, err := db.Query("SELECT id FROM sensors ORDER BY name")
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

// SensorStatus returns a sensor's current health status (up/warning/
// error). A missing sensor is an error (sql.ErrNoRows) so callers can
// tell "gone" from "up".
func (db *DB) SensorStatus(id string) (string, error) {
	var status string
	err := db.QueryRow("SELECT status FROM sensors WHERE id = ?", id).Scan(&status)
	return status, err
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
	// the API (POST /api/sensors: 60s / 1000ms / 25% / 2 / 3x) so a seeded
	// sensor and a dashboard-created one behave identically. They start
	// PAUSED — like UI-created sensors — because the targets are
	// environment-independent placeholders (127.0.0.1: not every host runs
	// a router or a server on 192.168.1.x, and a wrong active target would
	// fire down alerts on day one). The user edits the targets and resumes.
	// spike_mult is written explicitly so the seed row keeps a stable
	// value in the (deprecated, unread) compatibility column.
	sensors := []struct {
		name, target, tags string
	}{
		{"router", "127.0.0.1", "Networking"},
		{"server", "127.0.0.1", "Servers"},
	}

	for _, s := range sensors {
		// A real UUID id (not the name) so seeded sensors carry the same id
		// format as every API-created sensor.
		id := newID()
		if _, err := db.Exec(`
			INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
			VALUES (?, ?, ?, 60, 1000, 25, 2, 3, 'paused', 'up', ?)`,
			id, s.name, s.target, tsNow()); err != nil {
			return err
		}
		if s.tags != "" {
			if _, err := db.Exec("INSERT OR IGNORE INTO sensor_tags (sensor_id, tag) VALUES (?, ?)", id, s.tags); err != nil {
				return err
			}
		}
	}
	return nil
}
