package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

var (
	// ErrLastUser: RemoveUser refuses to delete the final account (use
	// auth-off for that). A sentinel, not an inline fmt.Errorf, so the
	// HTTP handler can errors.Is it to a 400 while every other db
	// failure 500s (the handler used to
	// echo every RemoveUser error, raw driver text included, as a 400).
	ErrLastUser = fmt.Errorf("cannot remove the last user — disable authentication instead")
	// ErrUserNotFound: RemoveUser of a name that doesn't exist. The db
	// layer used to treat this as a silent no-op, so the API answered
	// 200 and the CLI printed "User removed: <name>" for a mistyped
	// username — a false success on an admin operation. The handler maps it to 404, the same policy as
	// the password endpoint (unknown username → 404, not 403, so the
	// endpoint doesn't confirm which names exist).
	ErrUserNotFound = fmt.Errorf("no such user")
)

// NewID generates a unique sensor id.
func NewID() string {
	return uuid.NewString()
}

// ProbeWriteTimeout is the busy_timeout of the dedicated probe-write handle
// (NewStore). It is the REAL bound on a sensor-loop stall: modernc.org/sqlite
// v1.29.1 does not preempt a write parked on the write lock with a context
// deadline — the busy handler sleeps out the full busy_timeout (empirically
// verified on Go 1.26: a parked write with a 300ms ctx deadline returns
// SQLITE_BUSY after 15.05s). So the cap on the park is a per-connection
// pragma, not context.WithTimeout; the ctx bound (dbWriteTimeout) covers
// pool/queue waits and long statements. A var (not const) so tests can
// shorten it; read at NewStore time, before opening the handle.
var ProbeWriteTimeout = 8 * time.Second

type Store struct {
	*sql.DB
	// probeDB is a second handle on the same file whose busy_timeout is
	// ProbeWriteTimeout. Probe-path writes run on it so a stalled writer
	// parks a sensor loop for the cap, not the main pool's 15s.
	probeDB *sql.DB
}

// Close closes both handles. Shadows the embedded sql.DB.Close so callers
// that only know about Store release the probe handle too.
func (db *Store) Close() error {
	return errors.Join(db.DB.Close(), db.probeDB.Close())
}

// NewStoreForTest wraps already-opened *sql.DB handles (main + probe
// write) WITHOUT NewStore's DSN pragmas. For tests that need a specific
// pragma shape (e.g. foreign_keys OFF, to prove a SQL-level guard does
// not rely on the FK cascade). Production always uses NewStore.
func NewStoreForTest(db, probeDB *sql.DB) *Store {
	return &Store{DB: db, probeDB: probeDB}
}

func NewStore(dsn string) (*Store, error) {
	// Pragma settings go in the DSN query string so modernc.org/sqlite applies
	// them to EVERY connection the pool opens. Setting them via db.Exec() would
	// only configure the single connection that call happened to use — the
	// other pooled connections would run with the defaults (no busy_timeout),
	// and concurrent probe writes would fail instantly with SQLITE_BUSY.
	//
	//   busy_timeout(15000) — a blocked writer waits up to 15s instead of
	//                         failing immediately (critical under write bursts).
	//                         FIRST in the DSN: journal_mode is the only
	//                         pragma that writes, so the timeout must already
	//                         be in effect when it runs (see dsnWithPragmas).
	//   journal_mode(WAL)   — concurrent readers alongside a writer
	//   foreign_keys(ON)    — enforce ON DELETE CASCADE on probes/events/tags
	//   synchronous(NORMAL) — with WAL, commits no longer fsync each time. The
	//                         Store stays consistent across an app crash; only the
	//                         last few commits can be lost on a power cut, which
	//                         is acceptable for probe samples.
	//   temp_store(MEMORY)  — no /tmp exists in the scratch container; temp
	//                         B-trees must not spill to disk (see Dockerfile).
	//   journal_size_limit  — the WAL is truncated to 64 MiB after checkpoints
	//                         instead of staying at its post-purge high-water
	//                         mark (hundreds of MB) for the process lifetime.
	//   cache_size(-8000)   — 8 MiB page cache per connection (default 2 MiB
	//                         churns on the warmStats 24h-window read).
	//
	// NOTE: the '?' is load-bearing. modernc.org/sqlite treats everything after
	// it as query params; omit it and the whole string becomes a filename and
	// the driver silently opens a brand-new empty database (see v0.1.x incident
	// where a missing '?' caused a fresh seed-Store to be created beside the real
	// one). Verified against the live 22-sensor Store: all three path forms with
	// the '?' return sensors=22, busy_timeout=15000, journal_mode=wal.
	fullDSN := dsnWithPragmas(dsn, 15000)

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
		// The pool above is real: a failed probe must not leave the
		// handle (and its idle pool) behind.
		db.Close()
		return nil, err
	}
	// Probe-write handle: the same file, busy_timeout = ProbeWriteTimeout.
	// That pragma — not a ctx deadline — is the real cap on a sensor loop
	// parked by a stalled writer (see ProbeWriteTimeout). MaxOpenConns(1):
	// probe writes across all sensor loops serialize on one connection, so
	// surplus waits queue in database/sql's Conn(ctx) pool-wait — which IS
	// ctx-aware — instead of parking in the driver's busy handler; shutdown
	// cancel aborts a probe waiting to write, and the driver bounds one
	// already parked.
	probeDB, err := sql.Open("sqlite", dsnWithPragmas(dsn, int64(ProbeWriteTimeout/time.Millisecond)))
	if err != nil {
		db.Close()
		return nil, err
	}
	probeDB.SetMaxOpenConns(1)
	probeDB.SetMaxIdleConns(1)
	probeDB.SetConnMaxIdleTime(0)
	if _, err := probeDB.Exec("SELECT 1"); err != nil {
		db.Close()
		probeDB.Close()
		return nil, err
	}
	return &Store{DB: db, probeDB: probeDB}, nil
}

// dsnWithPragmas appends the per-connection pragmas to dsn with the given
// busy_timeout in ms. The '?' semantics are the ones documented in NewStore.
//
// ORDER IS LOAD-BEARING: the driver executes _pragma params in the order
// they appear, and journal_mode(WAL) is the ONLY one that writes (it flips
// the file's mode and creates -wal/-shm) — so busy_timeout must be in
// effect BEFORE it. With the old order (journal_mode first), a lazy pool
// connection — and the 30s -healthz-http probe, which opens its own
// connection on every check — that landed while another connection held
// the write lock ran the mode switch with busy_timeout = 0 and failed
// immediately with SQLITE_BUSY. The remaining pragmas are read-only
// connection settings; their order is immaterial.
//
//	temp_store(MEMORY) — the FROM-scratch image runs unprivileged with no
//	                      /tmp and a non-writable / (Dockerfile); a query
//	                      that spills a temp B-tree (a big sort, a
//	                      materialized CTE) would fail with SQLITE_CANTOPEN
//	                      on temp-file creation.
//	journal_size_limit — without it a large delete (clear-all-history, a
//	                      multi-million-row purge) checkpoints into a WAL
//	                      that stays hundreds of MB on disk forever; 64 MiB
//	                      is the cap (0 = unlimited).
//	cache_size(-8000)  — 8 MiB page cache per connection (negative = KiB,
//	                      1 KiB pages); the default 2 MiB churns on the
//	                      warmStats 24h-window read (~1.7M rows).
//
// History: docs/DECISIONS.md → sqlite-scalability-container-hazards.
func dsnWithPragmas(dsn string, busyMs int64) string {
	q := fmt.Sprintf("_pragma=busy_timeout(%d)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)&_pragma=temp_store(MEMORY)&_pragma=journal_size_limit(67108864)&_pragma=cache_size(-8000)", busyMs)
	if strings.Contains(dsn, "?") {
		return dsn + "&" + q
	}
	return dsn + "?" + q
}

func (db *Store) InitSchema() error {
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
		id INTEGER PRIMARY KEY,
		sensor_id TEXT NOT NULL,
		ts DATETIME NOT NULL,
		rtt_ms REAL,
		resolved_ip TEXT,
		http_status INTEGER,
		manual INTEGER NOT NULL DEFAULT 0,
		FOREIGN KEY (sensor_id) REFERENCES sensors(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY,
		sensor_id TEXT NOT NULL,
		ts DATETIME NOT NULL,
		from_status TEXT,
		to_status TEXT,
		note TEXT,
		FOREIGN KEY (sensor_id) REFERENCES sensors(id) ON DELETE CASCADE
	);

	-- The probes covering index is deliberately NOT created here: this
	-- base DDL runs on EVERY boot (all statements are IF NOT EXISTS),
	-- and after migration 14 the probes table has no sensor_id/ts
	-- columns — a legacy index line would fail every boot of a migrated
	-- DB. Migration 13 owns the TEXT-era index (transient: it exists
	-- only on fresh installs until migration 14 drops the table that
	-- carries it); migration 14 creates the new layout's index
	-- (idx_probes_cov).
	CREATE INDEX IF NOT EXISTS idx_events_sensor_ts ON events(sensor_id, ts);
	-- /api/events sorts the whole feed by e.ts (across all sensors), which the
	-- composite (sensor_id, ts) index above cannot serve. The table is 24h-
	-- bounded so this is cheap insurance, not a hot path — but the index is
	-- free, so the event feed's ORDER BY e.ts uses it instead of a full sort.
	CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

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
	// Numbered, transactional schema migrations:
	// each step runs in its OWN transaction and advances PRAGMA
	// user_version inside that same transaction, so a crash can never
	// leave a half-applied step (the tag migration used to straddle
	// INSERT … SELECT and DROP COLUMN across two implicit transactions,
	// safe on replay only because INSERT OR IGNORE deduped the copy).
	//
	// Replay model: every pre-versioned DB (fleet and test fixtures)
	// reads user_version = 0, so its first boot after upgrade runs the
	// whole list once and stamps the head. That is why each step keeps
	// its pragma/data guards INSIDE the tx: they make every step a
	// no-op on an already-migrated DB, which is what makes replay from
	// 0 safe. Subsequent boots read the version and skip the list.
	ver, err := db.schemaVersion()
	if err != nil {
		return err
	}
	if ver > schemaVersionHead {
		// A DB stamped by a NEWER binary: this build's migration list
		// has no entry for the extra step(s), so the loop below would
		// be a pure skip that accepts a schema this binary cannot fully
		// read. Refuse to start — restore a backup or run the newer
		// binary. History: docs/DECISIONS.md → db-ctx-torn-reads-resources
		return fmt.Errorf("database schema version %d is newer than this binary's %d: refusing to start with a schema it cannot fully read", ver, schemaVersionHead)
	}
	for v := ver; v < len(schemaMigrations); v++ {
		if err := db.applyMigration(v+1, schemaMigrations[v]); err != nil {
			return err
		}
	}
	return nil
}

// schemaMigration is one numbered step of the schema history: a human
// label plus a body that runs inside the step's transaction. The body
// gets the Store too (two Go-side steps reuse Store helpers and run on
// pool connections; their transactions are read-only, so no lock
// interplay). Bodies KEEP their idempotency guards: user_version makes
// the common path a skip, the guards make replay safe.
type schemaMigration struct {
	name string
	run  func(db *Store, tx *sql.Tx) error
}

// schemaMigrations is the append-only migration history; the 1-based
// index is the PRAGMA user_version value. NEVER renumber or edit an
// applied step — fleet DBs are stamped by position; add the next one.
var schemaMigrations = []schemaMigration{
	{
		// 1: legacy single-tag column → sensor_tags table. Atomic now:
		// copy + DROP land in ONE transaction. INSERT OR IGNORE stays as
		// the replay guard for DBs that half-applied this step under
		// the old non-transactional regime.
		name: "sensors.tag -> sensor_tags",
		run: func(db *Store, tx *sql.Tx) error {
			var tagCol int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sensors') WHERE name = 'tag'`).Scan(&tagCol); err != nil {
				return err
			}
			if tagCol == 0 {
				return nil
			}
			if _, err := tx.Exec(`INSERT OR IGNORE INTO sensor_tags (sensor_id, tag)
				SELECT id, tag FROM sensors WHERE tag IS NOT NULL AND TRIM(tag) <> ''`); err != nil {
				return err
			}
			if _, err := tx.Exec(`ALTER TABLE sensors DROP COLUMN tag`); err != nil {
				return err
			}
			log.Println("schema: migrated sensors.tag -> sensor_tags")
			return nil
		},
	},
	{
		// 2: per-sensor latency-spike multiplier. LIVE (dashboard-only):
		// sparkline bars at/above spike_mult × the window's average RTT
		// render amber (absolute red >200 ms unchanged). The probe engine
		// never reads it — status derivation is unaffected — so it is a
		// display tuning knob, editable per sensor in the dashboard modal.
		name: "sensors.spike_mult",
		run:  addColumnIfMissing("sensors", "spike_mult", `ALTER TABLE sensors ADD COLUMN spike_mult INTEGER NOT NULL DEFAULT 5`),
	},
	{
		// 3: record what each probe resolved to (diagnoses "sensors that
		// never respond" — a NULL/absent resolved_ip means the DNS lookup
		// never returned, the leading cause of a stalled sensor).
		name: "probes.resolved_ip",
		run:  addColumnIfMissing("probes", "resolved_ip", `ALTER TABLE probes ADD COLUMN resolved_ip TEXT`),
	},
	{
		// 4: HTTP status code for HTTP sensors (NULL for ICMP probes and
		// no-response probes), so a card can show "HTTP 503" vs
		// "no response" for the same loss row.
		name: "probes.http_status",
		run:  addColumnIfMissing("probes", "http_status", `ALTER TABLE probes ADD COLUMN http_status INTEGER`),
	},
	{
		// 5: tag "Pulse Now" manual probes (manual=1). Manual rows stay in
		// history — sparkline, graph, inspector — but are EXCLUDED from
		// status derivation (recentFromDB/recentFromCache filter them),
		// honoring the contract that a manual pulse never affects status
		// or alerts (before the tag, one lost manual pulse + one lost
		// scheduled probe tripped the down_after=2 consecutive-loss test
		// into an "error" alert). Existing rows are all scheduled probes,
		// so DEFAULT 0 is exactly right.
		name: "probes.manual",
		run:  addColumnIfMissing("probes", "manual", `ALTER TABLE probes ADD COLUMN manual INTEGER NOT NULL DEFAULT 0`),
	},
	{
		// 6: name-resolution failure for ICMP probes lost BEFORE a target
		// IP could be determined (NULL for packet losses and HTTP probes).
		// The homelab resolver (Pi-hole/AdGuard) is itself a monitored
		// sensor: its death used to flip every hostname sensor to "error"
		// at once — one root cause, an N-sensor storm that read as "N
		// hosts down" — because a DNS loss was indistinguishable from a
		// packet loss.
		name: "probes.dns_error",
		run:  addColumnIfMissing("probes", "dns_error", `ALTER TABLE probes ADD COLUMN dns_error TEXT`),
	},
	{
		// 7: sensor probe type. Existing sensors default to 'icmp' (the
		// original and only type), so this is a no-op data-wise; it lets
		// the probe worker dispatch the right probe.
		name: "sensors.type",
		run:  addColumnIfMissing("sensors", "type", `ALTER TABLE sensors ADD COLUMN type TEXT NOT NULL DEFAULT 'icmp'`),
	},
	{
		// 8: normalize legacy empty probe type to 'icmp'. The type column
		// was added with DEFAULT 'icmp', but rows created before the
		// column existed have type=''. The read paths used to normalize
		// ''→'icmp' in 6 places; this migration makes the DB the single
		// source of truth, so those normalizations are removed.
		name: "sensors.type '' -> icmp",
		run: func(db *Store, tx *sql.Tx) error {
			_, err := tx.Exec(`UPDATE sensors SET type = 'icmp' WHERE type = ''`)
			return err
		},
	},
	{
		// 9: rename stored statuses (v0.1.13): "down" was the old name
		// for error and "degraded" for warning; without this, the first
		// probe after upgrade would log a spurious transition and fire a
		// one-time alert on every already-affected sensor.
		//
		// Each UPDATE is filtered to the legacy rows it actually
		// rewrites. An unfiltered `UPDATE ... SET col = CASE ... ELSE col
		// END` matches EVERY row and, in SQLite, re-assigns+re-writes
		// each one even where the value is unchanged — so on a
		// fully-migrated Store this forced a full-table WAL write on
		// every boot, churning pages and blocking active probe writes
		// (WAL has a single writer). With the WHERE, a no-op replay
		// touches zero rows.
		name: "status rename down/degraded -> error/warning",
		run: func(db *Store, tx *sql.Tx) error {
			stmts := []string{
				`UPDATE sensors SET status = CASE status
					WHEN 'down' THEN 'error'
					WHEN 'degraded' THEN 'warning'
					ELSE status END
					WHERE status IN ('down', 'degraded')`,
				`UPDATE events SET from_status = CASE from_status
					WHEN 'down' THEN 'error' WHEN 'degraded' THEN 'warning' ELSE from_status END
					WHERE from_status IN ('down', 'degraded')`,
				`UPDATE events SET to_status = CASE to_status
					WHEN 'down' THEN 'error' WHEN 'degraded' THEN 'warning' ELSE to_status END
					WHERE to_status IN ('down', 'degraded')`,
				`UPDATE alert_state SET status = CASE status
					WHEN 'down' THEN 'error'
					WHEN 'degraded' THEN 'warning'
					ELSE status END
					WHERE status IN ('down', 'degraded')`,
				// Cosmetic: old event notes read "up -> degraded" / "down -> up".
				`UPDATE events SET note = replace(replace(replace(note, 'degraded', 'warning'), 'down', 'error'), 'warning -> up', 'recovered') WHERE note LIKE '%degraded%' OR note LIKE '%down%'`,
			}
			for _, s := range stmts {
				if _, err := tx.Exec(s); err != nil {
					return err
				}
			}
			return nil
		},
	},
	{
		// 10: per-provider alert keys (v0.1.14). The single legacy
		// "webhook_url" was the Google Chat URL, so move it to
		// google_chat_url and mark the provider enabled (a fresh install
		// has no legacy row, so it leaves both unset → off). Without
		// this, existing installs would silently lose their configured
		// alert webhook on upgrade.
		//
		// INSERT OR IGNORE: the NOT EXISTS guard only checks for a
		// NON-EMPTY google_chat_url, so an install whose operator later
		// CLEARED the Google Chat URL (row exists, value = '') re-ran
		// this INSERT and hit the settings.setting_key PRIMARY KEY
		// constraint — InitSchema failed and runServer log.Fatalf'd,
		// crash-looping the service. OR IGNORE makes the re-insert a
		// no-op: a cleared provider stays cleared.
		name: "webhook_url -> google_chat settings",
		run: func(db *Store, tx *sql.Tx) error {
			if _, err := tx.Exec(`INSERT OR IGNORE INTO settings (setting_key, value, updated_at)
				SELECT 'google_chat_url', value, COALESCE(updated_at, datetime('now'))
				FROM settings WHERE setting_key = 'webhook_url' AND TRIM(value) <> ''
				AND NOT EXISTS (SELECT 1 FROM settings WHERE setting_key = 'google_chat_url' AND TRIM(value) <> '')`); err != nil {
				return err
			}
			_, err := tx.Exec(`INSERT OR REPLACE INTO settings (setting_key, value, updated_at)
				SELECT 'google_chat_enabled', '1', COALESCE(updated_at, datetime('now'))
				FROM settings WHERE setting_key = 'webhook_url' AND TRIM(value) <> ''
				AND NOT EXISTS (SELECT 1 FROM settings WHERE setting_key = 'google_chat_enabled')`)
			return err
		},
	},
	{
		// 11: no-op by design (number preserved — fleet DBs are stamped by
		// position, never renumber). The legacy auth_token -> admin-user
		// conversion is an idempotent STARTUP step (runServer calls
		// MigrateLegacyAuthToken every boot), not a versioned step: a
		// deferred pass must stay retryable, and a version stamp would
		// commit on deferral and skip the retry forever — stamping a
		// deferred pass opened token-protected installs (0 users + dead
		// token = fully open dashboard).
		// History: docs/DECISIONS.md → legacy-token-startup-step
		name: "legacy auth_token -> admin user (no-op; startup step)",
		run:  func(db *Store, tx *sql.Tx) error { return nil },
	},
	{
		// 12: users.is_admin + promote the oldest user when no admin
		// exists (the account panel is admin-gated; an existing install
		// must never boot with zero admins). Runs AFTER the legacy token
		// slot so the migrated 'admin' account gets promoted. Idempotent
		// by its own guards; runs ON the step tx so the column, the
		// promotion, and the version stamp commit atomically (a crash
		// mid-step replays the whole step).
		// History: docs/DECISIONS.md → legacy-token-startup-step
		name: "users.is_admin + oldest-admin promotion",
		run:  func(db *Store, tx *sql.Tx) error { return db.migrateUserAdminColumn(tx) },
	},
	{
		// 13: probes index → covering. The (sensor_id, ts) index served
		// the range but not the SELECT list: warmStats Phase 1 (the 24h
		// window, ~1.7M rows at 100 sensors / 5s) and every
		// recentFromDB/history read paid a random table B-tree lookup
		// per row for rtt_ms + manual (~6.3s on the live fleet, against
		// the default 2 MiB page cache). The covering index reads
		// straight from the leaf pages. Runs in the step tx with the
		// version stamp (a few seconds of write lock at boot, once);
		// the CREATE/DROP guards keep replay a no-op.
		// History: docs/DECISIONS.md → sqlite-scalability-container-hazards
		name: "idx_probes_sensor_ts -> covering",
		run: func(db *Store, tx *sql.Tx) error {
			// Shape guard (migration 14 era): on a DB that already went
			// through the INTEGER-layout swap, probes has no sensor_id/
			// ts columns — creating the TEXT-era index would fail.
			// Replay-from-0 must be a no-op here; migration 14 owns the
			// new layout's index.
			var legacyTS int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('probes') WHERE name = 'ts'`).Scan(&legacyTS); err != nil {
				return err
			}
			if legacyTS == 0 {
				return nil
			}
			if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_probes_sensor_ts_cov ON probes(sensor_id, ts, rtt_ms, manual)`); err != nil {
				return err
			}
			if _, err := tx.Exec(`DROP INDEX IF EXISTS idx_probes_sensor_ts`); err != nil {
				return err
			}
			return nil
		},
	},
	{
		// 14: probes row layout -> INTEGER keys (sk + epoch-ms ts_ms).
		// Every probe row AND its covering index carried a 36-byte TEXT
		// UUID plus a 30-byte TEXT timestamp: 197 B/row simulated at the
		// 100-sensor / 5s / 24h envelope vs 68 B/row for an INTEGER key +
		// epoch-ms (317 MB -> 99.5 MB, 3.2x — the single biggest lever on
		// purge time, warm-up time, VACUUM-INTO backup size, and SD-card
		// wear). The swap is a single atomic replacement as far as the app
		// is concerned: no code path ever reads both shapes and there is
		// no dual-write transition. The table name stays `probes` (build
		// probes_v2 -> copy -> drop old -> rename), so the write/read
		// sites change only column names (sensor_id -> sk, ts -> ts_ms).
		//
		// sensors.sk is the surrogate key: a rowid backfill for existing
		// rows, and the sensors_sk_autogen trigger for every future
		// insert — one DDL line covers all creation paths (API create,
		// clone, seed, CLI, tests) without touching a single INSERT.
		//
		// The whole swap runs in the step transaction (the framework's
		// crash contract: a crash rolls the step back whole, the stamp
		// commits with it). Consequence: the WAL grows to the size of the
		// copied table for the duration of the step — a ~30 MB spike at
		// the current 22-sensor fleet, a ~500 MB spike at the 100-sensor
		// envelope (journal_size_limit caps post-commit checkpoints, not
		// in-tx growth). Accepted: the fleet is far from the envelope,
		// and the alternative (chunked copies across commits) breaks the
		// step's single-tx atomicity. If the envelope becomes real, the
		// lever is a chunked startup pass, not a renumbered step.
		//
		// The ts backfill is exact INTEGER arithmetic (strftime %s ->
		// seconds, %f -> .SSS): sub-millisecond storage precision is
		// deliberately dropped — ms is the design granularity, and the
		// old covering index dies with DROP TABLE (indexes belong to
		// their table).
		//
		// Replay guard: a probes table that already has ts_ms (this step
		// ran, or a fresh install replaying 1..N from 0 over its
		// legacy-anchor DDL) skips the step. Integrity guard: a ts that
		// is not TEXT, or TEXT SQLite cannot parse, fails the step
		// LOUDLY — strftime on a numeric ts interprets integers as Julian
		// day numbers (12345 -> year 33 AD) and would backfill
		// plausible-looking garbage. History: docs/DECISIONS.md ->
		// probe-rows-int-schema
		name: "probes -> (sk, ts_ms) INTEGER layout",
		run: func(db *Store, tx *sql.Tx) error {
			var hasNewLayout int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('probes') WHERE name = 'ts_ms'`).Scan(&hasNewLayout); err != nil {
				return err
			}
			if hasNewLayout > 0 {
				return nil
			}
			var bad int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM probes WHERE typeof(ts) IS NOT 'text' OR date(ts) IS NULL`).Scan(&bad); err != nil {
				return err
			}
			if bad > 0 {
				return fmt.Errorf("%d probes row(s) carry a ts that is not parseable TEXT: refusing to convert (restore a backup or repair the rows)", bad)
			}
			if _, err := tx.Exec(`ALTER TABLE sensors ADD COLUMN sk INTEGER`); err != nil {
				return err
			}
			// rowid is stable and unique (sensors is a rowid table); the
			// WHERE keeps a replay at zero touched rows.
			if _, err := tx.Exec(`UPDATE sensors SET sk = rowid WHERE sk IS NULL`); err != nil {
				return err
			}
			if _, err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_sensors_sk ON sensors(sk)`); err != nil {
				return err
			}
			// Auto-generate sk for every future sensor insert (the WHEN
			// guard leaves explicit sk values alone).
			if _, err := tx.Exec(`CREATE TRIGGER IF NOT EXISTS sensors_sk_autogen AFTER INSERT ON sensors
				WHEN NEW.sk IS NULL
				BEGIN
					UPDATE sensors SET sk = rowid WHERE rowid = NEW.rowid;
				END`); err != nil {
				return err
			}
			if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS probes_v2 (
				id INTEGER PRIMARY KEY,
				sk INTEGER NOT NULL REFERENCES sensors(sk) ON DELETE CASCADE,
				ts_ms INTEGER NOT NULL,
				rtt_ms REAL,
				resolved_ip TEXT,
				http_status INTEGER,
				dns_error TEXT,
				manual INTEGER NOT NULL DEFAULT 0
			)`); err != nil {
				return err
			}
			if _, err := tx.Exec(`INSERT INTO probes_v2 (id, sk, ts_ms, rtt_ms, resolved_ip, http_status, dns_error, manual)
				SELECT p.id, s.sk,
					CAST(strftime('%s', p.ts) AS INTEGER) * 1000 + CAST(SUBSTR(strftime('%f', p.ts), 4) AS INTEGER),
					p.rtt_ms, p.resolved_ip, p.http_status, p.dns_error, p.manual
				FROM probes p JOIN sensors s ON s.id = p.sensor_id`); err != nil {
				return err
			}
			if _, err := tx.Exec(`DROP TABLE probes`); err != nil {
				return err
			}
			if _, err := tx.Exec(`ALTER TABLE probes_v2 RENAME TO probes`); err != nil {
				return err
			}
			// Same covering shape as the pre-swap index, on the new
			// columns (the old one died with DROP TABLE).
			if _, err := tx.Exec(`CREATE INDEX idx_probes_cov ON probes(sk, ts_ms, rtt_ms, manual)`); err != nil {
				return err
			}
			log.Println("schema: migrated probes -> (sk, ts_ms) INTEGER layout")
			return nil
		},
	},
}

// schemaVersionHead is the applied-migration count a fully-migrated DB
// carries in PRAGMA user_version.
var schemaVersionHead = len(schemaMigrations)

// addColumnIfMissing builds the standard guarded-ALTER body: the pragma
// probe is the replay guard (no-op once the column exists).
func addColumnIfMissing(table, column, ddl string) func(*Store, *sql.Tx) error {
	return func(db *Store, tx *sql.Tx) error {
		var col int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('` + table + `') WHERE name = '` + column + `'`).Scan(&col); err != nil {
			return err
		}
		if col > 0 {
			return nil
		}
		_, err := tx.Exec(ddl)
		return err
	}
}

// schemaVersion reads PRAGMA user_version (0 = pre-versioning, every
// existing DB before this scheme).
func (db *Store) schemaVersion() (int, error) {
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return 0, err
	}
	return v, nil
}

// applyMigration runs one numbered step inside its own transaction and
// stamps user_version inside the SAME transaction: the step and its
// stamp commit atomically, so a crash mid-step replays the step whole on
// the next boot (never a half-step, never a stamped half-step).
func (db *Store) applyMigration(v int, m schemaMigration) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op after a successful Commit
	if err := m.run(db, tx); err != nil {
		return fmt.Errorf("schema migration %d (%s): %w", v, m.name, err)
	}
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", v)); err != nil {
		return fmt.Errorf("schema migration %d (%s): stamp: %w", v, m.name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("schema migration %d (%s): commit: %w", v, m.name, err)
	}
	log.Printf("schema: applied migration %d (%s)", v, m.name)
	return nil
}

// migrateUserAdminColumn adds users.is_admin to pre-admin-flag DBs and
// promotes the oldest user when the table has no admin. Runs inside the
// migration step's transaction: the column, the promotion, and the version
// stamp commit atomically, so a crash mid-step replays the whole step
// (both statements are idempotent, so the replay is safe).
func (db *Store) migrateUserAdminColumn(tx *sql.Tx) error {
	var n int
	if err := tx.QueryRow("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name = 'is_admin'").Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := tx.Exec("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0"); err != nil {
			return err
		}
	}
	res, err := tx.Exec(userAdminPromoteSQL)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 1 {
		log.Println("Promoted the oldest dashboard user to admin (is_admin migration)")
	}
	return nil
}

// userAdminPromoteSQL promotes the oldest user when the table has no admin.
// A var (not a literal) so tests can swap in a failing statement to prove
// the step's atomicity — the WHOLE step (column + promotion + stamp) must
// roll back, not just the stamp.
var userAdminPromoteSQL = `UPDATE users SET is_admin = 1
	WHERE rowid = (SELECT rowid FROM users ORDER BY created_at ASC, username ASC LIMIT 1)
	AND (SELECT COUNT(*) FROM users WHERE is_admin = 1) = 0`

// SensorTags returns the sorted tag list for a sensor. ctx + error follow
// the request-context contract: the old swallow-to-
// empty shape made a dead client ctx or a transient DB failure look like
// "sensor has no tags" — for handleSensorByID / handleSensorClone that is a
// lie rendered to the operator, so they surface the error (500) now.
func (db *Store) SensorTags(ctx context.Context, id string) ([]string, error) {
	rows, err := db.QueryContext(ctx, "SELECT tag FROM sensor_tags WHERE sensor_id = ? ORDER BY tag", id)
	if err != nil {
		return nil, err
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
		// Mid-stream iteration error (Store file I/O failure): same
		// contract as the query error above — the caller decides.
		return nil, err
	}
	return out, nil
}

// InQueryChunk is the max number of ids per IN(...) chunk for batch queries.
// modernc.org/sqlite (v1.29.1) accepts up to 32,766 bound parameters
// (verified against the real driver: 32,766 binds, 32,767 fails with "too
// many SQL variables"). A query that repeats an id list N times needs
// N*chunk params, so a fixed 500 stays far under the limit with headroom for
// the repeated lists (warmStats uses its id list twice, once per UNION arm).
// A realistic homelab fleet runs on a single chunk; the cap only engages if
// the fleet ever grows to thousands of sensors, where it prevents the query
// from failing outright with "too many SQL variables".
const InQueryChunk = 500

// SensorTagsFor fetches the sorted tag lists for a batch of sensors. It runs
// in InQueryChunk-sized batches so an unbounded id list can't exceed the
// SQLite host-parameter limit. Batch callers (fetchSensors, syncSensors) must
// not run a per-row SensorTags() inside a rows.Next() loop: the outer
// iteration holds a pooled connection, and per-row queries starve the pool
// under concurrent load. Empty ids → empty map; ids are internal UUIDs (no
// user string injection). ctx + error: the chunk-query
// error is now RETURNED, not logged-and-skipped — a silently-skipped chunk
// made the affected sensors route alerts as if they had NO tags. Each caller
// owns the failure policy: request callers (fetchSensors) fail the request;
// the background reconcile (syncSensors) logs with the old message and
// keeps reconciling (the documented untagged-routing tradeoff survives,
// visibly). Corrupt rows are still skipped with a log.
func (db *Store) SensorTagsFor(ctx context.Context, ids []string) (map[string][]string, error) {
	out := make(map[string][]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	// Closure per chunk: defer closes this chunk's cursor when the chunk
	// finishes, before the next chunk's query runs — top-level defer, not a
	// bare close below a loop, so no pooled connection is held across chunks.
	fetchChunk := func(chunk []string) error {
		q := make([]string, len(chunk))
		args := make([]any, len(chunk))
		for j, id := range chunk {
			q[j] = "?"
			args[j] = id
		}
		// ORDER BY sensor_id, tag uses the (sensor_id, tag) PK B-tree directly
		// (no temp sort); the per-sensor output is identical to ORDER BY tag
		// because tags within a sensor are still alphabetical.
		rows, err := db.QueryContext(ctx, "SELECT sensor_id, tag FROM sensor_tags WHERE sensor_id IN ("+
			strings.Join(q, ",")+") ORDER BY sensor_id, tag", args...)
		if err != nil {
			return err
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
		return rows.Err()
	}
	for i := 0; i < len(ids); i += InQueryChunk {
		end := i + InQueryChunk
		if end > len(ids) {
			end = len(ids)
		}
		if err := fetchChunk(ids[i:end]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// SetSensorTags atomically replaces a sensor's tags: DELETE then INSERTs in
// ONE transaction, so a mid-loop error (or a crash) rolls back cleanly and
// the sensor is never left with a partial/empty tag set. A torn tag set is
// worse than stale tags: with alert_scope='tags' it silently changes which
// sensors alert.
func (db *Store) SetSensorTags(id string, tags []string) error {
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

// settingsTxLockKey: sentinel key of the zero-row UPDATE that pins
// SQLite's write lock at the start of every read-then-write deferred tx
// (the maintenance transitions here, the settings PUT in api.go). A
// deferred tx that starts as a READER and upgrades to a write after a
// concurrent commit fails fast with SQLITE_BUSY_SNAPSHOT (517), which
// busy_timeout does NOT retry; pinning the lock with a zero-row UPDATE
// (the \x00 prefix matches no real setting) serializes colliding writers
// into wait-then-succeed.
const settingsTxLockKey = "\x00pulsemon-txlock"

// EnterMaintenanceWithFreshSnapshot enters maintenance mode with the
// active-sensor snapshot computed INSIDE the pause transaction itself.
// The handler used to read ActiveSensorIDs before
// the settings tx and apply that pre-tx list afterwards: a sensor activated
// (or created) between the read and the pause escaped the snapshot and kept
// probing under a mode that reads as ON until the next maintenance cycle.
// One transaction now: SELECT active ids → pause them → write snapshot +
// mode flag. Returns the ids actually paused (the handler feeds them to the
// SetPaused in-memory fast path). The handler's earlier read survives only
// as a UX pre-check (400 "no active sensors"); this read is authoritative.
//
// The mode flag is re-checked UNDER the write lock: the handler's pre-tx
// read (maintAlreadyOn) can be stale — two concurrent enters (a
// double-click) both read "0" and both get here, and the loser's SELECT
// active ids sees 0 rows (the winner paused them all) and would marshal
// "null" over the winner's good snapshot. Leaving maintenance would then
// decode "null" as an empty restore set and resume NOTHING — the whole
// fleet stranded paused. Already ON: no-op, the original snapshot is
// preserved (re-snapshotting would also drop sensors the operator resumed
// during maintenance).
func (db *Store) EnterMaintenanceWithFreshSnapshot(ctx context.Context) ([]string, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit succeeds
	// Pin the write lock BEFORE the snapshot read: a deferred
	// reader tx that upgrades after a concurrent commit fails fast with
	// SQLITE_BUSY_SNAPSHOT, which busy_timeout does not retry. See
	// settingsTxLockKey.
	if _, err := tx.ExecContext(ctx, "UPDATE settings SET value = value WHERE setting_key = ?", settingsTxLockKey); err != nil {
		return nil, err
	}
	// In-tx re-check of the mode flag (the pre-tx handler read is stale
	// under a concurrent enter — see the doc note).
	var cur string
	err = tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE setting_key = 'maintenance_mode'").Scan(&cur)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if cur == "1" {
		return nil, nil // already in maintenance; preserve existing snapshot
	}
	rows, err := tx.QueryContext(ctx, "SELECT id FROM sensors WHERE state = 'active' ORDER BY name")
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
	if err := applyMaintenanceTx(ctx, tx, true, ids, string(snap)); err != nil {
		return nil, err
	}
	return ids, nil
}

// LeaveMaintenanceFromSnapshot leaves maintenance mode reading the
// restore-set snapshot INSIDE the resume transaction — the mirror of
// EnterMaintenanceWithFreshSnapshot. Contract: pin the write lock → SELECT
// snapshot → resume those ids → clear snapshot + mode flag, one tx;
// returns the ids actually resumed (the handler feeds them to the
// SetPaused in-memory fast path). A snapshot that fails to decode is a
// HARD error with the tx rolled back — mode stays ON and the value stays
// on disk for inspection; the restore set must never be silently guessed
// from a failed read. A MISSING snapshot row is not an error (a pre-rework
// DB has no restore set to lose). History: docs/DECISIONS.md →
// maintenance-leave-fails-loud.
func (db *Store) LeaveMaintenanceFromSnapshot(ctx context.Context) ([]string, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit succeeds
	if _, err := tx.ExecContext(ctx, "UPDATE settings SET value = value WHERE setting_key = ?", settingsTxLockKey); err != nil {
		return nil, err
	}
	var snap string
	err = tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE setting_key = 'maintenance_active_ids'").Scan(&snap)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var ids []string
	if snap != "" {
		if err := json.Unmarshal([]byte(snap), &ids); err != nil {
			return nil, fmt.Errorf("maintenance snapshot is not valid JSON (%q): %w", snap, err)
		}
	}
	if err := applyMaintenanceTx(ctx, tx, false, ids, ""); err != nil {
		return nil, err
	}
	return ids, nil
}

// applyMaintenanceTx is the body of both maintenance transitions, running
// on the caller's tx and committing it on success. ctx is threaded into
// every Exec so a dead request context aborts the transition mid-statement
// instead of parking on the write lock (History: docs/DECISIONS.md →
// db-ctx-torn-reads-resources).
func applyMaintenanceTx(ctx context.Context, tx *sql.Tx, on bool, ids []string, snapJSON string) error {

	state := "paused"
	modeVal := "1"
	if !on {
		state = "active"
		modeVal = "0"
		snapJSON = "" // clear the snapshot on resume
	}

	// 1. Pause/resume the sensors (chunked to stay under SQLite's param limit).
	if len(ids) > 0 {
		for start := 0; start < len(ids); start += InQueryChunk {
			end := start + InQueryChunk
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
			if _, err := tx.ExecContext(ctx, "UPDATE sensors SET state = ? WHERE id IN ("+strings.Join(q, ",")+")", args...); err != nil {
				return err
			}
		}
	}

	// 2. Save/clear the snapshot.
	if _, err := tx.ExecContext(ctx, `INSERT INTO settings (setting_key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(setting_key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		"maintenance_active_ids", snapJSON, Now()); err != nil {
		return err
	}

	// 3. Set the mode flag.
	if _, err := tx.ExecContext(ctx, `INSERT INTO settings (setting_key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(setting_key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		"maintenance_mode", modeVal, Now()); err != nil {
		return err
	}

	return tx.Commit()
}

// AllTags returns each distinct tag with the number of sensors using it.
// ctx + error: GET /api/tags renders this query's
// result as the whole payload, so a dead ctx or transient failure must
// surface as a 500 — the old swallow-to-empty map rendered a failure as
// "the fleet has no tags".
func (db *Store) AllTags(ctx context.Context) (map[string]int, error) {
	// (sensor_id, tag) is the PK, so each sensor_id appears exactly once per
	// tag group — COUNT(*) equals COUNT(DISTINCT sensor_id) without the
	// DISTINCT's extra dedup pass.
	rows, err := db.QueryContext(ctx, `SELECT tag, COUNT(*) FROM sensor_tags GROUP BY tag ORDER BY tag`)
	if err != nil {
		return nil, err
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
		// above — the caller decides.
		return nil, err
	}
	return out, nil
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
func (db *Store) ImmediateTx(ctx context.Context, fn func(c *sql.Conn) error) error {
	return immediateTx(ctx, db.DB, fn)
}

// ProbeImmediateTx is ImmediateTx on the capped probe-write handle (see
// NewStore / ProbeWriteTimeout): a stalled writer parks the sensor loop for
// ProbeWriteTimeout, not the main pool's 15s busy_timeout.
func (db *Store) ProbeImmediateTx(ctx context.Context, fn func(c *sql.Conn) error) error {
	return immediateTx(ctx, db.probeDB, fn)
}

// ProbeExecContext runs one statement on the capped probe-write handle.
// Same capping rationale as ProbeImmediateTx.
func (db *Store) ProbeExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return db.probeDB.ExecContext(ctx, query, args...)
}

func immediateTx(ctx context.Context, gdb *sql.DB, fn func(c *sql.Conn) error) error {
	conn, err := gdb.Conn(ctx)
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
	// writes wedged until restart (same failure mode the
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
		//: a ctx canceled at the driver skips the
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

// legacyTokenUserCount is MigrateLegacyAuthToken's UserCount read,
// swappable for tests (seam pattern): a failure here is exactly the
// transient DB error the deferral semantics exist for.
var legacyTokenUserCount = func(db *Store) (int, error) { return db.UserCount() }

// MigrateLegacyAuthToken converts a pre-accounts auth_token setting into
// the "admin" user (the stored hash is already bcrypt, so it verifies
// exactly as before) and then clears the setting — the users table is the
// source of truth.
//
// It is an idempotent STARTUP step (runServer calls it every boot, before
// migrateAuthBootstrapped), not a versioned migration: a deferred pass
// must stay retryable, and a version stamp would commit on deferral and
// skip the retry forever — stamping a deferred pass left a token-protected
// install with 0 users and a dead token, i.e. a fully open dashboard. The
// token is destroyed ONLY on a confirmed outcome (users already exist, or
// the INSERT committed): on a UserCount error or an INSERT failure the
// token stays in place and the next boot retries.
//
// The migrated 'admin' is inserted with is_admin = 1 directly: this step
// runs AFTER InitSchema's migration list, so slot 12's oldest-user
// promotion (which the token user used to ride) has already passed.
func MigrateLegacyAuthToken(db *Store) error {
	if db.GetSetting("auth_token") == "" {
		return nil
	}
	n, err := legacyTokenUserCount(db)
	if err != nil {
		log.Printf("WARNING: legacy auth_token migration deferred (user count failed: %v); token kept, retried next start", err)
		return nil
	}
	if n == 0 {
		if _, err := db.Exec(`INSERT INTO users (username, password_hash, is_admin, created_at)
			VALUES ('admin', (SELECT value FROM settings WHERE setting_key = 'auth_token'), 1, ?)`,
			Now()); err != nil {
			log.Printf("WARNING: legacy auth_token migration to users table failed: %v; token kept, retried next start", err)
			return nil
		}
		// This install has been set up — mark it so the gate doesn't
		// treat a later auth-off state as a fresh install.
		if err := db.SetSetting("auth_bootstrapped", "1"); err != nil {
			log.Println("WARNING: failed to set auth_bootstrapped flag:", err)
		}
		log.Println("Migrated legacy auth token to the 'admin' user; set a new password in Settings")
	} else {
		// The token's owner may already exist as a plain (non-admin)
		// user — e.g. created via the CLI before any server boot, when
		// slot 12's promotion pass had no rows to promote. An existing
		// install must never end up with zero admins, so guarantee one.
		if _, err := db.Exec(userAdminPromoteSQL); err != nil {
			log.Printf("WARNING: legacy auth_token migration: admin promotion failed: %v", err)
		}
	}
	if err := db.SetSetting("auth_token", ""); err != nil {
		return err
	}
	return nil
}

// DeleteTag removes one tag from every sensor; returns how many sensors lost it.
func (db *Store) DeleteTag(ctx context.Context, tag string) (int64, error) {
	res, err := db.ExecContext(ctx, "DELETE FROM sensor_tags WHERE tag = ?", tag)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteTagReturning removes one tag from every sensor and returns the
// sensor ids it came off of, atomically: the old pre-SELECT + DeleteTag
// pair left a TOCTOU window in which a sensor gaining/losing the tag
// between the two statements made the respawn list stale (a probe loop
// keeping alert routing for a tag it no longer has, until process
// restart). DELETE ... RETURNING hands back exactly the rows removed,
// so the list is correct by construction and no window exists.
// History: docs/DECISIONS.md → db-ctx-torn-reads-resources
func (db *Store) DeleteTagReturning(ctx context.Context, tag string) ([]string, error) {
	rows, err := db.QueryContext(ctx, "DELETE FROM sensor_tags WHERE tag = ? RETURNING sensor_id", tag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// GetSetting reads a key from the settings table ("" when absent).
func (db *Store) GetSetting(key string) string {
	var v string
	if err := db.QueryRow("SELECT value FROM settings WHERE setting_key = ?", key).Scan(&v); err != nil {
		return ""
	}
	return v
}

// GetSettingErr is GetSetting that surfaces real Store errors: an absent key is
// ("", nil), any other failure ("", err). GetSetting's call sites keep
// their swallow-to-"" contract; this exists for paths where "unset" and
// "read failed" must not look the same — alert delivery and the
// settings GET/PUT payload (settingsPayload, 2026-11-11).
func (db *Store) GetSettingErr(key string) (string, error) {
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

// GetAllSettings loads the whole settings table in ONE read. Snapshot
// loaders use this instead of N point reads: the settings PUT commits all
// of its keys in a single transaction, so N separate GetSetting reads can
// straddle that commit and install a HALF-APPLIED snapshot, while one
// SELECT observes a single consistent commit point. Errors propagate:
// a caller must abort, never fall back to per-key "" defaults.
func (db *Store) GetAllSettings() (map[string]string, error) {
	rows, err := db.Query("SELECT setting_key, value FROM settings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string, 24)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// TSLayout is the single writer-side timestamp format: UTC, ALWAYS 9
// fractional digits. Fixed width is what makes string order equal
// chronological order (time.RFC3339Nano trims trailing zeros, so "…25.13Z"
// sorted AFTER "…25.134Z"), which the string-compared retention purge and
// ORDER BY ts rely on. It still parses under time.RFC3339Nano, and rows
// written by older versions (variable width) remain readable.
const TSLayout = "2006-01-02T15:04:05.000000000Z"

// FormatTS formats t for storage in any ts column.
func FormatTS(t time.Time) string { return t.UTC().Format(TSLayout) }

// Now is FormatTS(now).
func Now() string { return FormatTS(time.Now()) }

func (db *Store) SetSetting(key, value string) error {
	_, err := db.Exec(`INSERT INTO settings (setting_key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(setting_key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, Now())
	return err
}

// SetSettingInTx is SetSetting through a caller's transaction (lets handleSettingsPut apply a multi-key save atomically).
// ctx is the caller's request context: every statement on the settings PUT
// apply phase runs bounded, so a client disconnect mid-handler fails fast at
// the call site instead of racing the transaction's cancellation watcher
// (api_context_test.go contract; the apply phase's BeginTx/txlock calls were
// already ctx-bound — the writes and the guard read below were not).
func SetSettingInTx(ctx context.Context, tx *sql.Tx, key, value string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO settings (setting_key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(setting_key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, Now())
	return err
}

// ---------- dashboard users (username/password auth) ----------

// UserCount returns how many dashboard accounts exist. Auth is enabled
// iff this is > 0.
func (db *Store) UserCount() (int, error) {
	var n int
	err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	return n, err
}

// UserHash returns the stored bcrypt hash for a username ("", sql.ErrNoRows
// when absent).
func (db *Store) UserHash(username string) (string, error) {
	var h string
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&h)
	if err != nil {
		return "", err
	}
	return h, nil
}

// SetUserPassword overwrites a user's hash.
func (db *Store) SetUserPassword(username, passwordHash string) error {
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
// ErrLastUser) or no such user (ErrUserNotFound): the sentinel replaced the
// silent no-op, which made the API answer 200 and the
// CLI print "User removed" for a mistyped name).
//
// ctx bounds the transaction: the caller's request context reaches the
// DELETE + last-admin promotion, so a client disconnect fails fast instead of
// running the transaction to completion on a hidden Background context. This
// is the transactional side of the Store context rule — methods that span a
// transaction (RemoveUser, ImmediateTx, SetSettingInTx) take a
// context.Context; single autocommit helpers (GetSetting, SetSetting,
// UserCount, UserHash, SetUserPassword) take none because they're short and
// called from handlers, background goroutines, the CLI, and tests alike.
func (db *Store) RemoveUser(ctx context.Context, username string) error {
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
				return fmt.Errorf("%w: %s", ErrUserNotFound, username)
			}
			return ErrLastUser
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
func (db *Store) RemoveAllUsers() error {
	_, err := db.Exec("DELETE FROM users")
	return err
}

type AuthUser struct {
	Username  string `json:"username"`
	CreatedAt string `json:"created_at"`
	IsAdmin   bool   `json:"is_admin"`
}

// ListUsers returns every account, oldest first (created_at is the standard
// app timestamp, RFC3339Nano).
func (db *Store) ListUsers() ([]AuthUser, error) {
	rows, err := db.Query("SELECT username, created_at, is_admin FROM users ORDER BY created_at, username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuthUser{}
	for rows.Next() {
		var u AuthUser
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
func (db *Store) ActiveSensorIDs(ctx context.Context) ([]string, error) {
	rows, err := db.QueryContext(ctx, "SELECT id FROM sensors WHERE state = 'active' ORDER BY name")
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

// SensorKey is one sensor's durable identity pair: the TEXT id (API
// surface, tags, events' FK) and the INTEGER sk (probes' FK key since
// the INTEGER row-layout migration).
type SensorKey struct {
	ID string
	Sk int64
}

// SensorKeys lists every sensor's (id, sk) pair, in name order. The
// retention purge walks this set: its probes branch keys on sk, its
// events branch on the TEXT id (events keep the TEXT layout).
func (db *Store) SensorKeys() ([]SensorKey, error) {
	rows, err := db.Query("SELECT id, sk FROM sensors ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []SensorKey
	for rows.Next() {
		var k SensorKey
		if err := rows.Scan(&k.ID, &k.Sk); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (db *Store) SeedSensors() error {
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM sensors").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	// Fresh-install demo sensors. Tuning matches the UI-created defaults in
	// the API (POST /api/sensors: 60s / 1000ms / 25% / 2) so a seeded sensor
	// and a dashboard-created one behave identically. They start PAUSED —
	// like UI-created sensors — because the targets are environment-neutral
	// placeholders (127.0.0.1: not every host runs a router or a server on
	// 192.168.1.x, and a wrong active target would fire down alerts on day
	// one). The user edits the targets and resumes. spike_mult is a
	// dashboard-only display knob (sparkline spike tint; the probe engine
	// never reads it, so it never affects status); the seed writes it
	// explicitly (3) for a stable row, below the column default of 5.
	sensors := []struct {
		name, target, tags string
	}{
		{"router", "127.0.0.1", "Networking"},
		{"server", "127.0.0.1", "Servers"},
	}

	for _, s := range sensors {
		// A real UUID id (not the name) so seeded sensors carry the same id
		// format as every API-created sensor.
		id := NewID()
		if _, err := db.Exec(`
			INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
			VALUES (?, ?, ?, 60, 1000, 25, 2, 3, 'paused', 'up', ?)`,
			id, s.name, s.target, Now()); err != nil {
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

// BackupTo writes a consistent, self-contained snapshot of the database
// to dst via `VACUUM INTO` (SQLite 3.27+; the bundled modernc sqlite is
// 3.4x). Unlike a plain file copy, the snapshot is valid while this store
// is actively serving WAL traffic - no stopped service needed. The
// pre-update safety copy (pulsemon.db.preupdate, see
// backupDatabasePreUpdate in update.go) uses this so the in-dashboard
// self-update can make its copy without pausing the monitor.
func (s *Store) BackupTo(dst string) error {
	_, err := s.Exec("VACUUM INTO ?", dst)
	return err
}

// SensorCount returns the number of configured sensors. The post-restart
// verifier (Windows restart-helper) compares it against the pre-update
// backup's count to detect a data-losing update.
func (s *Store) SensorCount() (int, error) {
	var n int
	err := s.QueryRow("SELECT COUNT(*) FROM sensors").Scan(&n)
	return n, err
}
