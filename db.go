package main

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
}

func NewDB(dsn string) (*DB, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// Multiple concurrent connections are required: the probe worker and HTTP
	// handlers issue nested queries (e.g. iterating sensors while fetching each
	// one's tags). With a single shared connection those nest and deadlock.
	// WAL mode allows concurrent readers; SQLite serializes writers internally.
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(4)
	db.SetConnMaxIdleTime(0)
	if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		return nil, err
	}
	if _, err := db.Exec("PRAGMA busy_timeout=10000;"); err != nil {
		return nil, err
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON;"); err != nil {
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

func (db *DB) SetSensorTags(id string, tags []string) error {
	if _, err := db.Exec("DELETE FROM sensor_tags WHERE sensor_id = ?", id); err != nil {
		return err
	}
	for _, t := range tags {
		if _, err := db.Exec("INSERT OR IGNORE INTO sensor_tags (sensor_id, tag) VALUES (?, ?)", id, t); err != nil {
			return err
		}
	}
	return nil
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

func (db *DB) SetSetting(key, value string) error {
	_, err := db.Exec(`INSERT INTO settings (setting_key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(setting_key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, time.Now().UTC().Format(time.RFC3339))
	return err
}

func (db *DB) SeedSensors() error {
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM sensors").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	sensors := []struct {
		name, target, tags string
	}{
		{"router", "192.168.1.1", "Core"},
		{"zenai", "192.168.1.19", "Servers"},
		{"zensrv", "192.168.1.9", "Servers"},
		{"zentest", "192.168.1.206", "Servers"},
	}

	for _, s := range sensors {
		if _, err := db.Exec(`
			INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, state, status, created_at)
			VALUES (?, ?, ?, 5, 2000, 5, 3, 'active', 'up', ?)`,
			s.name, s.name, s.target, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
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
