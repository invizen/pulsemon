package store

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These pins lock migration 14 (docs/DECISIONS.md -> probe-rows-int-schema):
// the probes table's swap from TEXT (sensor_id UUID + RFC3339Nano ts) to
// INTEGER (sk surrogate + epoch-ms ts_ms), and the sensors.sk surrogate the
// swap hangs on. The API ts string contract is untouched — the boundary
// converts epoch-ms <-> RFC3339Nano at the read sites.

// freshProbesColumns returns the probes table's column names in table order.
func freshProbesColumns(t *testing.T, db *Store) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM pragma_table_info('probes') ORDER BY cid`)
	if err != nil {
		t.Fatalf("pragma_table_info(probes): %v", err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatalf("scan column: %v", err)
		}
		cols = append(cols, c)
	}
	return cols
}

// TestProbesIntSchemaFresh pins the fresh-DB shape after 1..14: the probes
// table is the INTEGER layout (sk + ts_ms), sensors carries the sk
// surrogate with its unique index and autogen trigger, and the covering
// index covers (sk, ts_ms, rtt_ms, manual) — the exact SELECT list of
// warmStats Phase 1/2, recentFromDB, and /history.
func TestProbesIntSchemaFresh(t *testing.T) {
	db := openTestStore(t)

	want := []string{"id", "sk", "ts_ms", "rtt_ms", "resolved_ip", "http_status", "dns_error", "manual"}
	got := freshProbesColumns(t, db)
	if len(got) != len(want) {
		t.Fatalf("probes columns = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("probes column %d = %q, want %q", i, got[i], want[i])
		}
	}
	for _, dead := range []string{"idx_probes_sensor_ts", "idx_probes_sensor_ts_cov"} {
		if indexExists(t, db, dead) {
			t.Errorf("TEXT-era index %s still present on a fresh DB", dead)
		}
	}
	cov := indexColumns(t, db, "idx_probes_cov")
	if len(cov) != 4 || cov[0] != "sk" || cov[1] != "ts_ms" || cov[2] != "rtt_ms" || cov[3] != "manual" {
		t.Fatalf("idx_probes_cov = %v, want [sk ts_ms rtt_ms manual]", cov)
	}
	var sensorSk int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sensors') WHERE name = 'sk'`).Scan(&sensorSk); err != nil {
		t.Fatalf("sensors.sk probe: %v", err)
	}
	if sensorSk != 1 {
		t.Fatal("sensors table is missing the sk surrogate column")
	}
	if !indexExists(t, db, "idx_sensors_sk") {
		t.Fatal("idx_sensors_sk missing")
	}
	var trig int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name = 'sensors_sk_autogen'`).Scan(&trig); err != nil {
		t.Fatalf("trigger probe: %v", err)
	}
	if trig != 1 {
		t.Fatal("sensors_sk_autogen trigger missing")
	}
	if v := getUserVersion(t, db); v != schemaVersionHead {
		t.Fatalf("fresh DB user_version = %d, want head %d", v, schemaVersionHead)
	}
}

// TestSensorsSkAutogen pins the surrogate-key contract: an INSERT that
// omits sk gets one assigned (rowid), an INSERT with an explicit sk keeps
// it, and the unique index rejects a second row with the same sk. This is
// what lets every existing sensor-creation path (API create, clone, seed,
// CLI, tests) keep working without a single INSERT touched.
func TestSensorsSkAutogen(t *testing.T) {
	db := openTestStore(t)
	seed := `INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, state, status, created_at)
		VALUES (?, ?, '127.0.0.1', 30, 1000, 25, 2, 'active', 'up', ?)`
	if _, err := db.Exec(seed, "a", "a", Now()); err != nil {
		t.Fatalf("seed a: %v", err)
	}
	var skA int64
	if err := db.QueryRow(`SELECT sk FROM sensors WHERE id = 'a'`).Scan(&skA); err != nil {
		t.Fatalf("read sk a: %v", err)
	}
	if skA == 0 {
		t.Fatal("autogen trigger did not assign a sk (0 = unassigned)")
	}
	// Explicit sk is preserved by the trigger's WHEN guard.
	if _, err := db.Exec(seed, "b", "b", Now()); err != nil {
		t.Fatalf("seed b: %v", err)
	}
	if _, err := db.Exec(`UPDATE sensors SET sk = 4242 WHERE id = 'b'`); err != nil {
		t.Fatalf("set explicit sk: %v", err)
	}
	var skB int64
	if err := db.QueryRow(`SELECT sk FROM sensors WHERE id = 'b'`).Scan(&skB); err != nil {
		t.Fatalf("read sk b: %v", err)
	}
	if skB != 4242 {
		t.Fatalf("explicit sk = %d, want 4242 (the trigger must not clobber it)", skB)
	}
	// A fresh INSERT must not collide with an existing sk: the trigger
	// assigns rowid, which is unique by construction.
	if _, err := db.Exec(seed, "c", "c", Now()); err != nil {
		t.Fatalf("seed c: %v", err)
	}
	var skC int64
	if err := db.QueryRow(`SELECT sk FROM sensors WHERE id = 'c'`).Scan(&skC); err != nil {
		t.Fatalf("read sk c: %v", err)
	}
	if skC == skA || skC == skB {
		t.Fatalf("sk collision: c=%d a=%d b=%d", skC, skA, skB)
	}
	// The unique index is what makes sk a usable FK parent.
	if _, err := db.Exec(`UPDATE sensors SET sk = 4242 WHERE id = 'a'`); err == nil {
		t.Fatal("duplicate sk accepted — idx_sensors_sk is not unique")
	}
}

// buildV13Store creates a fresh store (which boots to v14) and reverts the
// probes layout to the legacy v13 shape — TEXT sensor_id + RFC3339Nano ts,
// the covering index on the old columns, no sensors.sk — then stamps
// user_version 13. The result is byte-for-byte the state of a fleet DB
// right before this change.
func buildV13Store(t *testing.T, dir string) *Store {
	t.Helper()
	st, err := NewStore(filepath.Join(dir, "v13.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := st.InitSchema(); err != nil {
		st.Close()
		t.Fatalf("InitSchema: %v", err)
	}
	stmts := []string{
		`DROP INDEX idx_probes_cov`,
		`DROP TABLE probes`,
		`CREATE TABLE probes (
			id INTEGER PRIMARY KEY,
			sensor_id TEXT NOT NULL,
			ts DATETIME NOT NULL,
			rtt_ms REAL,
			resolved_ip TEXT,
			http_status INTEGER,
			dns_error TEXT,
			manual INTEGER NOT NULL DEFAULT 0,
			FOREIGN KEY (sensor_id) REFERENCES sensors(id) ON DELETE CASCADE
		)`,
		`DROP TRIGGER sensors_sk_autogen`,
		`DROP INDEX idx_sensors_sk`,
		`ALTER TABLE sensors DROP COLUMN sk`,
		`PRAGMA user_version = 13`,
	}
	for _, s := range stmts {
		if _, err := st.Exec(s); err != nil {
			st.Close()
			t.Fatalf("revert to v13 (%s): %v", s, err)
		}
	}
	return st
}

// TestMigration14UpgradesV13ToV14 is the upgrade pin: a fleet DB stamped
// at 13 (the shape every live install had) boots through InitSchema into
// the INTEGER layout with its data converted — row counts preserved,
// ts_ms exact to the millisecond (both integer-second and fractional
// legacy rows), sensors.sk backfilled and unique, the FK live, the old
// indexes gone, and the version stamped at the head.
func TestMigration14UpgradesV13ToV14(t *testing.T) {
	dir := t.TempDir()
	st := buildV13Store(t, dir)

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seed := `INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, state, status, created_at)
		VALUES (?, ?, '127.0.0.1', 30, 1000, 25, 2, 'active', 'up', ?)`
	if _, err := st.Exec(seed, "a", "a", base.UTC().Format(time.RFC3339Nano)); err != nil {
		st.Close()
		t.Fatalf("seed sensor: %v", err)
	}
	// A SECOND sensor: with only one sensor, a broken join that maps every
	// probe to a constant sk is indistinguishable from the correct mapping
	// (sensor a's sk is 1, the same as any plausible constant). Two sensors
	// make the per-sensor sk assignment checkable.
	if _, err := st.Exec(seed, "b", "b", base.UTC().Format(time.RFC3339Nano)); err != nil {
		st.Close()
		t.Fatalf("seed sensor b: %v", err)
	}
	rows := []struct {
		ts     string
		rtt    string
		manual int
	}{
		{base.UTC().Format(time.RFC3339Nano), "10.0", 0},
		{base.Add(500 * time.Millisecond).UTC().Format(time.RFC3339Nano), "12.5", 0},
		{base.Add(time.Second).UTC().Format(time.RFC3339Nano), "NULL", 1},
	}
	for i, r := range rows {
		if _, err := st.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms, manual) VALUES ('a', ?, `+r.rtt+`, `+strconv.Itoa(r.manual)+`)`, r.ts); err != nil {
			st.Close()
			t.Fatalf("seed probe %d: %v", i, err)
		}
	}
	// sensor b: one row at base + 100ms, so the per-sensor sk check has a
	// second anchor.
	if _, err := st.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms, manual) VALUES ('b', ?, 7.25, 0)`,
		base.Add(100*time.Millisecond).UTC().Format(time.RFC3339Nano)); err != nil {
		st.Close()
		t.Fatalf("seed probe b: %v", err)
	}
	st.Close()

	// Boot again: InitSchema must run migration 14 over the v13 DB.
	st2, err := NewStore(filepath.Join(dir, "v13.db"))
	if err != nil {
		t.Fatalf("NewStore (reboot): %v", err)
	}
	defer st2.Close()
	if err := st2.InitSchema(); err != nil {
		t.Fatalf("InitSchema over v13 DB: %v", err)
	}
	if v := getUserVersion(t, st2); v != schemaVersionHead {
		t.Fatalf("user_version after migration = %d, want head %d", v, schemaVersionHead)
	}

	var n int
	if err := st2.QueryRow(`SELECT COUNT(*) FROM probes`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != len(rows)+1 {
		t.Fatalf("probe rows after migration = %d, want %d (the swap must lose no rows)", n, len(rows)+1)
	}

	// Sorted by ts_ms: a@base, b@base+100ms, a@base+500ms, a@base+1s.
	wantTS := []int64{
		base.UnixMilli(),
		base.Add(100 * time.Millisecond).UnixMilli(),
		base.Add(500 * time.Millisecond).UnixMilli(),
		base.Add(time.Second).UnixMilli(),
	}
	var gotTS []int64
	skCounts := map[int64]int{}
	rttVals := []float64{}
	manuals := []int{}
	rows2, err := st2.Query(`SELECT sk, ts_ms, rtt_ms, manual FROM probes ORDER BY ts_ms`)
	if err != nil {
		t.Fatalf("read probes: %v", err)
	}
	defer rows2.Close()
	for rows2.Next() {
		var sk int64
		var tsMS int64
		var rtt *float64
		var manual int
		if err := rows2.Scan(&sk, &tsMS, &rtt, &manual); err != nil {
			t.Fatalf("scan probe: %v", err)
		}
		gotTS = append(gotTS, tsMS)
		skCounts[sk]++
		if rtt != nil {
			rttVals = append(rttVals, *rtt)
		}
		manuals = append(manuals, manual)
	}
	for i := range wantTS {
		if gotTS[i] != wantTS[i] {
			t.Errorf("ts_ms[%d] = %d, want %d (the TEXT->ms backfill must be exact, fractional rows included)", i, gotTS[i], wantTS[i])
		}
	}
	// Per-sensor sk assignment: the join must map each row to ITS sensor's
	// sk (a -> 1, b -> 2), not to a constant.
	if skCounts[1] != 3 || skCounts[2] != 1 || len(skCounts) != 2 {
		t.Errorf("per-sensor sk counts = %v, want {1:3, 2:1} (the copy join must key on the sensor, not a constant)", skCounts)
	}
	for sk := range skCounts {
		if sk == 0 {
			t.Fatal("a probe row's sk is 0 (unassigned) — the sensors.sk backfill did not run")
		}
	}
	if len(rttVals) != 3 || rttVals[0] != 10.0 || rttVals[1] != 7.25 || rttVals[2] != 12.5 {
		t.Errorf("rtt_ms after migration = %v, want [10 7.25 12.5] (NULL stays NULL, ts_ms order)", rttVals)
	}
	if len(manuals) != 4 || manuals[3] != 1 {
		t.Errorf("manual flags after migration = %v, want [0 0 0 1]", manuals)
	}
	if !indexExists(t, st2, "idx_probes_cov") {
		t.Error("idx_probes_cov missing after migration")
	}
	for _, dead := range []string{"idx_probes_sensor_ts", "idx_probes_sensor_ts_cov"} {
		if indexExists(t, st2, dead) {
			t.Errorf("TEXT-era index %s survived the migration", dead)
		}
	}
	// FK is live on the new column: an orphan sk must be rejected.
	if _, err := st2.Exec(`INSERT INTO probes (sk, ts_ms, rtt_ms) VALUES (9999, ?, 1.0)`, base.UnixMilli()); err == nil {
		t.Error("orphan probe sk accepted — the probes.sk FK is not enforced")
	}
	// ...and ON DELETE CASCADE follows the surrogate now — per sensor:
	// deleting a leaves b's row, deleting b leaves none.
	if _, err := st2.Exec(`DELETE FROM sensors WHERE id = 'a'`); err != nil {
		t.Fatalf("delete sensor: %v", err)
	}
	if err := st2.QueryRow(`SELECT COUNT(*) FROM probes`).Scan(&n); err != nil {
		t.Fatalf("count after cascade: %v", err)
	}
	if n != 1 {
		t.Errorf("probe rows after deleting sensor a = %d, want 1 (only a's rows cascade)", n)
	}
	if _, err := st2.Exec(`DELETE FROM sensors WHERE id = 'b'`); err != nil {
		t.Fatalf("delete sensor b: %v", err)
	}
	if err := st2.QueryRow(`SELECT COUNT(*) FROM probes`).Scan(&n); err != nil {
		t.Fatalf("count after second cascade: %v", err)
	}
	if n != 0 {
		t.Errorf("probe rows after deleting both sensors = %d, want 0 (ON DELETE CASCADE on sk)", n)
	}
}

// TestMigration14RefusesUnparseableTS pins the integrity guard: a legacy
// row whose ts is not parseable TEXT (a numeric ts, the classic corrupt
// shape) must fail the step LOUDLY — strftime would interpret an integer
// as a Julian day number and backfill plausible-looking garbage — and the
// step must roll back whole (version stays 13, the legacy table intact).
func TestMigration14RefusesUnparseableTS(t *testing.T) {
	dir := t.TempDir()
	st := buildV13Store(t, dir)
	seed := `INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, state, status, created_at)
		VALUES ('a', 'a', '127.0.0.1', 30, 1000, 25, 2, 'active', 'up', '2026-01-01T00:00:00Z')`
	if _, err := st.Exec(seed); err != nil {
		st.Close()
		t.Fatalf("seed sensor: %v", err)
	}
	if _, err := st.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES ('a', 12345, 1.0)`); err != nil {
		st.Close()
		t.Fatalf("seed numeric-ts row: %v", err)
	}
	st.Close()

	st2, err := NewStore(filepath.Join(dir, "v13.db"))
	if err != nil {
		t.Fatalf("NewStore (reboot): %v", err)
	}
	defer st2.Close()
	err = st2.InitSchema()
	if err == nil {
		t.Fatal("InitSchema succeeded over a numeric-ts row — the guard is dead")
	}
	if !strings.Contains(err.Error(), "refusing to convert") {
		t.Fatalf("error = %v, want the integrity guard's refusal message", err)
	}
	// The step rolled back: version is still 13 and the legacy table is
	// untouched (no half-converted state on disk).
	if v := getUserVersion(t, st2); v != 13 {
		t.Fatalf("user_version after failed step = %d, want 13 (the step must roll back whole)", v)
	}
	var n int
	if err := st2.QueryRow(`SELECT COUNT(*) FROM probes WHERE typeof(ts) = 'integer'`).Scan(&n); err != nil {
		t.Fatalf("legacy table check: %v", err)
	}
	if n != 1 {
		t.Fatalf("legacy probes rows = %d, want 1 (the rollback must leave the old table intact)", n)
	}
}

// TestMigration14ReplayIsNoOp pins the replay contract on the new layout:
// a second InitSchema over an already-migrated DB touches nothing (the
// ts_ms presence guard + the version stamp), and the data survives.
func TestMigration14ReplayIsNoOp(t *testing.T) {
	st, err := NewStore(filepath.Join(t.TempDir(), "replay.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer st.Close()
	if err := st.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := st.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, state, status, created_at)
		VALUES ('a', 'a', '127.0.0.1', 30, 1000, 25, 2, 'active', 'up', ?)`, base.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed sensor: %v", err)
	}
	if _, err := st.Exec(`INSERT INTO probes (sk, ts_ms, rtt_ms) VALUES ((SELECT sk FROM sensors WHERE id = 'a'), ?, 10.0)`, base.UnixMilli()); err != nil {
		t.Fatalf("seed probe: %v", err)
	}
	if err := st.InitSchema(); err != nil {
		t.Fatalf("replay InitSchema: %v", err)
	}
	var n int
	if err := st.QueryRow(`SELECT COUNT(*) FROM probes`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("probe rows after replay = %d, want 1", n)
	}
	if v := getUserVersion(t, st); v != schemaVersionHead {
		t.Fatalf("user_version after replay = %d, want head %d", v, schemaVersionHead)
	}
}
