package main

import (
	"errors"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// isUniqueConstraintErr reports whether err is a SQLite uniqueness
// violation, judged by RESULT CODE rather than by matching the driver's
// message text.
//
// The message ("UNIQUE constraint failed: <table>.<column>") is
// modernc.org/sqlite-internal and can change wording between driver releases
// without notice — a silent break for any detection that keys on the string.
// The result codes are part of the stable SQLite ABI, so keying on them is
// driver-upgrade-proof.
//
// SQLite emits that SAME message for two distinct extended result codes, and
// the old text match caught both, so this must too:
//   - SQLITE_CONSTRAINT_UNIQUE     (2067) — a UNIQUE index (sensors.name)
//   - SQLITE_CONSTRAINT_PRIMARYKEY (1555) — a PRIMARY KEY (users.username)
//
// Each call site sits in a context where that uniqueness constraint is the
// only realistically violable one (the id column is a generated UUID), so the
// code alone identifies the violation — no column substring is needed.
func isUniqueConstraintErr(err error) bool {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code() {
	case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
		return true
	}
	return false
}
