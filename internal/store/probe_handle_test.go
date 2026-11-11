package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// TestProbeHandleCarriesCappedBusyTimeout pins the mechanism behind finding
// #4: probe-path writes run on a handle whose busy_timeout is
// ProbeWriteTimeout, so the cap on a lock-parked write is real at the driver
// (a ctx deadline cannot preempt a busy-parked write in modernc.org/sqlite
// v1.29.1 — empirically verified), while the main pool keeps the tuned 15s
// write-coalescing knob.
func TestProbeHandleCarriesCappedBusyTimeout(t *testing.T) {
	old := ProbeWriteTimeout
	ProbeWriteTimeout = 1234 * time.Millisecond
	defer func() { ProbeWriteTimeout = old }()

	st, err := NewStore(filepath.Join(t.TempDir(), "cap.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer st.Close()

	var probeMs int
	err = st.ProbeImmediateTx(context.Background(), func(c *sql.Conn) error {
		return c.QueryRowContext(context.Background(), `PRAGMA busy_timeout`).Scan(&probeMs)
	})
	if err != nil {
		t.Fatalf("ProbeImmediateTx: %v", err)
	}
	if probeMs != 1234 {
		t.Fatalf("probe handle busy_timeout = %d ms, want 1234 (the ProbeWriteTimeout seam must reach the driver)", probeMs)
	}

	var mainMs int
	if err := st.QueryRow(`PRAGMA busy_timeout`).Scan(&mainMs); err != nil {
		t.Fatalf("main pool pragma: %v", err)
	}
	if mainMs != 15000 {
		t.Fatalf("main pool busy_timeout = %d ms, want 15000 (the tuned knob must not move)", mainMs)
	}
}
