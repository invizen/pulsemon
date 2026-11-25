package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"pulsemon/internal/store"
	"runtime"
	"testing"
)

func countOpenFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("count fds: %v", err)
	}
	return len(ents)
}

// TestTLSInstallWriteFailureClosesTempFDs pins that a pair install that
// fails at the FIRST temp write releases both temp descriptors. The
// injected creator hands out read-only files, so tmpCert.Write fails
// with EBADF and install() returns before any explicit Close. The
// pre-fix code closed the temps only on the paths that reached the
// explicit closes, so every early-return failure leaked up to two fds
// per failed PUT (the caller removed the names, not the descriptors).
func TestTLSInstallWriteFailureClosesTempFDs(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("counts /proc/self/fd")
	}
	dataDir := t.TempDir()
	t.Setenv("PULSEMON_DB", filepath.Join(dataDir, "pulsemon.db"))

	db, err := store.NewStore(dbPathFromEnv())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(db, NewProbeWorker(db))

	origTestBind := tlsTestBind
	tlsTestBind = func(network, addr string) error { return nil }
	t.Cleanup(func() { tlsTestBind = origTestBind })

	cert, key, _ := makeTestCert(t, "rsa")
	body, _ := json.Marshal(map[string]any{"cert": cert, "key": key})

	n := 0
	orig := tlsCreateTemp
	t.Cleanup(func() { tlsCreateTemp = orig })
	tlsCreateTemp = func(dir, _ string) (*os.File, error) {
		n++
		return os.OpenFile(filepath.Join(dir, fmt.Sprintf(".leaktest-%d.tmp", n)),
			os.O_RDONLY|os.O_CREATE, 0o600)
	}

	base := countOpenFDs(t)
	req := httptest.NewRequest(http.MethodPost, "/api/settings/tls", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Mux().ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("install with failing temp write = %d, want 500", w.Code)
	}
	if after := countOpenFDs(t); after > base {
		t.Fatalf("failed TLS install leaked %d fd(s): temps closed only on explicit-close paths", after-base)
	}
}
