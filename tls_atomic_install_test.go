package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"pulsemon/internal/store"
)

// TestFix_m3_TLSPutAtomicInstall pins the m3 fix: a pair install that
// fails partway must leave the OLD pair and the stored port untouched.
// The key target is made a directory so the key rename cannot succeed
// (the "failing second write" the pre-fix code did not survive: it had
// already saved the port and written the cert, leaving a mismatched
// pair that crash-looped the next boot).
func TestFix_m3_TLSPutAtomicInstall(t *testing.T) {
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

	dir := tlsDir(db)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	oldCert, oldKey, _ := makeTestCert(t, "ec")
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), []byte(oldCert), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), []byte(oldKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting("listener_https_port", "443"); err != nil {
		t.Fatal(err)
	}

	// Make the KEY target a directory: renaming the temp key over it must
	// fail, so the install dies before anything is renamed into place.
	if err := os.Remove(filepath.Join(dir, "key.pem")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "key.pem"), 0o700); err != nil {
		t.Fatal(err)
	}

	newCert, newKey, _ := makeTestCert(t, "rsa")
	body, _ := json.Marshal(map[string]any{"cert": newCert, "key": newKey, "port": 8443})
	req := httptest.NewRequest(http.MethodPost, "/api/settings/tls", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("PUT with failing key install = %d, want 500", w.Code)
	}

	// Old cert untouched.
	if b, err := os.ReadFile(filepath.Join(dir, "cert.pem")); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(b, []byte(oldCert)) {
		t.Errorf("cert.pem changed after a failed install")
	}
	// Key target still the directory (untouched).
	fi, err := os.Stat(filepath.Join(dir, "key.pem"))
	if err != nil || !fi.IsDir() {
		t.Errorf("key.pem target = %v, %v; want the directory untouched", fi, err)
	}
	// Port NOT persisted.
	if p := db.GetSetting("listener_https_port"); p != "443" {
		t.Errorf("listener_https_port = %q, want 443 (unchanged)", p)
	}
	// No temp litter left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == "cert.pem" || e.Name() == "key.pem" {
			continue
		}
		t.Errorf("leftover %q in the tls dir after a failed install", e.Name())
	}
}
