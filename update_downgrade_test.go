package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"pulsemon/internal/store"
)

// floorDB returns a fresh test DB with max_version_seen set to floor
// (empty floor = a fresh install with no recorded history).
func floorDB(t *testing.T, floor string) *store.Store {
	t.Helper()
	db := newTestDB(t)
	if floor != "" {
		if err := db.SetSetting(maxVersionSeenSetting, floor); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// TestDowngradeGuard pins the floor's decision table: below the floor is
// refused, at/above it passes, and bookkeeping gaps (no DB, no floor,
// unparseable values) never block an update.
func TestDowngradeGuard(t *testing.T) {
	cases := []struct {
		name    string
		floor   string
		tag     string
		allow   bool
		wantErr bool
	}{
		{"below floor refused", "v0.4.6", "v0.4.5", false, true},
		{"above floor allowed", "v0.4.6", "v0.4.7", false, false},
		{"equal to floor allowed", "v0.4.6", "v0.4.6", false, false},
		{"allow flag overrides", "v0.4.6", "v0.4.5", true, false},
		{"no floor (fresh install) allowed", "", "v0.4.5", false, false},
		{"unparseable floor never blocks", "garbage", "v0.4.5", false, false},
		{"unparseable tag never blocks", "v0.4.6", "not-a-version", false, false},
		{"pre-release below final refused", "v0.5.0", "v0.5.0-rc1", false, true},
		{"major bump above floor allowed", "v0.4.6", "v1.0.0", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var db *store.Store
			if tc.floor != "" {
				db = floorDB(t, tc.floor)
			}
			err := downgradeGuard(db, tc.tag, tc.allow)
			if (err != nil) != tc.wantErr {
				t.Fatalf("downgradeGuard(floor=%q, tag=%q, allow=%v) = %v, wantErr=%v",
					tc.floor, tc.tag, tc.allow, err, tc.wantErr)
			}
		})
	}
	t.Run("nil db never blocks", func(t *testing.T) {
		if err := downgradeGuard(nil, "v0.4.5", false); err != nil {
			t.Fatalf("nil db: %v", err)
		}
	})
}

// TestBumpMaxVersionSeen pins the boot-time bookkeeping: the floor is
// monotonic (a rolled-back box never lowers it) and dev builds record
// nothing, so an unstamped binary can't poison the floor with "dev".
func TestBumpMaxVersionSeen(t *testing.T) {
	oldVer := Version
	t.Cleanup(func() { Version = oldVer })

	t.Run("dev version records nothing", func(t *testing.T) {
		Version = "dev"
		db := floorDB(t, "")
		bumpMaxVersionSeen(db)
		if got := db.GetSetting(maxVersionSeenSetting); got != "" {
			t.Fatalf("dev boot stored %q, want nothing", got)
		}
	})
	t.Run("higher version raises the floor", func(t *testing.T) {
		Version = "v0.5.0"
		db := floorDB(t, "v0.4.6")
		bumpMaxVersionSeen(db)
		if got := db.GetSetting(maxVersionSeenSetting); got != "v0.5.0" {
			t.Fatalf("floor = %q, want v0.5.0", got)
		}
	})
	t.Run("lower version (rollback) never lowers the floor", func(t *testing.T) {
		Version = "v0.4.4"
		db := floorDB(t, "v0.4.6")
		bumpMaxVersionSeen(db)
		if got := db.GetSetting(maxVersionSeenSetting); got != "v0.4.6" {
			t.Fatalf("floor = %q, want v0.4.6 preserved after rollback", got)
		}
	})
	t.Run("nil db is a no-op", func(t *testing.T) {
		Version = "v0.5.0"
		bumpMaxVersionSeen(nil)
	})
}

// stubHealthzDB points openHealthzDB at a fixed test DB so runUpdate's
// guard reads a controlled floor (restored after the test).
func stubHealthzDB(t *testing.T, db *store.Store) {
	t.Helper()
	old := openHealthzDB
	openHealthzDB = func() *store.Store { return db }
	t.Cleanup(func() { openHealthzDB = old })
}

// TestRunUpdateRefusesDowngradeBelowMaxSeen is the CLI end-to-end: the
// install has run v0.4.6 (recorded at boot), is currently running v0.4.4
// (post-rollback), and the "latest" release is v0.4.5 — NEWER than the
// running version (the ordering rule passes it) but BELOW the floor (the
// guard refuses it). Nothing is downloaded.
func TestRunUpdateRefusesDowngradeBelowMaxSeen(t *testing.T) {
	base, _ := serveRelease(t, "v0.4.5", "")
	oldBase := releaseBase
	releaseBase = base
	oldVer := Version
	Version = "v0.4.4"
	t.Cleanup(func() { releaseBase, Version = oldBase, oldVer })
	stubHealthzDB(t, floorDB(t, "v0.4.6"))

	before := tempLeakBefore()
	code, out := captureOutput(t, func() int { return runUpdate([]string{}) })
	if code != 1 {
		t.Fatalf("runUpdate on a below-floor release = %d, want 1: %s", code, out)
	}
	if !strings.Contains(out, "below the highest version") {
		t.Fatalf("output lacks the downgrade-guard message: %s", out)
	}
	if leaked := tempLeakAfter(before); len(leaked) != 0 {
		t.Fatalf("guard refusal orphaned temp files: %v", leaked)
	}
}

// TestRunUpdateAllowDowngradePassesGuard: --allow-downgrade lifts the floor
// for that run. The same release gets PAST the guard all the way to the
// (deliberately broken) SHA check — proving the guard, not the sha, was the
// blocker.
func TestRunUpdateAllowDowngradePassesGuard(t *testing.T) {
	base, _ := serveRelease(t, "v0.4.5", "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	oldBase := releaseBase
	releaseBase = base
	oldVer := Version
	Version = "v0.4.4"
	t.Cleanup(func() { releaseBase, Version = oldBase, oldVer })
	stubHealthzDB(t, floorDB(t, "v0.4.6"))

	before := tempLeakBefore()
	code, out := captureOutput(t, func() int { return runUpdate([]string{"--allow-downgrade"}) })
	if code != 1 {
		t.Fatalf("runUpdate --allow-downgrade = %d, want 1 (sha mismatch after passing the guard): %s", code, out)
	}
	if strings.Contains(out, "below the highest version") {
		t.Fatalf("--allow-downgrade did not lift the guard: %s", out)
	}
	if !strings.Contains(out, "SHA-256 MISMATCH") {
		t.Fatalf("expected the run to reach the SHA check (guard lifted), got: %s", out)
	}
	if leaked := tempLeakAfter(before); len(leaked) != 0 {
		t.Fatalf("allow-downgrade run orphaned temp files: %v", leaked)
	}
}

// TestUpdateRefusesDowngradeBelowMaxSeen is the dashboard twin: an
// un-pinned "latest" update for a tag below the floor is a 409 and nothing
// is installed.
func TestUpdateRefusesDowngradeBelowMaxSeen(t *testing.T) {
	db := newTestDB(t)
	if err := db.SetSetting(maxVersionSeenSetting, "v0.4.6"); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(db, NewProbeWorker(db))
	if err := srv.auth.AddUser("admin", "update-test-password-1"); err != nil {
		t.Fatal(err)
	}
	h := setupUpdateHarness(t, false)
	base, _ := serveRelease(t, "v0.4.5", "")
	oldBase, oldVer := releaseBase, Version
	releaseBase, Version = base, "v0.4.4"
	t.Cleanup(func() { releaseBase, Version = oldBase, oldVer })

	rec := postUpdate(t, srv, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("code = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if got, _ := os.ReadFile(h.exePath); string(got) != "old binary" {
		t.Fatalf("binary was swapped on a downgrade-guard refusal: %q", got)
	}
}

// servePinnedReleaseVerified is serveReleaseVerified for an EXPLICIT version
// pin: it answers /releases/tags/<tag> (the endpoint a pinned update hits)
// with the real digest, so verification passes and the full install path is
// exercised.
func servePinnedReleaseVerified(t *testing.T, tag string) string {
	t.Helper()
	bin := []byte("fake pulsemon binary payload\n")
	real := sha256.Sum256(bin)
	realHex := hex.EncodeToString(real[:])
	sigHex := signFixture(t, bin)

	mux := http.NewServeMux()
	mux.HandleFunc("/releases/tags/"+tag, func(w http.ResponseWriter, r *http.Request) {
		rel := ghRelease{
			TagName: tag,
			Assets: []releaseAsset{
				{Name: targetAsset(), BrowserDownloadURL: "http://" + r.Host + "/releases/bin", Digest: "sha256:" + realHex},
				{Name: targetAsset() + ".sig", BrowserDownloadURL: "http://" + r.Host + "/releases/bin.sig"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rel)
	})
	mux.HandleFunc("/releases/bin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(bin)
	})
	mux.HandleFunc("/releases/bin.sig", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(sigHex))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL + "/releases"
}

// TestUpdateExplicitPinBypassesDowngradeGuard: an EXPLICIT version pin in
// the request body is the API's opt-out (the dashboard's --allow-downgrade)
// — pinning a below-floor tag is a deliberate operator choice, so the full
// install path runs and the binary is swapped.
func TestUpdateExplicitPinBypassesDowngradeGuard(t *testing.T) {
	db := newTestDB(t)
	if err := db.SetSetting(maxVersionSeenSetting, "v0.4.6"); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(db, NewProbeWorker(db))
	if err := srv.auth.AddUser("admin", "update-test-password-1"); err != nil {
		t.Fatal(err)
	}
	h := setupUpdateHarness(t, false)
	base := servePinnedReleaseVerified(t, "v0.4.5")
	oldBase, oldVer := releaseBase, Version
	releaseBase, Version = base, "v0.4.4"
	t.Cleanup(func() { releaseBase, Version = oldBase, oldVer })

	rec := postUpdate(t, srv, `{"version":"v0.4.5"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 (installed): %s", rec.Code, rec.Body.String())
	}
	if res := decodeUpdate(t, rec); res.Status != "installed" {
		t.Fatalf("res = %+v, want installed", res)
	}
	if got, _ := os.ReadFile(h.exePath); !strings.Contains(string(got), "fake pulsemon binary payload") {
		t.Fatalf("binary not swapped on an explicit pin: %q", got)
	}
}
