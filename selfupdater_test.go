package main

// --- Finding #14: self-updater bugs ---
//
// Three defects: (1) installBinary hardlinked the running binary to .prev
// on EVERY platform — on Windows NTFS that link succeeds on a running
// .exe, leaving dst mapped, so swapBinary's rename-over failed with
// ERROR_ACCESS_DENIED and every Windows live update died; the backup is
// now platform-specific (Linux hardlinks, Windows renames). (2) The
// /api/update-check failure backoff was dead code: the suppression window
// was compared against the age of the last SUCCESS (always ≥ TTL after
// expiry) instead of the last ATTEMPT, and cold-cache failures never set
// the failure flag — hammering api.github.com on every 5s poll during
// outages. (3) `sign verify <file> <tag> <asset>` fell through to the
// legacy raw-bytes check when the manifest check failed, letting an
// uninstallable or tag-replayed .sig pass release CI.

import (
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestBackupBinaryLinuxHardlinks: on Linux the backup must be a HARDLINK —
// after backupBinary BOTH dst and prev exist and point at the same inode.
// A rename (the Windows scheme) would leave dst missing, re-opening the
// power-loss window in which the install boots with NO binary.
func TestBackupBinaryLinuxHardlinks(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "bin")
	prev := dst + ".prev"
	if err := os.WriteFile(dst, []byte("old\n"), 0755); err != nil {
		t.Fatal(err)
	}
	// A stale .prev must be replaced, not fatal.
	if err := os.WriteFile(prev, []byte("stale\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := backupBinary(dst, prev); err != nil {
		t.Fatalf("backupBinary: %v", err)
	}
	dfi, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("dst missing after backup (%v) — a rename scheme would do that; Linux must hardlink", err)
	}
	pfi, err := os.Stat(prev)
	if err != nil {
		t.Fatalf("prev missing after backup: %v", err)
	}
	if !os.SameFile(dfi, pfi) {
		t.Fatal("dst and prev are different inodes — the backup is not a hardlink (dst would disappear if this were a rename)")
	}
	content, err := os.ReadFile(prev)
	if err != nil || string(content) != "old\n" {
		t.Fatalf("prev content = %q (err %v), want the OLD binary (stale .prev replaced)", content, err)
	}
}

// updateCheckPollTest scaffolds handleUpdateCheck against a fake GitHub
// that fails every request, with the check-state vars swapped and
// restored.
func updateCheckPollTest(t *testing.T, gh http.Handler) (get func(refresh bool) int, hits func() int) {
	t.Helper()
	var hitCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCount++
		gh.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	oldBase := releaseBase
	releaseBase = srv.URL + "/releases"
	t.Cleanup(func() { releaseBase = oldBase })

	oldCache, oldAt, oldAttempt, oldFailed := updateCheckCached, updateCheckAt, updateCheckAttemptAt, updateCheckFailed
	oldTTL, oldFailTTL := updateCheckTTL, updateCheckFailTTL
	t.Cleanup(func() {
		updateCheckCached, updateCheckAt, updateCheckAttemptAt, updateCheckFailed = oldCache, oldAt, oldAttempt, oldFailed
		updateCheckTTL, updateCheckFailTTL = oldTTL, oldFailTTL
	})
	updateCheckCached, updateCheckFailed = nil, false
	updateCheckAt, updateCheckAttemptAt = time.Time{}, time.Time{}

	db := newTestDB(t)
	s := NewServer(db, NewProbeWorker(db))
	return func(refresh bool) int {
		u := "/api/update-check"
		if refresh {
			u += "?refresh=1"
		}
		req := httptest.NewRequest("GET", u, nil)
		rec := httptest.NewRecorder()
		s.handleUpdateCheck(rec, req)
		return rec.Code
	}, func() int { return hitCount }
}

// TestUpdateCheckColdCacheFailureBackoff: with NO cached result, a failed
// upstream must 503 — and the NEXT poll within the failure window must
// 503 WITHOUT re-fetching. Pre-fix, cold-cache failures never set
// updateCheckFailed, so every 5s dashboard poll re-hit api.github.com
// during an outage from first boot.
func TestUpdateCheckColdCacheFailureBackoff(t *testing.T) {
	get, hits := updateCheckPollTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))

	if code := get(false); code != http.StatusServiceUnavailable {
		t.Fatalf("cold failure: code=%d, want 503", code)
	}
	if hits() != 1 {
		t.Fatalf("cold failure hit upstream %d times, want 1", hits())
	}
	// Second poll inside updateCheckFailTTL: suppressed, NO upstream hit.
	if code := get(false); code != http.StatusServiceUnavailable {
		t.Fatalf("suppressed cold failure: code=%d, want 503", code)
	}
	if hits() != 1 {
		t.Fatalf("suppressed cold failure hit upstream %d times, want still 1 (the flag must be set on cold failures too)", hits())
	}
}

// TestUpdateCheckFailureBackoffAfterStaleCache: the dead-code killer. The
// failed attempt happens AFTER the cached success has aged past
// updateCheckFailTTL — the exact production shape (30m-old cache, 1m
// failure window). Pre-fix the suppression tested the SUCCESS age, which
// is always ≥ failTTL in this shape, so the branch never fired and the
// next poll re-fetched. The fix measures from the ATTEMPT.
func TestUpdateCheckFailureBackoffAfterStaleCache(t *testing.T) {
	var firstOnly int
	gh := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstOnly++
		if firstOnly > 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"tag_name":"v9.9.9","html_url":"https://github.com/invizen/pulsemon/releases/tag/v9.9.9"}`))
	})
	get, hits := updateCheckPollTest(t, gh)
	updateCheckTTL = time.Millisecond // cache expires immediately
	updateCheckFailTTL = 20 * time.Millisecond

	if code := get(false); code != http.StatusOK {
		t.Fatalf("first check: code=%d, want 200", code)
	}
	// Let the cached success age PAST the failure window.
	time.Sleep(30 * time.Millisecond)
	// Cache is stale: the poll fetches, the fetch FAILS, and the stale
	// result is served. The attempt timestamp is NOW.
	if code := get(false); code != http.StatusOK {
		t.Fatalf("stale-serve check: code=%d, want 200 (stale cached result)", code)
	}
	if hits() != 2 {
		t.Fatalf("upstream hit %d times, want 2 (success + one failed probe)", hits())
	}
	// The killer poll: the success is now ≥ failTTL old (pre-fix: NOT
	// suppressed → refetch), but the attempt is fresh (fix: suppressed).
	if code := get(false); code != http.StatusOK {
		t.Fatalf("suppressed check: code=%d, want 200 stale", code)
	}
	if hits() != 2 {
		t.Fatalf("suppressed check hit upstream %d times, want still 2 (the backoff must measure from the ATTEMPT, not the success)", hits())
	}
}

// signVerifyFiles stages a release binary + detached .sig in a temp dir
// and returns the binary path.
func signVerifyFiles(t *testing.T, binBytes, sig []byte) string {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "pulsemon-linux-amd64")
	if err := os.WriteFile(file, binBytes, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file+".sig", []byte(hex.EncodeToString(sig)+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return file
}

// TestSignVerifyManifestModeRejectsLegacySig: a 4-arg (manifest) verify
// must NOT fall through to the raw-bytes check. A legacy raw-bytes .sig
// is uninstallable by the manifest client and unbound to the tag/asset —
// pre-fix it passed release CI.
func TestSignVerifyManifestModeRejectsLegacySig(t *testing.T) {
	_, priv, binBytes := sigTestSetup(t)
	file := signVerifyFiles(t, binBytes, ed25519.Sign(priv, binBytes)) // raw-bytes sig
	if rc := runSignRelease([]string{"verify", file, "v0.4.5", "pulsemon-linux-amd64"}); rc != 1 {
		t.Fatalf("legacy raw-bytes .sig passed 4-arg manifest verify (rc=%d) — the fall-through lets unbindable signatures ship", rc)
	}
}

// TestSignVerifyManifestModeAcceptsManifestSig: the happy path — a
// manifest-bound signature verifies in 4-arg mode.
func TestSignVerifyManifestModeAcceptsManifestSig(t *testing.T) {
	_, priv, binBytes := sigTestSetup(t)
	file := signVerifyFiles(t, binBytes, signManifest(t, priv, "v0.4.5", "pulsemon-linux-amd64", binBytes))
	if rc := runSignRelease([]string{"verify", file, "v0.4.5", "pulsemon-linux-amd64"}); rc != 0 {
		t.Fatalf("valid manifest signature rejected in 4-arg mode (rc=%d)", rc)
	}
}

// TestSignVerifyTagReplayRejected: a manifest signature bound to tag
// v0.4.4 must not verify for tag v0.4.5 — the tag/asset binding is the
// point of manifest mode.
func TestSignVerifyTagReplayRejected(t *testing.T) {
	_, priv, binBytes := sigTestSetup(t)
	file := signVerifyFiles(t, binBytes, signManifest(t, priv, "v0.4.4", "pulsemon-linux-amd64", binBytes))
	if rc := runSignRelease([]string{"verify", file, "v0.4.5", "pulsemon-linux-amd64"}); rc != 1 {
		t.Fatalf("tag-replayed signature accepted (rc=%d), want rejected", rc)
	}
}

// TestSignVerifyLegacyModeAcceptsRawSig: 2-arg (legacy) mode keeps the
// raw-bytes check — pre-manifest releases must still verify.
func TestSignVerifyLegacyModeAcceptsRawSig(t *testing.T) {
	_, priv, binBytes := sigTestSetup(t)
	file := signVerifyFiles(t, binBytes, ed25519.Sign(priv, binBytes))
	if rc := runSignRelease([]string{"verify", file}); rc != 0 {
		t.Fatalf("legacy raw-bytes .sig rejected in 2-arg mode (rc=%d) — pre-manifest releases must still verify", rc)
	}
}
