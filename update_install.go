package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"pulsemon/internal/store"
	"strconv"
	"strings"
	"time"
)

// installBinary swaps the running binary. On Linux the running process keeps
// the old inode alive, so writing a temp file in the same directory and
// renaming it over the original is atomic and safe — no "text file busy".
// Before the swap the current binary is kept at <dst>.prev (M4 rollback
// artifact): the rename atomically replaces any stale .prev and preserves
// the original's mode and ownership.
func installBinary(src, dst, wantSHA string) error {
	// Preserve the original binary's ownership (a root-installed binary
	// must stay root-owned after a root update). The rename replaces dst's
	// inode with one owned by the executing user, so restore the recorded
	// owner on EVERY original — including 0:0, which the previous
	// "uid != 0 || gid != 0" guard silently skipped.
	wantUID, wantGID, haveOwner := binaryOwner(dst)

	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".pulsemon-swap-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename

	// Stage the new binary into the temp file FIRST: a bad source must
	// fail with the destination untouched (TestInstallBinaryBadSource),
	// so dst is only moved aside once the source is fully staged.
	// Open the source with a managed lifecycle — the previous mustOpen
	// helper leaked this descriptor on every install and panicked (raw
	// runtime trace, no formatted diagnostic) when the open failed.
	srcFile, err := os.Open(src)
	if err != nil {
		tmp.Close()
		return fmt.Errorf("open source binary: %w", err)
	}
	defer srcFile.Close()

	// Hash while staging: verifying the src PATH and
	// then re-reading it leaves a window where the temp file can be
	// swapped between verify and install. Hashing the exact bytes being
	// staged closes it — a drifted source fails here, BEFORE dst is
	// touched, and what passes is by construction what gets installed.
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), srcFile); err != nil {
		tmp.Close()
		return err
	}
	if wantSHA != "" {
		if got := hex.EncodeToString(h.Sum(nil)); got != wantSHA {
			tmp.Close()
			return fmt.Errorf("install refused: staged binary hash drifted from the verified download (expected %s, staged %s)", wantSHA, got)
		}
	}
	// Mode: PRESERVE the original binary's permission bits when dst
	// exists (forcing 0755 silently widened e.g.
	// 0750), always ensuring owner-executable — a legacy 0600 dst must
	// not come back unbootable. A fresh install with no dst is 0755.
	dstMode := os.FileMode(0755)
	if fi, err := os.Stat(dst); err == nil {
		dstMode = fi.Mode().Perm() | 0100
	}
	if err := tmp.Chmod(dstMode); err != nil {
		tmp.Close()
		return err
	}
	// F18c: restore the recorded ownership on the STAGED file, before the
	// rename. A post-swap chown that fails leaves a LIVE binary with the
	// wrong owner (the service may no longer be able to exec it); pre-swap
	// the same failure just refuses the install with dst untouched.
	if haveOwner {
		if err := tmp.Chown(int(wantUID), int(wantGID)); err != nil {
			tmp.Close()
			return fmt.Errorf("chown staged binary to original owner (%d:%d): %w", wantUID, wantGID, err)
		}
	}
	// F18b: make the staged binary durable BEFORE the rename.
	// Without this, a crash between the copy and the rename can leave a
	// truncated file that the rename then promotes over the good binary.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync staged binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Keep the previous binary for `pulsemon update rollback`. A missing
	// dst (no running binary to back up) is tolerated: there is simply no
	// previous version to roll back to.
	//
	// HOW the backup is made is platform-specific (backupBinary), because
	// the two OSes disagree on what a running binary tolerates: Linux
	// hardlinks (dst never disappears, so a power loss between backup and
	// swap cannot boot an install with NO binary), Windows renames (NTFS
	// happily hardlinks a RUNNING exe — the link succeeds and leaves dst
	// mapped, so the rename of the new binary OVER the locked dst then
	// fails with ERROR_ACCESS_DENIED and every Windows live update dies).
	// The swap that follows is equally platform-specific (swapBinary).
	prev := dst + ".prev"
	if _, err := os.Lstat(dst); err != nil {
		uWarn("no previous binary to keep at " + prev + " (nothing to roll back to later)")
	} else if err := backupBinary(dst, prev); err != nil {
		return err
	}
	if err := swapBinary(tmpName, dst); err != nil {
		// The previous binary was already moved to .prev; put it back so
		// a failed swap never leaves the install without a current
		// binary.
		if _, perr := os.Stat(prev); perr == nil {
			_ = os.Rename(prev, dst)
		}
		return err
	}
	// F18b: fsync the destination directory so the rename
	// itself is durable (best effort — some filesystems, e.g. Windows,
	// cannot open a directory for sync; the rename is already atomic).
	if d, err := os.Open(dir); err == nil {
		if serr := d.Sync(); serr != nil {
			uWarn("directory fsync after swap failed: " + serr.Error())
		}
		d.Close()
	}
	return nil
}

// rollbackBinary restores <exe>.prev over <exe> (atomic rename) and
// consumes the .prev. It is the undo for installBinary: after a bad update
// the previous binary is exactly one rename away. Fails cleanly when there
// is no .prev (nothing to roll back to — e.g. the first update from a
// release that predates the .prev artifact).
func rollbackBinary(exe string) error {
	prev := exe + ".prev"
	if _, err := os.Stat(prev); err != nil {
		return fmt.Errorf("no previous binary at %s to roll back to", prev)
	}
	// Windows note (Win32 semantics reasoned, not
	// executed — no Windows runner verified this): renaming OVER a loaded
	// image fails with a sharing violation (ERROR_USER_MAPPED_FILE).
	// Consequences: (a) the watchdog's rollback is fine — it runs after
	// the broken new binary has exited, so its image is no longer mapped;
	// (b) a MANUAL `pulsemon update rollback` while the service still runs
	// the image will FAIL here — fails safe (the running binary is
	// untouched), but the operator must stop the service first on Windows.
	if err := os.Rename(prev, exe); err != nil {
		return fmt.Errorf("restore previous binary over %s: %w", exe, err)
	}
	return nil
}

// runningExecutable locates the running binary (os.Executable) and resolves
// symlinks best-effort: on Linux os.Executable already returns the resolved
// path via /proc/self/exe, so this mostly matters on other platforms. A
// failed resolution keeps the unresolved path — the update must still work
// (and os.Executable never returns an empty string, so installBinary's
// filepath.Dir(dst) can't silently fall back to the CWD). Var so tests can
// stub it: a unit test must never let the install path touch the real test
// binary (/tmp/go-build.../pulsemon.test).
var runningExecutable = func() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	return exe, nil
}

// maxVersionSeenSetting is the settings key holding the highest version this
// install has EVER run. It is the anti-downgrade floor for self-update: a
// release tag below it is refused (a replayed/old build published under a
// tag that is still "newer" than the running version must not install over a
// box that has already run something newer — e.g. after an operator
// rollback, the old tag must not creep back up).
const maxVersionSeenSetting = "max_version_seen"

// bumpMaxVersionSeen records the running version as the highest ever seen.
// MONOTONIC: a lower running version (post-rollback) never lowers the floor.
// Best-effort by design — this is bookkeeping on the boot path, so a DB
// failure is a log line, never a boot failure (and dev/unparseable versions
// record nothing, so an unstamped build can't poison the floor).
func bumpMaxVersionSeen(db *store.Store) {
	if db == nil {
		return
	}
	run := parseVer(Version)
	if !run.ok {
		return
	}
	if stored := db.GetSetting(maxVersionSeenSetting); stored != "" {
		if p := parseVer(stored); p.ok && !p.lessThan(run) {
			return // stored floor is already >= the running version
		}
	}
	if err := db.SetSetting(maxVersionSeenSetting, Version); err != nil {
		log.Printf("update: record highest version seen: %v", err)
	}
}

// downgradeGuard refuses to install a release tag that is below the highest
// version this install has ever run (maxVersionSeenSetting). allow (the
// CLI's --allow-downgrade) overrides it; a missing DB or an unparseable
// floor never blocks an update (the guard must not fail on bookkeeping
// gaps). An EMPTY floor is a no-op: a fresh install has no history, so its
// first update is always allowed.
func downgradeGuard(db *store.Store, tag string, allow bool) error {
	if allow || db == nil {
		return nil
	}
	stored := db.GetSetting(maxVersionSeenSetting)
	if stored == "" {
		return nil
	}
	cand := parseVer(tag)
	floor := parseVer(stored)
	if !cand.ok || !floor.ok {
		return nil
	}
	if cand.lessThan(floor) {
		return fmt.Errorf("refusing to install %s: it is below the highest version this install has ever run (%s); re-run with --allow-downgrade to override", tag, stored)
	}
	return nil
}

// healthzHostPort splits PULSEMON_ADDR into (host, port) for the health
// check, the same way install.sh derives its target:
//
//	":9299"           -> ("localhost", "9299")  (all-interface bind)
//	"127.0.0.1:9299"  -> ("127.0.0.1", "9299")
//	"[::1]:9299"      -> ("::1", "9299")
//	"9299" (bare)     -> ("localhost", "9299")
//	"" (unset)        -> ("localhost", "9299")  (the binary's own default)
func healthzHostPort() (string, string) {
	addr := os.Getenv("PULSEMON_ADDR")
	if addr == "" {
		addr = unitEnvVar("PULSEMON_ADDR") // F16: unit env fallback
	}
	switch {
	case addr == "":
		return "localhost", "9299"
	case strings.HasPrefix(addr, ":"):
		return "localhost", addr[1:]
	case strings.ContainsRune(addr, ':'):
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return "localhost", "9299"
		}
		if host == "" {
			host = "localhost"
		}
		return host, port
	default: // bare port
		return "localhost", addr
	}
}

// healthzTarget derives the plain-HTTP host:port to healthcheck from
// PULSEMON_ADDR (kept for callers that only need the HTTP candidate).
func healthzTarget() string {
	host, port := healthzHostPort()
	return net.JoinHostPort(host, port)
}

// healthzTargets returns the ordered scheme://host:port candidates the
// post-restart health check polls. The port the new process serves on
// depends on its listener config: with a TLS cert in place it serves
// HTTPS ONLY on the configured HTTPS port (listener_https_port, default
// 443) and does NOT bind the PULSEMON_ADDR port at all — so a TLS
// install's healthz is unreachable at the plain port (the old code polled
// only the plain port and `pulsemon update --restart` always timed out on
// TLS installs). Poll every (scheme, port) combination and accept the
// first that answers pulsemon's healthz payload; that covers plain
// installs, TLS on the default port, TLS on a custom listener_https_port,
// and a cert added/removed across the restart.
//
// db may be nil (no data dir / first run): the HTTPS port falls back to
// defaultHTTPSPort.
func healthzTargets(db *store.Store) []string {
	host, httpPort := healthzHostPort()
	httpsPort := defaultHTTPSPort
	if db != nil {
		if p := db.GetSetting("listener_https_port"); p != "" {
			if n, err := parsePort(p); err == nil {
				httpsPort = n
			}
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, t := range []string{
		"https://" + net.JoinHostPort(host, strconv.Itoa(httpsPort)),
		"http://" + net.JoinHostPort(host, httpPort),
		"https://" + net.JoinHostPort(host, httpPort),
		"http://" + net.JoinHostPort(host, strconv.Itoa(httpsPort)),
	} {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// activeTimeout and restartTimeout bound the two systemctl calls in the
// --restart path. systemctl talks to dbus (user or system bus); a wedged bus
// must not hang the update, so both are hard-limited. Vars so a test could
// shrink them.
var (
	activeTimeout  = 10 * time.Second
	restartTimeout = 60 * time.Second
)

// healthzTimeout bounds the post-restart poll. A var so tests can shrink it.
var healthzTimeout = 15 * time.Second

// healthzPayloadOK reports whether body is a real pulsemon healthz answer.
// It accepts "ok" (healthy) AND "degraded" (up and serving, but ICMP
// unavailable — e.g. a host without CAP_NET_RAW/ping_group_range): a
// degraded service IS a successful update. The old "ok"-only marker rolled
// back a perfectly working new binary on no-ICMP hosts. A 2xx/3xx from ANY other service sharing a candidate port (a reverse
// proxy on 443, a stale process on the HTTP port) must not be mistaken for
// the monitor — the body check is what makes polling several candidate
// ports safe.
func healthzPayloadOK(body string) bool {
	return strings.Contains(body, `"status":"ok"`) ||
		strings.Contains(body, `"status":"degraded"`)
}

// healthzDBPath is the DB path the post-restart health check opens: the
// shell's PULSEMON_DB, else the unit's (F16), else the default. Deliberately
// NOT dbPathFromEnv: the server's own startup must not be redirected by a
// unit file it is not running under.
func healthzDBPath() string {
	if p := os.Getenv("PULSEMON_DB"); p != "" {
		return p
	}
	if p := unitEnvVar("PULSEMON_DB"); p != "" {
		return p
	}
	return defaultDBPath()
}

// openHealthzDB opens the data DB so the post-restart health check can read
// the listener config (the HTTPS port). A var so tests can stub it (the
// restart tests run where no data dir exists). nil on any failure — the
// health check then falls back to the default HTTPS port.
var openHealthzDB = func() *store.Store {
	db, err := store.NewStore(healthzDBPath())
	if err != nil {
		return nil
	}
	return db
}

// waitHealthy polls the pulsemon healthz endpoint until it answers with the
// healthz payload or the default timeout elapses. It returns ok plus a short
// detail for the log line.
//
// Every (scheme, port) candidate is polled (see healthzTargets): once a cert
// is installed the plain-HTTP port is deliberately not bound, so the TLS
// answer comes from the HTTPS port, not PULSEMON_ADDR's. A response only
// counts when it carries the pulsemon healthz payload — a reverse proxy
// answering on 443 must not be mistaken for the monitor. TLS verification is
// skipped because the question here is "did the new process come up and
// answer", not "is the certificate trusted" — and a self-signed homelab
// cert must pass too.
func waitHealthy(db *store.Store) (bool, string) {
	return waitHealthyWithTimeout(db, healthzTimeout)
}

// waitHealthyWithTimeout is the timeout-parameterized form of waitHealthy
// (the watchdog passes its own budget — see runWatchdog).
func waitHealthyWithTimeout(db *store.Store, timeout time.Duration) (bool, string) {
	targets := healthzTargets(db)
	deadline := time.Now().Add(timeout)
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	var lastErr error
	for {
		for _, target := range targets {
			resp, err := client.Get(target + "/api/healthz")
			if err == nil {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				resp.Body.Close()
				if resp.StatusCode < 400 && healthzPayloadOK(string(body)) {
					return true, target
				}
				lastErr = fmt.Errorf("HTTP %d without pulsemon healthz payload", resp.StatusCode)
			} else {
				lastErr = err
			}
		}
		if time.Now().After(deadline) {
			return false, strings.Join(targets, ", ") + " — " + lastErr.Error()
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// backupDatabasePreUpdate makes the pre-swap safety copy of the data DB
// (pulsemon.db.preupdate, next to the DB) so the post-restart verifier
// (the Windows restart-helper) can compare the live sensor count against
// the pre-update one and restore the backup if the update lost data.
// It uses `VACUUM INTO` (store.BackupTo), so the snapshot is consistent
// even while the monitor keeps serving - no service pause needed.
// live, when non-nil, is the in-process store the caller is already
// serving from (the API update path runs INSIDE the server) — reusing it
// avoids a second connection pool on the same file; the CLI update path
// has no in-process store and passes nil (one short-lived pool).
// Best effort: a failed backup must NEVER block an update; it degrades to
// "no verification", which is exactly today's behavior.
// History: docs/DECISIONS.md -> windows-upgrade-safety,
//
//	preupdate-vacuum-into-replace
func backupDatabasePreUpdate(live *store.Store) {
	dbPath := healthzDBPath()
	backup := filepath.Join(filepath.Dir(dbPath), "pulsemon.db.preupdate")
	st := live
	owned := false
	if st == nil {
		var err error
		st, err = store.NewStore(dbPath)
		if err != nil {
			uWarn("pre-update DB backup skipped: " + err.Error())
			return
		}
		owned = true
	}
	if owned {
		defer st.Close()
	}
	if err := st.BackupTo(backup); err != nil {
		uWarn("pre-update DB backup failed: " + err.Error())
	}
}

// sensorRestoreDecision is the pure decision core of the post-restart
// verifier: given the live sensor count (from the restarted service's
// healthz) and the pre-update backup's count, should the backup be
// restored? The restore fires when the live count DROPPED below the
// pre-update count (data loss) - a higher count is fine (sensors added
// during the window). With no usable backup there is nothing to compare
// against: no restore (today's behavior).
// History: docs/DECISIONS.md -> windows-upgrade-safety
func sensorRestoreDecision(liveCount, backupCount int, haveBackup bool) (restore bool, reason string) {
	if !haveBackup {
		return false, "no pre-update backup; nothing to verify against"
	}
	if liveCount < 0 {
		// The service answered no usable healthz (or its payload had no
		// count): we cannot distinguish "data loss" from "not up". The
		// watchdog already owns the not-up case (binary rollback); the
		// verifier does not double-act on an unverifiable state.
		return false, "live sensor count unavailable; leaving the binary/watchdog path in charge"
	}
	if liveCount < backupCount {
		return true, fmt.Sprintf("sensor count dropped %d -> %d", backupCount, liveCount)
	}
	return false, fmt.Sprintf("sensor count intact (%d >= pre-update %d)", liveCount, backupCount)
}

// waitSensorCount polls the pulsemon healthz endpoint (same candidate
// targets and payload check as waitHealthyWithTimeout) until it answers
// with a pulsemon payload, then returns the reported sensor count (the
// "sensors" field). ok=false with count=-1 means the deadline elapsed
// without a usable answer.
func waitSensorCount(db *store.Store, timeout time.Duration) (count int, ok bool, detail string) {
	targets := healthzTargets(db)
	deadline := time.Now().Add(timeout)
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	var lastErr error
	for {
		for _, target := range targets {
			resp, err := client.Get(target + "/api/healthz")
			if err == nil {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				resp.Body.Close()
				if resp.StatusCode < 400 && healthzPayloadOK(string(body)) {
					var hz struct {
						Sensors int `json:"sensors"`
					}
					if jerr := json.Unmarshal(body, &hz); jerr == nil {
						return hz.Sensors, true, target
					}
					lastErr = fmt.Errorf("pulsemon healthz payload without a sensors field: %s", body)
				} else {
					lastErr = fmt.Errorf("HTTP %d without pulsemon healthz payload", resp.StatusCode)
				}
			} else {
				lastErr = err
			}
		}
		if time.Now().After(deadline) {
			return -1, false, strings.Join(targets, ", ") + " - " + lastErr.Error()
		}
		time.Sleep(500 * time.Millisecond)
	}
}
