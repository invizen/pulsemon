package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"pulsemon/internal/store"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Version is stamped at build time:
//
//	go build -ldflags "-X main.Version=v0.1.6" ...
//
// Binaries built without it report "dev".
var Version = "dev"

// releaseBase is the GitHub releases API for this repo. It is a var (not a
// const) so tests can point runUpdate at a local httptest server.
var releaseBase = "https://api.github.com/repos/invizen/pulsemon/releases"

// release_pubkeys holds the trusted release-signing public keys (ed25519,
// hex, one per line) — see the file header for the rotation model. A release
// binary is accepted only if its detached .sig asset verifies against at
// least one of these keys. This is the authenticity root for self-update:
// the SHA-256 check proves the bytes survived the download (integrity), but
// the signature proves the publisher held the private key (authenticity) —
// the one thing a compromised release pipeline cannot forge.
//
//go:embed release_pubkeys
var releaseKeyFS embed.FS

// releasePubkeys is the embedded trusted-key set as bytes. It is a var (not
// the FS read inline) so tests can swap in a known test key set and restore
// it in t.Cleanup — the same var-seam idiom this file uses (releaseBase,
// detectRestart, ...).
var releasePubkeys = mustReadEmbeddedPubkeys()

func mustReadEmbeddedPubkeys() []byte {
	b, err := releaseKeyFS.ReadFile("release_pubkeys")
	if err != nil {
		// The file is embedded at build time; a read failure is a build/bundle
		// bug, not a runtime condition, so it is loud.
		panic("release_pubkeys: " + err.Error())
	}
	return b
}

// update colors — matches the house script style (update_llama.sh).
const (
	uBold   = "\033[1m"
	uGreen  = "\033[0;32m"
	uYellow = "\033[0;33m"
	uRed    = "\033[0;31m"
	uReset  = "\033[0m"
)

func uInfo(msg string) { fmt.Printf("%s%s[+]%s %s\n", uBold, uGreen, uReset, msg) }
func uWarn(msg string) { fmt.Printf("%s%s[!]%s %s\n", uBold, uYellow, uReset, msg) }
func uErr(msg string)  { fmt.Fprintf(os.Stderr, "%s%s[x]%s %s\n", uBold, uRed, uReset, msg) }

// semVer is a parsed semver-ish version with its pre-release label KEPT
// the old parseVer dropped the label, so a final
// release compared EQUAL to its own pre-release and v0.4.0 never "upgraded"
// a v0.4.0-rc1 install.
type semVer struct {
	maj, min, pat int
	pre           string // "" = final release
	ok            bool
}

// parseVer parses a semver-ish version ("v1.2.3", "1.2.3-beta"). ok=false
// means the string is not a version at all (e.g. the "dev" build default),
// which callers treat as "older than any release". Build metadata (+build)
// is ignored for precedence, per semver.
func parseVer(s string) semVer {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	var pre string
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return semVer{}
	}
	maj, e1 := strconv.Atoi(parts[0])
	min, e2 := strconv.Atoi(parts[1])
	if e1 != nil || e2 != nil || maj < 0 || min < 0 {
		return semVer{}
	}
	pat := 0
	if len(parts) > 2 {
		p, e3 := strconv.Atoi(parts[2])
		if e3 != nil {
			return semVer{}
		}
		pat = p
	}
	return semVer{maj: maj, min: min, pat: pat, pre: pre, ok: true}
}

// comparePreRelease orders two pre-release labels per semver 11:
// dot-separated identifiers compared left to right; numeric identifiers
// compare as integers and sort BELOW alphanumeric ones; a shorter list is
// smaller when all its identifiers equal the longer list's prefix.
func comparePreRelease(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		ai, aNum := strconv.Atoi(as[i])
		bi, bNum := strconv.Atoi(bs[i])
		switch {
		case aNum == nil && bNum == nil:
			if ai != bi {
				if ai < bi {
					return -1
				}
				return 1
			}
		case aNum == nil:
			return -1 // numeric sorts below alphanumeric
		case bNum == nil:
			return 1
		default:
			if as[i] != bs[i] {
				if as[i] < bs[i] {
					return -1
				}
				return 1
			}
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
}

// lessThan reports whether a < b in semver precedence.
func (a semVer) lessThan(b semVer) bool {
	if a.maj != b.maj {
		return a.maj < b.maj
	}
	if a.min != b.min {
		return a.min < b.min
	}
	if a.pat != b.pat {
		return a.pat < b.pat
	}
	// Equal core: a pre-release sorts BELOW the final release (semver
	// 11.4) — v0.4.0-rc1 < v0.4.0.
	if a.pre == b.pre {
		return false
	}
	if a.pre == "" {
		return false // a is the final release: a > b
	}
	if b.pre == "" {
		return true // b is the final release: a < b
	}
	return comparePreRelease(a.pre, b.pre) < 0
}

// newerRelease reports whether the release tag is strictly newer than the
// running version. An unstamped ("dev") binary is always treated as older.
// Pre-releases order per semver, so a FINAL release is newer than its own
// pre-release (v0.4.0 > v0.4.0-rc1) — the old label-stripping compare made
// them equal and pinned rc installs forever.
func newerRelease(releaseTag, running string) bool {
	r := parseVer(releaseTag)
	if !r.ok {
		return false
	}
	m := parseVer(running)
	if !m.ok {
		return true
	}
	return m.lessThan(r)
}

// validVersionToken reports whether v is safe to interpolate into the
// GitHub releases URL path as a tag name: "v" + [A-Za-z0-9.+-] only, up to
// 40 chars (semver releases incl. pre-release/build suffixes: v1.2.3,
// v1.2.3-rc1, v1.2.3+build5). It blocks path traversal ("../evil"),
// whitespace and control characters (which make http.NewRequest error)
// from reaching the URL at all. GitHub tags are free-form, but pulsemon's
// own releases are semver — pinning the accepted shape keeps the URL
// surface closed.
func validVersionToken(v string) bool {
	if len(v) < 2 || len(v) > 40 || v[0] != 'v' {
		return false
	}
	for i := 1; i < len(v); i++ {
		c := v[i]
		ok := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			c == '.' || c == '-' || c == '+'
		if !ok {
			return false
		}
	}
	return true
}

// releaseAsset is one asset of a GitHub release.
type releaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"` // the actual binary URL
	URL                string `json:"url"`                  // API endpoint — JSON unless Accept: application/octet-stream
	Digest             string `json:"digest"`               // GitHub-computed "sha256:<hex>"; empty for pre-2025 uploads
}

type ghRelease struct {
	TagName string         `json:"tag_name"`
	Assets  []releaseAsset `json:"assets"`
}

// targetAsset is the release asset name for the platform this binary runs
// on — "pulsemon-<GOOS>-<GOARCH>" (e.g. pulsemon-linux-amd64, pulsemon-linux-arm64
// on a Pi 4/5 or RK3588); Windows assets carry the .exe extension (the
// release workflow uploads pulsemon-windows-amd64.exe), so the name is
// platform-shaped, not a bare os/arch join. It honors $GOARCH so a host can
// deliberately fetch a different architecture's release asset. The sidecar
// checksum asset is targetAsset() + ".sha256" (see the fallback below).
func targetAsset() string {
	goarch := os.Getenv("GOARCH")
	if goarch == "" {
		goarch = runtime.GOARCH
	} else if goarch != runtime.GOARCH {
		// Loud: the override is a deliberate packaging
		// feature (tests cross-arch asset naming), but a stray GOARCH in
		// the SERVER's environment would fetch and INSTALL a wrong-arch
		// binary that passes the SHA check (it IS the official asset) and
		// only fails at exec. The watchdog now catches that and rolls
		// back — but the log must not hide WHY the rollback happened.
		log.Printf("update: GOARCH=%s override active while this host is %s — fetching the %s asset; a wrong-arch binary passes the hash check and is caught only at restart (watchdog rolls back)", goarch, runtime.GOARCH, targetAssetName(runtime.GOOS, goarch))
	}
	return targetAssetName(runtime.GOOS, goarch)
}

// targetAssetName is the pure (testable) form of targetAsset: the release
// asset name for a given platform (the bare os/arch join made
// the first real Windows self-update on zendev fail — the asset is
// pulsemon-windows-amd64.exe, not pulsemon-windows-amd64).
func targetAssetName(goos, goarch string) string {
	name := fmt.Sprintf("pulsemon-%s-%s", goos, goarch)
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// runUpdate implements `pulsemon update`. Works from any directory: it
// locates the running binary via os.Executable, so the systemd unit and
// Docker need no changes.
//
//	pulsemon update          check + install if newer
//	pulsemon update check    check only, no install
//	pulsemon update v0.1.5   install a specific version
//	pulsemon update --restart install AND restart the running service
//	pulsemon update rollback   restore the previous binary (<exe>.prev)
//	pulsemon update rollback --restart   restore + restart the service
//
// --restart auto-restarts ONLY when a live systemd pulsemon service is
// confidently detected (a user-bus service, or a system-bus service when
// running as root), then polls healthz and reports the outcome. It keeps the
// default install-and-hint contract otherwise, because the fleet is mixed:
// containers, root installs, and non-systemd hosts are safer told how to
// restart than auto-restarted (a bad new version would otherwise take the
// monitor down).
//
// Exit codes: 0 = up to date or update installed (including a check of a
// target that is NOT newer than the running version, and a --restart that
// found nothing to restart or a container), 1 = failure (including a
// --restart whose service failed to come up healthy),
// 2 = target is newer than the running version and --check (check-only,
// for scripting — the target may be "latest" or an explicit pin).
//
// It RETURNS the exit code instead of calling os.Exit itself: os.Exit skips
// the deferred os.Remove of the downloaded temp file, so every failed
// verification or check-only run would have orphaned a multi-megabyte binary
// in the system temp dir. main() performs the actual exit.
func runUpdate(args []string) int {
	checkOnly := false
	restart := false
	rollback := false
	watchdog := false
	allowDowngrade := false
	wdPrev, wdDst, wdBus := "", "", ""
	wdTimeout := 30 * time.Second
	wdOldPid := 0
	version := "latest"
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "check", "--check":
			checkOnly = true
		case "restart", "--restart":
			restart = true
		case "rollback":
			rollback = true
		case "--allow-downgrade":
			// Opt out of the anti-downgrade floor (max_version_seen) for
			// this one run — e.g. deliberately re-installing an older
			// release after a rollback.
			allowDowngrade = true
		case "watchdog", "--watchdog":
			// The detached post-restart guardian (I2) — see runWatchdog.
			watchdog = true
		case "--prev", "--dst", "--timeout", "--old-pid", "--bus":
			if i+1 >= len(args) {
				uErr(a + " requires a value")
				return 1
			}
			i++
			switch a {
			case "--prev":
				wdPrev = args[i]
			case "--dst":
				wdDst = args[i]
			case "--bus":
				// The authoritative bus captured BEFORE the restart
				// (spawnUpdateWatchdog's detectRestart): at rollback
				// time a crashed/stopped service is no longer "active",
				// so re-detecting there reports no bus and the restart
				// is lost. Validated: a garbage bus would be issued to
				// systemctl for a unit that is not there.
				if !validRestartBus(args[i]) {
					uErr("invalid --bus: " + args[i] + " (want user, system, or windows-service)")
					return 1
				}
				wdBus = args[i]
			case "--old-pid":
				n, perr := strconv.Atoi(args[i])
				if perr != nil {
					uErr("invalid --old-pid: " + args[i])
					return 1
				}
				wdOldPid = n
			case "--timeout":
				d, perr := time.ParseDuration(args[i])
				if perr != nil || d <= 0 {
					uErr("invalid --timeout: " + args[i])
					return 1
				}
				wdTimeout = d
			}
		case "-h", "--help":
			fmt.Println("usage: pulsemon update [check|rollback|watchdog|<version>] [--restart] [--allow-downgrade]")
			fmt.Println("       pulsemon update watchdog --prev <bin.prev> --dst <bin> [--bus user|system|windows-service] [--timeout 30s] [--old-pid PID]")
			return 0
		default:
			version = a
		}
	}

	if watchdog {
		return runWatchdog(wdPrev, wdDst, wdBus, wdTimeout, wdOldPid)
	}

	exe, err := runningExecutable()
	if err != nil {
		uErr("cannot locate running binary: " + err.Error())
		return 1
	}
	uInfo("binary:  " + exe)
	uInfo("version: " + Version)

	if rollback {
		// Cross-process lock (F19): the rollback rename touches the same
		// .prev the install path moves — serialize against a concurrent
		// update in another process.
		lockFile, lerr := acquireUpdateLock()
		if lerr != nil {
			if errors.Is(lerr, errUpdateLockHeld) {
				uErr("rollback: " + lerr.Error())
				return 1
			}
			uErr("rollback: update lock: " + lerr.Error())
			return 1
		}
		defer lockFile.Close()
		if err := rollbackBinary(exe); err != nil {
			uErr("rollback: " + err.Error())
			return 1
		}
		uInfo("rolled back " + exe + " to the previous binary (from " + exe + ".prev)")
		return handleRollbackRestart(exe, restart)
	}

	client := &http.Client{Timeout: 30 * time.Second}

	rel, err := fetchRelease(client, version)
	if err != nil {
		uErr("fetch release: " + err.Error())
		return 1
	}
	uInfo("release: " + rel.TagName)

	sel := selectAssets(rel)
	if sel.assetURL == "" {
		uErr("release has no " + targetAsset() + " asset")
		return 1
	}
	assetURL := sel.assetURL

	// Version ordering matters for BOTH "latest" and explicit pins: a check
	// against an older pin must not claim "new version available" (exit 2),
	// which would mislead automation into treating a downgrade as an update.
	if isNewer := newerRelease(rel.TagName, Version); !isNewer {
		if version == "latest" {
			if checkOnly {
				uInfo("up to date (" + Version + " is the latest release). Nothing to do.")
			} else {
				uInfo("already up to date (" + Version + "). Nothing to do.")
			}
		} else {
			uInfo("target version " + rel.TagName + " is not newer than running " + Version + ". Nothing to do.")
		}
		return 0
	}

	if checkOnly {
		uWarn("new version available: " + rel.TagName + " (running " + Version + "). Run 'pulsemon update' to install.")
		return 2
	}

	// Anti-downgrade floor: a release tag below the highest
	// version this install has ever run is refused — a replayed old build
	// published under a newer-looking tag must not install over a box that
	// has already run something newer. The DB is opened best-effort (the
	// same helper the healthz CLI uses): when it is unavailable (no data
	// dir) the floor is empty and the update proceeds.
	db := openHealthzDB()
	if db != nil {
		defer db.Close()
	}
	if err := downgradeGuard(db, rel.TagName, allowDowngrade); err != nil {
		uErr(err.Error())
		return 1
	}

	// Cross-process install lock: everything from
	// here on mutates the on-disk binary. The lock is held (via the open
	// file) until this process exits, covering the whole
	// download→install→restart span; a concurrent update in another
	// process (the dashboard endpoint vs. this CLI) gets a clean refusal.
	lockFile, err := acquireUpdateLock()
	if err != nil {
		if errors.Is(err, errUpdateLockHeld) {
			uErr(err.Error())
			return 1
		}
		uErr("update lock: " + err.Error())
		return 1
	}
	defer lockFile.Close()

	uInfo("downloading " + rel.TagName + "...")
	tmp, err := downloadAsset(client, assetURL)
	if err != nil {
		uErr("download: " + err.Error())
		return 1
	}
	defer os.Remove(tmp)

	// Mandatory verification (security) — see verifyDownloadedAsset: the
	// update must never install an unverified binary.
	digest, err := verifyDownloadedAsset(client, sel, tmp)
	if err != nil {
		uErr("refusing to update: " + err.Error())
		return 1
	}
	uInfo("sha256:  " + digest + " ✓")

	// Safety copy of the data DB BEFORE the swap (VACUUM INTO, consistent
	// while serving): the post-restart verifier compares the sensor count
	// against this backup. Best effort - it never blocks the update.
	// nil: the CLI path has no in-process store of its own.
	backupDatabasePreUpdate(nil)

	if err := installBinary(tmp, exe, digest); err != nil {
		uErr("install: " + err.Error())
		return 1
	}
	uInfo("installed " + rel.TagName + " to " + exe)

	return handleRestart(exe, restart)
}

// runWatchdog is the detached post-restart guardian for the API's
// auto-restart path (I2): the server process dies WITH
// the service restart it triggers, so without a watchdog a broken new
// binary stays broken with no one to roll it back. The watchdog polls the
// same healthz targets the CLI uses (accepting ok OR degraded — see
// healthzPayloadOK), and on failure restores <prev> over <dst> and restarts
// the service.
//
// Exit codes: 0 = the new binary is healthy, or a rollback was performed
// successfully; 1 = the rollback itself failed (the box needs a human).
func runWatchdog(prev, dst, bus string, timeout time.Duration, oldPid int) int {
	if prev == "" || dst == "" {
		uErr("watchdog: --prev and --dst are required")
		return 1
	}
	// Guard order. The spawning server holds the update
	// flock until its own death (the restart we are guarding), and its
	// healthz answers with a VALID payload while it is still up. So the
	// old order — lock once, then poll — failed both ways: the single
	// LOCK_NB acquisition hit EWOULDBLOCK while the server was alive and
	// the watchdog exited 1 instantly (no guardian at all, silently:
	// detachSpawn nils stdio), and any fix that kept polling while the old
	// process lived would misread the OLD server as a healthy restart.
	// Therefore: wait for the old PID to exit, THEN acquire the lock (with
	// retries bounded to lockRetryBudget), THEN poll healthz.
	if oldPid > 0 && !waitForProcessExit(oldPid, wdOldProcTimeout) {
		uErr("watchdog: old server process " + strconv.Itoa(oldPid) +
			" still alive after " + wdOldProcTimeout.String() + "; exiting without touching the binary (its health is not the new one's)")
		return 1
	}
	lockDeadline := time.Now().Add(lockRetryBudget)
	var lockFile *os.File
	for {
		var err error
		lockFile, err = acquireUpdateLock()
		if err == nil {
			break
		}
		if !errors.Is(err, errUpdateLockHeld) || !time.Now().Before(lockDeadline) {
			uErr("watchdog: update lock: " + err.Error())
			return 1
		}
		time.Sleep(200 * time.Millisecond)
	}
	defer lockFile.Close()

	db := openHealthzDB()
	if db != nil {
		defer db.Close()
	}
	ok, detail := waitHealthyWithTimeout(db, timeout)
	if ok {
		uInfo("watchdog: service is healthy after restart (" + detail + ")")
		// Healthy is not the same as intact: the v1.1.19->v1.1.20
		// incident left a HEALTHY service with its sensors wiped. This
		// is the belt-and-suspenders check (DB restore + binary rollback
		// if the live sensor count dropped below the pre-update one).
		verifySensorsIntactWatchdog(db, prev, dst, bus)
		return 0
	}
	uErr("watchdog: service not healthy after restart (" + detail + "); restoring " + prev)
	if err := rollbackBinaryFile(prev, dst); err != nil {
		uErr("watchdog: rollback failed: " + err.Error())
		return 1
	}
	uInfo("watchdog: previous binary restored to " + dst)
	// The SPAWN-TIME bus is authoritative for this restart: a broken
	// binary has crashed the service into activating/failed, where
	// detectRestart() (systemctl is-active) reports "" and a
	// detect-only restart would be skipped, leaving the monitor dead.
	// Detection is the fallback for a watchdog spawned without --bus
	// (an older version, or a manual run) — the old safe default.
	restartBus := bus
	if restartBus == "" {
		restartBus = detectRestart()
	}
	if restartBus != "" {
		if err := performRestart(restartBus); err != nil {
			uErr("watchdog: restart after rollback failed: " + err.Error())
			return 1
		}
		uInfo("watchdog: service restarted with the previous binary")
	}
	return 0
}

// stopForRestoreFn stops the running service before the watchdog restores
// the pre-update DB and rolls the binary back: a live process must not have
// the DB open (the restore removes -wal/-shm and rewrites the file) nor be
// holding the binary image. Platform default (Linux): systemctl stop on the
// detected bus. Windows overrides this in update_windows.go (SCM stop —
// best-effort for the VSA). Tests stub it.
var stopForRestoreFn = func() error {
	bus := detectRestartSystemd()
	if bus == "" {
		return fmt.Errorf("no active pulsemon systemd service detected")
	}
	args := []string{"stop", "pulsemon"}
	if bus == "user" {
		args = append([]string{"--user"}, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), restartTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, systemctlPath(), args...)
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("stop pulsemon (%s bus): %v: %s", bus, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// serviceStateFn reports the live service state: "running", "stopped",
// "pending", or "" with an error. The watchdog's data-restore path must
// know whether a live process is holding the DB open BEFORE it rewrites
// the file (a restore under a live writer corrupts the data). Platform
// default (Linux): systemctl is-active. Windows overrides in
// update_windows.go (SCM QueryServiceStatus with the VSA's proven query
// right — its START/STOP are integrity-denied, so the state is the only
// reliable signal of who holds the DB). Tests stub it.
var serviceStateFn = func() (string, error) {
	bus := detectRestartSystemd()
	if bus == "" {
		return "stopped", nil // not active on either bus
	}
	args := []string{"is-active", "pulsemon"}
	if bus == "user" {
		args = append([]string{"--user"}, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), activeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, systemctlPath(), args...)
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.CombinedOutput()
	state := strings.TrimSpace(string(out))
	if err != nil {
		// is-active exits non-zero for every non-active state but still
		// prints it: trust the printed state over the exit code.
		switch state {
		case "inactive", "failed", "deactivating", "activating", "":
			return "stopped", nil
		default:
			return "", fmt.Errorf("systemctl is-active: %v: %s", err, state)
		}
	}
	if state == "active" {
		return "running", nil
	}
	return state, nil
}

// restartSensorWaitTimeout bounds the post-restart healthz sensor-count
// poll in the watchdog verifier. The watchdog ALREADY waited for the
// service to become healthy (waitHealthyWithTimeout passed) — the count
// poll is the same endpoint one probe later, so 30s is generous headroom
// (the 90s the retired helper used covered the service START, which the
// watchdog does not re-wait for). A var so a test can shrink it.
var restartSensorWaitTimeout = 30 * time.Second

// restartSensorWait is a seam over waitSensorCount so the verifier's test
// can stub it (a unit test must not poll a real port).
var restartSensorWait = func(db *store.Store, timeout time.Duration) (int, bool, string) {
	return waitSensorCount(db, timeout)
}

// restoreDatabaseFile replaces the live DB with a copy of backup (a
// consistent VACUUM INTO snapshot). The service is STOPPED when this runs,
// so nobody has the DB open. The live -wal/-shm files belong to the live
// DB's last session and must NOT replay over the restored file: remove
// them first (SQLite would replay them on the next open, mixing stale WAL
// pages into the snapshot).
//
// The copy is STREAMED to a temp file in the live file's directory and
// then renamed into place — never read wholesale into RAM (the backup is
// hundreds of MB at the declared fleet), and never written in place
// (an in-place rewrite truncates the live file first, so a power loss
// mid-write strands a truncated DB; this path already runs only after
// the watchdog proved data loss, which is exactly when a second failure
// is least acceptable). Same-directory temp + rename is what makes the
// swap atomic: the live path sees the old file whole or the new one
// whole, never a prefix. The .preupdate backup survives either way.
func restoreDatabaseFile(backup, live string) error {
	_ = os.Remove(live + "-wal")
	_ = os.Remove(live + "-shm")
	src, err := os.Open(backup)
	if err != nil {
		return err
	}
	defer src.Close()
	tmp, err := os.CreateTemp(filepath.Dir(live), ".pulsemon-restore-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err = io.Copy(tmp, src); err == nil {
		err = tmp.Chmod(0o600)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), live)
}

// verifySensorsIntactWatchdog is the post-restart data-integrity check the
// watchdog runs on the HEALTHY path (the belt-and-suspenders half of the
// self-update): the update wrote pulsemon.db.preupdate (a VACUUM INTO
// snapshot) BEFORE swapping the binary, so now that the service is back
// up, compare the live sensor count against the pre-update one. A
// shortfall means the update lost sensor data (the v1.1.19->v1.1.20
// "sensors wiped" incident: the binary swap raced a schema migration and
// the new schema lost rows). The only self-heal is restoring the pre-
// update DB and rolling the binary back to the known-good pair, then
// bringing the service up on it.
//
// It runs while the watchdog HOLDS the update lock (runWatchdog acquired
// it), so it cannot race the unhealthy-path rollback.
//
// SAFETY: the service is RUNNING when this runs (it answered healthz). A
// DB restore under a live writer corrupts the data, so the restore only
// proceeds when the service is stopped: a stopped service (the crash-loop
// case) is restored directly; a running service is stopped first, and a
// stop that is DENIED (the Windows VSA lacks SERVICE_STOP —
// integrity-enforced, see update_windows.go) means nothing is touched and
// the log carries exact manual-restore instructions. The data is safe in
// the backup either way.
//
// The watchdog is detached (no console, no inherited pipes), so uInfo/uErr
// would vanish: every finding also goes to pulsemon-watchdog.log next to
// the DB — the operator's only post-mortem record.
//
// History: docs/DECISIONS.md -> windows-upgrade-safety,
//
//	windows-recovery-restart
func verifySensorsIntactWatchdog(db *store.Store, prevBin, dstBin, bus string) {
	dbPath := healthzDBPath()
	backup := filepath.Join(filepath.Dir(dbPath), "pulsemon.db.preupdate")
	logLine := func(format string, a ...any) {
		// Go forbids extra fixed args alongside a `s...` expansion (the
		// expansion must supply the ENTIRE variadic tail), so the
		// timestamp rides in the slice.
		args := append([]any{time.Now().Format(time.RFC3339)}, a...)
		line := fmt.Sprintf("%s watchdog: "+format+"\n", args...)
		f, err := os.OpenFile(filepath.Join(filepath.Dir(dbPath), "pulsemon-watchdog.log"),
			os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return
		}
		defer f.Close()
		_, _ = f.WriteString(line)
	}

	if _, err := os.Stat(backup); err != nil {
		logLine("no pre-update backup at %s — sensor verification skipped", backup)
		return
	}
	// Read-only: the verifier must never write to the safety copy, and a
	// read-write open would set journal_mode(WAL) and strand -wal/-shm
	// sidecars beside the snapshot (see store.NewStoreReadOnly).
	bst, err := store.NewStoreReadOnly(backup)
	if err != nil {
		logLine("cannot open pre-update backup (%v) — sensor verification skipped", err)
		return
	}
	want, err := bst.SensorCount()
	bst.Close()
	if err != nil {
		logLine("cannot count sensors in pre-update backup (%v) — sensor verification skipped", err)
		return
	}
	if want == 0 {
		logLine("no sensors in the pre-update backup — nothing to verify")
		return
	}

	live, ok, detail := restartSensorWait(db, restartSensorWaitTimeout)
	if !ok {
		logLine("live sensor count unavailable (%s) — the watchdog's unhealthy path owns a service that will not answer; leaving data as-is", detail)
		return
	}
	rest, reason := sensorRestoreDecision(live, want, true)
	if !rest {
		logLine("sensors intact: %s", reason)
		// The update is VERIFIED: this snapshot has served its purpose, so
		// remove it. A surviving backup is the stale-baseline trap — months
		// later the operator may legitimately delete sensors, and a future
		// watchdog comparing the lower live count against THIS months-old
		// snapshot would declare data loss and restore it, wiping the
		// intervening months of config, users and history. The next update
		// writes a fresh snapshot atomically (BackupTo renames into place).
		if err := os.Remove(backup); err != nil {
			logLine("note: verified pre-update backup %s could not be removed (%v) — the next update replaces it atomically", backup, err)
		}
		return
	}
	logLine("DATA LOSS after update: %s — restoring the pre-update DB and the previous binary", reason)

	state, sErr := serviceStateFn()
	if (state == "running" || state == "pending") && sErr == nil {
		if err := stopForRestoreFn(); err != nil {
			logLine("cannot stop the running service to restore the database (%v) — MANUAL ACTION REQUIRED: stop the pulsemon service, replace the data DB with the backup at %s, replace the service binary with %s, then start the service", err, backup, prevBin)
			return
		}
	} else if sErr != nil && state != "stopped" {
		logLine("cannot determine the service state (%v) — a running service would hold the DB open, so nothing was restored; check the pulsemon service, then restore the DB from %s and the binary from %s if needed", sErr, backup, prevBin)
		return
	}
	// state == "stopped": no live writer; safe to restore.
	if err := restoreDatabaseFile(backup, dbPath); err != nil {
		logLine("DATABASE RESTORE FAILED: %v — restore %s over the data DB manually", err, backup)
		return
	}
	logLine("pre-update database restored from %s", backup)
	if err := rollbackBinaryFile(prevBin, dstBin); err != nil {
		logLine("BINARY ROLLBACK FAILED: %v — replace the service binary with %s manually", err, prevBin)
		return
	}
	logLine("previous binary restored to %s", dstBin)
	// The SPAWN-TIME bus is authoritative here too: the service was just
	// stopped for the restore, so detectRestart() (is-active) reports ""
	// and a detect-only restart would hit the SYSTEM bus without --user —
	// failing on every user-bus install.
	restartBus := bus
	if restartBus == "" {
		restartBus = detectRestart()
	}
	if restartBus == "" {
		logLine("no service bus known (none passed and none detected) — if the service's recovery action is configured it will start the service on the restored pair by itself; otherwise start the pulsemon service manually")
		return
	}
	if err := performRestart(restartBus); err != nil {
		logLine("restart after restore: %v — if the service's SCM recovery action is configured it will start the service on the restored pair by itself; otherwise start the pulsemon service manually", err)
		return
	}
	logLine("service restarted on the restored database and previous binary")
}

// wdOldProcTimeout bounds the watchdog's wait for the SPAWNING server
// process to exit (systemd stop drains up to ~6s; 20s is generous headroom).
// lockRetryBudget bounds the wait for the update flock to be released by
// that dying server. Both are vars so tests can shrink them.
var (
	wdOldProcTimeout = 20 * time.Second
	lockRetryBudget  = 10 * time.Second
)

// waitForProcessExit reports whether pid exited within timeout.
func waitForProcessExit(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if processGone(pid) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// watchdogTimeout is the health-poll budget for the restart watchdog,
// overridable via PULSEMON_WATCHDOG_TIMEOUT (Go duration, clamped to
// 5s..5m, invalid values warn and keep the 30s default). The hardcoded 30s
// can roll back a WORKING update on an
// install whose startup work — InitSchema, warmStats — legitimately takes
// longer on a very large DB; the operator can widen the window without a
// code change.
func watchdogTimeout() time.Duration {
	const def = 30 * time.Second
	v := os.Getenv("PULSEMON_WATCHDOG_TIMEOUT")
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 5*time.Second || d > 5*time.Minute {
		uWarn("ignoring invalid PULSEMON_WATCHDOG_TIMEOUT " + strconv.Quote(v) + " (want a Go duration between 5s and 5m0s) — using " + def.String())
		return def
	}
	return d
}

// spawnUpdateWatchdog detaches `pulsemon update --watchdog ...` (I2) so the
// API's auto-restart path keeps a guardian after this process dies. The
// watchdog polls healthz and rolls back to <exe>.prev if the new binary
// never comes up. --old-pid is us: the watchdog must not lock-acquire or
// health-poll until THIS process is gone.
//
// bus is the systemd bus detectRestart reported ("user"/"system"): on
// systemd the watchdog is spawned through `systemd-run --scope` so it lives
// in its own transient cgroup — a plain detach (Setsid) keeps it inside
// pulsemon.service's cgroup, where KillMode=control-group (the default)
// kills it with the service on the very restart it was guarding.
func spawnUpdateWatchdog(exe, bus string) error {
	return detachSpawn(buildWatchdogCommand(exe, bus))
}

// buildWatchdogCommand returns the command that spawns the detached
// watchdog, factored out of spawnUpdateWatchdog so the spawn contract is
// testable without starting a process. Two invariants:
//
//  1. It executes <exe>.prev when that file exists — the binary at <exe>
//     is the one we JUST installed, i.e. possibly the broken one (wrong
//     arch, crash in init). Spawning IT to guard itself failed in exactly
//     the failure modes the watchdog exists for; the previous binary is
//     the known-good one that also carries a working `update watchdog`
//     implementation. No .prev (first update from a pre-.prev release)
//     falls back to <exe>: nothing to roll back to, but the spawn must
//     not fail for lack of a binary.
//
//  2. On systemd with a known bus it wraps the spawn in
//     `systemd-run [--user] --scope`, placing the watchdog in an
//     independent transient cgroup that `systemctl restart pulsemon`
//     cannot kill (KillMode=control-group kills only the unit's own
//     cgroup). Without systemd-run (non-systemd host) the plain command
//     is returned and the caller's detach is all the isolation there is.
//
//  3. The bus rides into the watchdog argv (--bus) as the AUTHORITATIVE
//     post-rollback restart target: at rollback time the service is
//     crashed (activating/failed) or stopped (the DB-restore path), so a
//     fresh detectRestart() there reports no bus and the restart is
//     lost. An empty bus (non-systemd host) keeps the argv shape
//     constant; the watchdog then falls back to detection.
func buildWatchdogCommand(exe, bus string) *exec.Cmd {
	watchdogBin := exe + ".prev"
	if _, err := os.Stat(watchdogBin); err != nil {
		watchdogBin = exe
	}
	args := []string{"update", "watchdog",
		"--prev", exe + ".prev", "--dst", exe,
		"--bus", bus,
		"--timeout", watchdogTimeout().String(),
		"--old-pid", strconv.Itoa(os.Getpid())}
	if run := systemdRunPath(); bus != "" && run != "" {
		prefix := []string{"--scope"}
		if bus == "user" {
			prefix = []string{"--user", "--scope"}
		}
		return exec.Command(run, append(prefix, append([]string{watchdogBin}, args...)...)...)
	}
	return exec.Command(watchdogBin, args...)
}

// handleRestart is the post-install restart decision, factored out of
// runUpdate so it can be tested in isolation without touching installBinary.
// That matters: installBinary renames the new binary over exe, and under
// `go test` exe is the cached test binary (/tmp/go-build.../pulsemon.test) —
// so the restart tests call handleRestart directly and never enter the
// install path (no fake payload ever lands on the test binary). Returns the
// exit code for this stage; runUpdate returns it.
func handleRestart(exe string, restart bool) int {
	// Container: the binary in the running image is unchanged; a rebuild is
	// required, not a restart.
	if exe == "/pulsemon" {
		if restart {
			uWarn("--restart ignored: container detected — the binary in the image is unchanged; rebuild with `docker compose up -d --build` (pulling the new release) to update.")
		} else {
			uWarn("container detected — the binary inside the image is unchanged; rebuild with `docker compose up -d --build` (pulling the new release) to update.")
		}
		return 0
	}

	// Default (no --restart): install-and-hint. Tell the operator how to
	// restart based on how the process is running — never auto-restart,
	// because the fleet is mixed and a bad new version must not take the
	// monitor down on its own.
	if !restart {
		if _, err := os.Stat("/run/systemd/system"); err == nil {
			uInfo("restart with: systemctl --user restart pulsemon   (system-wide install: sudo systemctl restart pulsemon)")
		} else {
			uWarn("restart the pulsemon process to pick up the new binary.")
		}
		return 0
	}

	// --restart: only auto-restart when we can confidently detect a live
	// systemd pulsemon service; otherwise fall back to the hint (never guess
	// a restart on a mixed fleet).
	d := detectRestart()
	if d == "" {
		if _, err := os.Stat("/run/systemd/system"); err == nil {
			uInfo("no live pulsemon service detected; restart with: systemctl --user restart pulsemon   (system-wide install: sudo systemctl restart pulsemon)")
		} else {
			uWarn("no live pulsemon service detected; restart the pulsemon process to pick up the new binary.")
		}
		return 0
	}
	uInfo("restarting pulsemon (" + d + " service)...")
	if err := performRestart(d); err != nil {
		uErr("restart failed: " + err.Error())
		uErr("the new binary is installed but the service did not restart — check: " + journalHint(d))
		return 1
	}
	// Poll healthz to confirm the new binary actually came up. The new
	// process's port depends on its TLS config, which lives in the DB —
	// open it (same data volume; WAL allows a concurrent reader) so the
	// check can find a TLS-on-custom-port install. nil on failure: the
	// check then falls back to the default HTTPS port.
	db := openHealthzDB()
	if db != nil {
		defer db.Close()
	}
	if ok, detail := waitHealthy(db); ok {
		uInfo("pulsemon is up and healthy after restart (" + detail + ")")
	} else {
		// The new binary is not answering: roll the install back to
		// <exe>.prev, restart once more, and report exit 1 (the update
		// did not take, even if the old binary comes back healthy).
		uErr("service restarted but is not answering healthz yet (" + detail + ")")
		uErr("rolling back to the previous binary (" + exe + ".prev) and restarting...")
		if rerr := rollbackBinary(exe); rerr != nil {
			uErr("rollback failed: " + rerr.Error())
			uErr("check: " + journalHint(d))
			return 1
		}
		if perr := performRestart(d); perr != nil {
			uErr("restart after rollback failed: " + perr.Error())
			uErr("check: " + journalHint(d))
			return 1
		}
		if ok, detail2 := waitHealthy(db); ok {
			uInfo("rolled back to the previous binary; pulsemon is healthy again (" + detail2 + ")")
		} else {
			uErr("rolled back to the previous binary, but it is not answering healthz either (" + detail2 + ")")
			uErr("check: " + journalHint(d))
		}
		return 1
	}
	return 0
}

// handleRollbackRestart is the post-rollback restart decision for
// `pulsemon update rollback [--restart]`: the same auto-restart rule as
// handleRestart (only a confidently detected live systemd service), with
// the install-and-hint fallbacks otherwise.
func handleRollbackRestart(exe string, restart bool) int {
	if exe == "/pulsemon" {
		if restart {
			uWarn("--restart ignored: container detected — the binary in the image is unchanged; rebuild with `docker compose up -d --build` to pick up the previous binary.")
		} else {
			uWarn("container detected — the binary inside the image is unchanged; rebuild with `docker compose up -d --build` to pick up the previous binary.")
		}
		return 0
	}

	if !restart {
		if _, err := os.Stat("/run/systemd/system"); err == nil {
			uInfo("restart with: systemctl --user restart pulsemon   (system-wide install: sudo systemctl restart pulsemon)")
		} else {
			uWarn("restart the pulsemon process to pick up the previous binary.")
		}
		return 0
	}

	d := detectRestart()
	if d == "" {
		if _, err := os.Stat("/run/systemd/system"); err == nil {
			uInfo("no live pulsemon service detected; restart with: systemctl --user restart pulsemon   (system-wide install: sudo systemctl restart pulsemon)")
		} else {
			uWarn("no live pulsemon service detected; restart the pulsemon process to pick up the previous binary.")
		}
		return 0
	}
	uInfo("restarting pulsemon (" + d + " service)...")
	if err := performRestart(d); err != nil {
		uErr("restart failed: " + err.Error())
		uErr("check: " + journalHint(d))
		return 1
	}
	db := openHealthzDB()
	if db != nil {
		defer db.Close()
	}
	if ok, detail := waitHealthy(db); ok {
		uInfo("pulsemon is up and healthy after restart (" + detail + ")")
	} else {
		uErr("service restarted but is not answering healthz yet (" + detail + ")")
		uErr("check: " + journalHint(d))
		return 1
	}
	return 0
}

// userAgent identifies this client to the GitHub API. GitHub's API
// guidelines require a custom User-Agent; the stdlib default
// (Go-http-client/1.1) gets throttled or 403'd far more aggressively
// than an app-specific one. Set on EVERY outbound request below —
// fetchRelease, fetchChecksumSidecar and downloadAsset all reach
// api.github.com (the asset-URL fallback paths included).
func userAgent() string {
	return "pulsemon-updater/" + Version
}

func fetchRelease(client *http.Client, version string) (*ghRelease, error) {
	url := releaseBase + "/latest"
	if version != "latest" {
		if !strings.HasPrefix(version, "v") {
			version = "v" + version
		}
		if !validVersionToken(version) {
			return nil, fmt.Errorf("invalid version %q: expected a release tag like v0.2.2", version)
		}
		url = releaseBase + "/tags/" + version
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid request for %q: %v", url, err)
	}
	req.Header.Set("User-Agent", userAgent())
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned HTTP %d for %s", resp.StatusCode, url)
	}
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

// releaseSelection is the (binary, digest, sidecar, signature) quad resolved
// from a release's asset list for the running platform. tag + asset are the
// manifest-binding fields: the release signature covers the manifest
// (releaseManifestMessage), which binds it to THIS tag and THIS asset so a
// signature for one release can never verify against another (replay).
type releaseSelection struct {
	assetURL   string
	sha        string
	sidecarURL string
	sigURL     string
	tag        string
	asset      string
}

// selectAssets picks the release assets for this platform: the binary
// (targetAsset()), its GitHub-computed digest if present, and the
// targetAsset()+".sha256" sidecar URL used when no API digest exists. URLs
// prefer the browser download URL; the API asset endpoint only works with
// Accept: application/octet-stream and carries no asset name.
func selectAssets(rel *ghRelease) releaseSelection {
	sel := releaseSelection{tag: rel.TagName, asset: targetAsset()}
	for _, a := range rel.Assets {
		switch a.Name {
		case targetAsset():
			sel.sha = strings.TrimPrefix(a.Digest, "sha256:")
			if a.BrowserDownloadURL != "" {
				sel.assetURL = a.BrowserDownloadURL
			} else {
				sel.assetURL = a.URL
			}
		case targetAsset() + ".sha256":
			if a.BrowserDownloadURL != "" {
				sel.sidecarURL = a.BrowserDownloadURL
			} else {
				sel.sidecarURL = a.URL
			}
		case targetAsset() + ".sig":
			if a.BrowserDownloadURL != "" {
				sel.sigURL = a.BrowserDownloadURL
			} else {
				sel.sigURL = a.URL
			}
		}
	}
	return sel
}

// fetchChecksumSidecar downloads the published .sha256 sidecar asset and
// returns the bare 64-hex digest, normalized to lowercase (uppercase hex
// from checksum tools is accepted). Accepts both "sha256sum" format
// ("<hex>  <name>") and a bare hex line.
func fetchChecksumSidecar(client *http.Client, url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent())
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errReleaseFetch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: HTTP %d for %s", errReleaseFetch, resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	fields := strings.Fields(strings.TrimSpace(string(body)))
	if len(fields) == 0 {
		return "", fmt.Errorf("empty sidecar")
	}
	hexd := fields[0]
	if len(hexd) != 64 {
		return "", fmt.Errorf("malformed sidecar: %q", hexd)
	}
	// Some pipelines and checksum tools emit uppercase hex (sha256sum -b on
	// some distros, hand-typed digests). Normalize before validating so an
	// uppercase sidecar is accepted and still compares equal to the
	// lowercase digest computed by fileSHA256.
	hexd = strings.ToLower(hexd)
	for _, c := range hexd {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", fmt.Errorf("sidecar digest is not hex: %q", hexd)
		}
	}
	return hexd, nil
}

func downloadAsset(client *http.Client, url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	// Request the identity (uncompressed) form and the octet-stream content
	// type explicitly. A CDN edge that serves a gzip-encoded object without
	// the Content-Encoding header would otherwise hand us compressed bytes
	// that fail the SHA-256 check with no obvious cause; the Accept header
	// makes an API asset URL (fallback path) return the binary instead of
	// its JSON metadata.
	req.Header.Set("User-Agent", userAgent())
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Accept", "application/octet-stream")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && ce != "identity" {
		return "", fmt.Errorf("unexpected Content-Encoding %q from release CDN (refusing to verify compressed bytes)", ce)
	}
	f, err := os.CreateTemp("", "pulsemon-update-*")
	if err != nil {
		return "", err
	}
	defer f.Close()
	// Hard byte cap: the Content-Length cross-check below only catches
	// truncation, not a lying CDN that streams an enormous body (or a
	// mismatched-but-claimed-large one), which would fill the temp
	// filesystem before any verification could fail. 512 MiB is far past
	// any plausible pulsemon release.
	const maxAssetBytes = 512 << 20
	var got int64
	if got, err = io.Copy(f, io.LimitReader(resp.Body, maxAssetBytes+1)); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	if got > maxAssetBytes {
		os.Remove(f.Name())
		return "", fmt.Errorf("release asset exceeds %d bytes", maxAssetBytes)
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if want, perr := strconv.ParseInt(cl, 10, 64); perr == nil && got != want {
			os.Remove(f.Name())
			return "", fmt.Errorf("downloaded %d bytes, header said %d (connection truncated?)", got, want)
		}
	}
	return f.Name(), nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

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
	if haveOwner {
		if err := os.Chown(dst, int(wantUID), int(wantGID)); err != nil {
			uWarn("could not restore original ownership on " + dst + ": " + err.Error())
		}
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

// errReleaseFetch marks a failure to FETCH a release artifact (the .sig or
// .sha256 asset download) as distinct from a verification VERDICT (bad or
// missing signature, SHA mismatch, missing sidecar asset). Fetch failures
// embed upstream detail — asset URLs, DNS names, proxy config — which the
// API layer must not echo into a response body (handleUpdate splits on
// this sentinel); verdicts are operator-actionable and are surfaced
// verbatim. The CLI path (runUpdate) shows the full error either way.
var errReleaseFetch = errors.New("release asset fetch failed")

// verifyDownloadedAsset enforces the mandatory authenticity + integrity
// checks on a downloaded release asset. It runs TWO gates, in order:
//
//  1. AUTHENTICITY (the load-bearing one): the binary's detached ed25519
//     signature (targetAsset()+".sig", resolved by name in selectAssets)
//     must verify against at least one of the embedded trusted release
//     pubkeys (release_pubkeys). This is FAIL-CLOSED — a missing .sig, an
//     undecodable signature, or one that verifies against no trusted key is
//     a refusal. A compromised release pipeline can publish a trojaned
//     binary and a matching SHA-256 (both come from the same release), but
//     it cannot sign the binary without the private key, so it cannot pass
//     this gate.
//
//  2. INTEGRITY (defense in depth): the SHA-256 must match the release's
//     published digest (GitHub API digest, or the .sha256 sidecar when that
//     is absent — pre-2025 uploads; when NEITHER exists it refuses). A
//     valid signature already pins the exact bytes the key holder signed, so
//     this is a redundant integrity net; it is kept because it is cheap and
//     catches a sig/bytes skew.
//
// Shared by the CLI (runUpdate) and the dashboard endpoint (handleUpdate) so
// the verification contract lives in one place. Returns the verified digest.
func verifyDownloadedAsset(client *http.Client, sel releaseSelection, tmp string) (string, error) {
	// Stream the digest ONCE: the asset is up to 512 MiB (maxAssetBytes)
	// and a low-RAM SBC must not page the whole binary in just to hash it.
	// Both gates below consume this one digest.
	digest, err := fileSHA256(tmp)
	if err != nil {
		return "", fmt.Errorf("verify: %v", err)
	}

	// Gate 1: authenticity. Fail-closed — see verifyReleaseSignature.
	if err := verifyReleaseSignature(client, sel, digest); err != nil {
		return "", err
	}

	// Gate 2: integrity (defense in depth on top of the signature).
	verifySHA := strings.TrimPrefix(sel.sha, "sha256:")
	if verifySHA == "" {
		if sel.sidecarURL == "" {
			return "", fmt.Errorf("no trusted SHA-256 sidecar asset found in release")
		}
		sidecar, err := fetchChecksumSidecar(client, sel.sidecarURL)
		if err != nil {
			return "", fmt.Errorf("no trusted SHA-256 available (sidecar fetch failed: %v)", err)
		}
		verifySHA = sidecar
	}
	if digest != verifySHA {
		return "", fmt.Errorf("SHA-256 MISMATCH — expected %s, got %s", verifySHA, digest)
	}
	return digest, nil
}

// parseReleasePubkeys decodes the embedded trusted release-signing pubkeys
// (release_pubkeys: hex ed25519 pubkeys, one per line; '#' comments and
// blank lines ignored) into ed25519 public keys.
func parseReleasePubkeys() ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for _, line := range strings.Split(string(releasePubkeys), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		b, err := hex.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("release_pubkeys: bad hex key: %v", err)
		}
		if len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("release_pubkeys: key is %d bytes, want %d", len(b), ed25519.PublicKeySize)
		}
		keys = append(keys, ed25519.PublicKey(b))
	}
	if len(keys) == 0 {
		return nil, errors.New("release_pubkeys: no trusted keys embedded")
	}
	return keys, nil
}

// fetchReleaseSignature downloads the detached .sig asset for the release
// binary and returns the decoded ed25519 signature bytes. The .sig is the
// hex-encoded 64-byte signature (one line), produced by `pulsemon sign
// release`. The read is capped far below any real signature to bound it.
func fetchReleaseSignature(client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent())
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errReleaseFetch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d for %s", errReleaseFetch, resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return nil, err
	}
	sig, err := hex.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		return nil, fmt.Errorf("malformed .sig (not hex): %v", err)
	}
	return sig, nil
}

// releaseManifestMessage is the exact byte string a release signature
// covers: a versioned manifest binding the signature to the release TAG,
// the ASSET NAME, and the binary's SHA-256. A signature made for one
// (tag, asset, sha) triple cannot verify against any other — a compromised
// account (no signing key) can no longer replay an old signed binary under
// a new tag, and a wrong-arch .sig (linux-amd64 asset verified as
// linux-arm64) is refused too. The format is versioned (line 1) so a
// future field can be added without silently re-keying old signatures.
//
// The raw-bytes form (v0.4.4 and earlier) signed the RAW BINARY BYTES
// instead; it is no longer accepted by verifyReleaseSignature (it bound
// nothing but the bytes, leaving a replay hole — see the comment there). It
// is retained in the `sign` maintainer tool (2/4-arg forms) for historical
// verification only.
func releaseManifestMessage(tag, asset, sha256Hex string) []byte {
	return []byte(fmt.Sprintf("pulsemon-release-v1\n%s\n%s\n%s\n", tag, asset, sha256Hex))
}

// verifyReleaseSignature checks the downloaded binary's detached ed25519
// signature against the embedded trusted pubkey set. FAIL-CLOSED: a missing
// .sig asset, an undecodable/oversized signature, or a signature that
// verifies against none of the trusted keys is a refusal — an unsigned or
// foreign-signed release must never install. This is the authenticity root
// the SHA-256 check cannot provide.
//
// The signature is checked against the MANIFEST (tag + asset + sha256). The
// digest is passed in by the caller (verifyDownloadedAsset streams it once
// via fileSHA256) so the multi-hundred-MiB binary is never held in memory
// just to build the manifest message.
func verifyReleaseSignature(client *http.Client, sel releaseSelection, sha256Hex string) error {
	if sel.sigURL == "" {
		return errors.New("release has no .sig signature asset — refusing to install an unsigned release")
	}
	sig, err := fetchReleaseSignature(client, sel.sigURL)
	if err != nil {
		return fmt.Errorf("release signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("release signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	keys, err := parseReleasePubkeys()
	if err != nil {
		return err
	}
	// The signature must verify against the MANIFEST (tag + asset + sha256).
	// The legacy raw-bytes form (pre-manifest releases, v0.4.4 and earlier)
	// is NO LONGER accepted: it bound the signature to the bytes only, so a
	// compromised release account (no signing key) could re-upload an old
	// signed binary under a newer-looking tag and the signature would still
	// verify — a replay the anti-downgrade floor cannot catch, because the
	// tag is attacker-chosen (it sits above the floor). The fallback existed
	// for ONE transition release (the first carrying this manifest verifier,
	// cut v0.4.4→v0.4.5 era) so v0.4.4-era clients could install it; that is
	// long past (VERSION is well beyond it), and no client running this
	// verifier can self-update to a pre-manifest release anyway (downgrades
	// are refused by the floor), so the fallback was dead weight that
	// re-opened the replay hole. Fail closed if the binding fields are
	// missing — a signature with no tag/asset to bind to is unverifiable.
	if sel.tag == "" || sel.asset == "" {
		return errors.New("release signature: missing tag or asset — the manifest-bound signature cannot be verified")
	}
	msg := releaseManifestMessage(sel.tag, sel.asset, sha256Hex)
	for _, pub := range keys {
		if ed25519.Verify(pub, msg, sig) {
			return nil
		}
	}
	return errors.New("release signature invalid — the binary is not signed by a trusted release key for this release tag and asset")
}

// runSignRelease implements the maintainer's release-signing commands:
//
//	pulsemon sign genkey                   -> new ed25519 keypair (stdout)
//	pulsemon sign release <file> <keyfile> -> write <file>.sig
//	pulsemon sign verify <file>            -> check <file>.sig vs embedded keys
//
// genkey prints the public key (hex, add to release_pubkeys) and the private
// key (hex, keep as the release-signing secret). `release` signs a release
// binary's exact bytes with the private key (a hex ed25519 private key, one
// line, in <keyfile>) and writes a detached .sig next to it (hex, one line) —
// the asset verifyReleaseSignature checks at update time. `verify` re-checks
// an existing <file>.sig against the EMBEDDED release_pubkeys (the same keys
// a client verifies with), so a release cut with the wrong key is caught
// before it ships.
//
// This is a MAINTAINER tool run on the trusted release host during a cut; it
// is not part of the update path and never runs on a client.
func runSignRelease(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: pulsemon sign <genkey|release <file> <keyfile>|verify <file>>")
		return 1
	}
	switch args[0] {
	case "genkey":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			uErr("generate key: " + err.Error())
			return 1
		}
		fmt.Println("# pulsemon release-signing keypair (ed25519).")
		fmt.Println("# Add the PUBLIC key to release_pubkeys (one line).")
		fmt.Println("# Keep the PRIVATE key ONLY on the trusted release host (600-perm")
		fmt.Println("# file) — it never touches CI; Windows is signed offline like Linux.")
		fmt.Println("# NEVER commit the private key.")
		fmt.Println("PUBKEY=" + hex.EncodeToString(pub))
		fmt.Println("PRIVKEY=" + hex.EncodeToString(priv))
		return 0
	case "release":
		// 2 args = LEGACY form (sign the raw binary bytes; pre-manifest
		// releases — the first release carrying the manifest verifier is
		// cut this way so v0.4.4-era clients can install it).
		// 4 args = MANIFEST form: sign "pulsemon-release-v1\n<tag>\n<asset>\n<sha256>\n",
		// binding the signature to the release tag, asset name and digest.
		if len(args) != 3 && len(args) != 5 {
			fmt.Fprintln(os.Stderr, "usage: pulsemon sign release <file> <keyfile> [tag asset-name]")
			return 1
		}
		file, keyfile := args[1], args[2]
		binBytes, err := os.ReadFile(file)
		if err != nil {
			uErr("read " + file + ": " + err.Error())
			return 1
		}
		keyHex, err := os.ReadFile(keyfile)
		if err != nil {
			uErr("read " + keyfile + ": " + err.Error())
			return 1
		}
		priv, err := hex.DecodeString(strings.TrimSpace(string(keyHex)))
		if err != nil {
			uErr("keyfile is not hex: " + err.Error())
			return 1
		}
		if len(priv) != ed25519.PrivateKeySize {
			uErr("keyfile is " + strconv.Itoa(len(priv)) + " bytes, want " + strconv.Itoa(ed25519.PrivateKeySize))
			return 1
		}
		msg := binBytes
		form := "legacy raw-bytes"
		if len(args) == 5 {
			sum := sha256.Sum256(binBytes)
			msg = releaseManifestMessage(args[3], args[4], hex.EncodeToString(sum[:]))
			form = "manifest (" + args[3] + ", " + args[4] + ")"
		}
		sig := ed25519.Sign(ed25519.PrivateKey(priv), msg)
		sigPath := file + ".sig"
		if err := os.WriteFile(sigPath, []byte(hex.EncodeToString(sig)+"\n"), 0o644); err != nil {
			uErr("write " + sigPath + ": " + err.Error())
			return 1
		}
		// Self-check: the signature we just wrote must verify against the key's
		// public half (an ed25519 private key's last 32 bytes are its pubkey).
		if !ed25519.Verify(ed25519.PublicKey(priv[32:]), msg, sig) {
			uErr("sign self-check failed (signature did not verify)")
			return 1
		}
		uInfo("signed " + file + " -> " + sigPath + " [" + form + "]")
		sum := sha256.Sum256(binBytes)
		uInfo("sha256:  " + hex.EncodeToString(sum[:]))
		return 0
	case "verify":
		// 1 arg = LEGACY check (raw binary bytes). 3 args = MANIFEST check:
		// the tag and asset name must match the signed manifest, which is
		// what catches a signature replayed from a different release.
		if len(args) != 2 && len(args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: pulsemon sign verify <file> [tag asset-name]")
			return 1
		}
		file := args[1]
		binBytes, err := os.ReadFile(file)
		if err != nil {
			uErr("read " + file + ": " + err.Error())
			return 1
		}
		sigRaw, err := os.ReadFile(file + ".sig")
		if err != nil {
			uErr("read " + file + ".sig: " + err.Error())
			return 1
		}
		sig, err := hex.DecodeString(strings.TrimSpace(string(sigRaw)))
		if err != nil {
			uErr(file + ".sig is not hex: " + err.Error())
			return 1
		}
		if len(sig) != ed25519.SignatureSize {
			uErr(file + ".sig is " + strconv.Itoa(len(sig)) + " bytes, want " + strconv.Itoa(ed25519.SignatureSize))
			return 1
		}
		keys, err := parseReleasePubkeys()
		if err != nil {
			uErr(err.Error())
			return 1
		}
		verified, form := false, "legacy raw-bytes"
		if len(args) == 4 {
			// Manifest mode verifies ONLY the manifest-bound message. The
			// old code fell through to the raw-bytes check when this
			// failed — letting a legacy raw-bytes .sig (uninstallable by
			// the manifest client, and unbound to this tag/asset, so a
			// signature replayed from another release passes) sail through
			// release CI.
			sum := sha256.Sum256(binBytes)
			msg := releaseManifestMessage(args[2], args[3], hex.EncodeToString(sum[:]))
			for _, pub := range keys {
				if ed25519.Verify(pub, msg, sig) {
					verified, form = true, "manifest ("+args[2]+", "+args[3]+")"
					break
				}
			}
		} else {
			// 2-arg legacy mode: the raw-bytes check is the ONLY form
			// (pre-manifest releases).
			for _, pub := range keys {
				if ed25519.Verify(pub, binBytes, sig) {
					verified = true
					break
				}
			}
		}
		if verified {
			uInfo("signature valid: " + file + " verifies against the embedded release_pubkeys [" + form + "]")
			return 0
		}
		uErr("signature INVALID: " + file + " does not verify against the embedded release_pubkeys (wrong signing key, or tag/asset mismatch?)")
		return 1
	default:
		fmt.Fprintln(os.Stderr, "usage: pulsemon sign <genkey|release <file> <keyfile> [tag asset-name]|verify <file> [tag asset-name]>")
		return 1
	}
}

// detectRestart and performRestart are vars (not plain funcs) so tests can
// stub them: a unit test must NEVER run systemctl against the host it runs
// on. The real implementations shell out to systemctl; the stubs in
// update_restart_test.go just record what would have run.
var (
	detectRestart  = detectRestartSystemd
	performRestart = func(bus string) error { return runRestart(bus) }
)

// apiAutoRestart reports whether the in-dashboard update (POST /api/update,
// which runs INSIDE the server process) may restart the service itself
// after the binary swap. systemd (the default): yes. Windows: NO — the
// service runs as its own virtual service account (NT SERVICE\Pulsemon),
// and that VSA cannot start/stop its own service (mandatory-integrity
// enforcement denies it even though the DACL grants START|STOP — probed
// live from the service's own token), so an in-process restart is
// impossible. The Windows in-dashboard update stages the verified binary
// and hands the operator the restart (restartServiceHint); an elevated
// console `pulsemon update --restart` keeps the full auto-restart path
// (a High-integrity token passes the SCM check). Windows overrides in
// update_windows.go.
var apiAutoRestart = true

// restartServiceHint is the operator-facing restart instruction carried in
// the "installed" (staged) update response. The systemd default is generic;
// Windows overrides in update_windows.go with the service name and its two
// restart paths (services.msc / Restart-Service).
var restartServiceHint = "the new binary is installed; restart the pulsemon service to pick it up"

// detectRestartSystemd reports which systemd bus the live pulsemon service runs
// on: "user" if a user-bus service is active, "system" if a system-bus service
// is active (root), else "" when no live service is confidently detectable.
// It probes the USER bus first (that's how install.sh installs it) and falls
// back to the system bus. Probing via is-active (exit code, not output) means
// root's nonexistent user bus and non-systemd hosts both report "" — the safe
// "don't guess a restart" answer.
func detectRestartSystemd() string {
	if systemctlActive("user") {
		return "user"
	}
	if systemctlActive("system") {
		return "system"
	}
	return ""
}

// systemctlActive reports whether the pulsemon service is active on the given
// bus ("user" or "system"). `systemctl is-active` exits 0 only when active.
// Bounded by activeTimeout: systemctl talks to dbus, and a wedged bus
// must not stall `pulsemon update --restart` — an unanswered probe is treated
// as "no live service" and the safe hint is printed.
func systemctlActive(bus string) bool {
	args := []string{"is-active", "pulsemon"}
	if bus == "user" {
		args = append([]string{"--user"}, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), activeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, systemctlPath(), args...)
	// is-active prints "active"/"inactive"/"failed"/"unknown"; we only care
	// about the exit code, so discard output.
	return cmd.Run() == nil
}

// validRestartBus reports whether bus names a bus the restart paths
// understand: "user" or "system" (systemd) or "windows-service" (the
// Windows SCM). "" is accepted (no bus — the caller detects at runtime).
// The watchdog CLI validates --bus against this: a garbage value would
// be issued to systemctl for a unit that is not there.
func validRestartBus(bus string) bool {
	switch bus {
	case "", "user", "system", "windows-service":
		return true
	}
	return false
}

// runRestart restarts the pulsemon service on the given bus and waits for the
// command to return. Bounded by restartTimeout: systemctl restart can wait a
// while for the unit to settle (a slow or stuck service), and the bound keeps
// a wedged dbus from hanging the update indefinitely.
//
// A `reset-failed` on the SAME bus runs first: a crash-looped broken binary
// trips StartLimitBurst, and until the failed state is reset the restart
// fails with "start-limit-hit" no matter how often it is retried — exactly
// the state the post-rollback restart faces. Best effort: on a healthy unit
// reset-failed is a no-op, and a reset failure must not block the restart.
func runRestart(bus string) error {
	resetArgs := []string{"reset-failed", "pulsemon"}
	restartArgs := []string{"restart", "pulsemon"}
	if bus == "user" {
		resetArgs = append([]string{"--user"}, resetArgs...)
		restartArgs = append([]string{"--user"}, restartArgs...)
	}
	run := func(args []string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), restartTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, systemctlPath(), args...)
		// If systemctl (or a wrapper) leaves a child holding the output
		// pipe, the context kill alone would not release CombinedOutput:
		// bound the wait too.
		cmd.WaitDelay = 2 * time.Second
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	// reset-failed first (see above); its result is deliberately
	// discarded — the restart below is the load-bearing call.
	_, _ = run(resetArgs)
	out, err := run(restartArgs)
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// journalHint is the operator's next diagnostic step after a restart problem.
func journalHint(bus string) string {
	if bus == "user" {
		return "journalctl --user -u pulsemon"
	}
	if bus == "windows-service" {
		return "the Windows Event Log (Application) + %ProgramData%\\Pulsemon\\pulsemon-watchdog.log"
	}
	return "journalctl -u pulsemon"
}

// unitFileCandidates are the pulsemon systemd unit files the CLI consults
// for unit-level environment: the user unit first
// (install.sh's default), then the system unit.
func unitFileCandidates() []string {
	var out []string
	if home, err := os.UserHomeDir(); err == nil {
		out = append(out, filepath.Join(home, ".config/systemd/user/pulsemon.service"))
	}
	out = append(out, "/etc/systemd/system/pulsemon.service")
	return out
}

// unitEnvVar returns name's value from the pulsemon unit's Environment=
// lines: `pulsemon update --restart` runs from the
// operator's shell, which does NOT carry the unit's PULSEMON_ADDR /
// PULSEMON_DB — the post-restart healthz poll and the DB lookup then fell
// back to defaults, so a non-default-port install could never verify its
// own update. Shell env wins (callers check it first); this is the
// fallback. Understands systemd's Environment= shapes: K=V, quoted K=V,
// and space-separated lists.
func unitEnvVar(name string) string {
	for _, path := range unitFileCandidates() {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "Environment=") {
				continue
			}
			for _, kv := range strings.Fields(strings.TrimPrefix(line, "Environment=")) {
				kv = strings.Trim(kv, `"'`)
				if k, v, ok := strings.Cut(kv, "="); ok && k == name {
					return strings.Trim(v, `"'`)
				}
			}
		}
	}
	return ""
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

// systemctlPath is the systemctl binary the updater/restart helpers execute.
// A var so tests can inject a fake: a unit test must NEVER run the host's real
// systemctl (it would restart a real pulsemon service on a dev/test box).
var systemctlPath = resolveSystemctl

// resolveSystemctl picks the systemctl binary. The fixed system locations win
// over $PATH so a writable directory early in PATH cannot substitute its own
// "systemctl"; PATH is only the fallback for unusual layouts (NixOS, containers).
func resolveSystemctl() string {
	for _, p := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	if p, err := exec.LookPath("systemctl"); err == nil {
		return p
	}
	return "systemctl"
}
