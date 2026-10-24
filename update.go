package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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
	wdPrev, wdDst := "", ""
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
		case "watchdog", "--watchdog":
			// The detached post-restart guardian (I2) — see runWatchdog.
			watchdog = true
		case "--prev", "--dst", "--timeout", "--old-pid":
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
			fmt.Println("usage: pulsemon update [check|rollback|watchdog|<version>] [--restart]")
			fmt.Println("       pulsemon update watchdog --prev <bin.prev> --dst <bin> [--timeout 30s] [--old-pid PID]")
			return 0
		default:
			version = a
		}
	}

	if watchdog {
		return runWatchdog(wdPrev, wdDst, wdTimeout, wdOldPid)
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

	if err := installBinary(tmp, exe); err != nil {
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
func runWatchdog(prev, dst string, timeout time.Duration, oldPid int) int {
	if prev == "" || dst == "" {
		uErr("watchdog: --prev and --dst are required")
		return 1
	}
	// Guard order (review 2026-10-24). The spawning server holds the update
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
		return 0
	}
	uErr("watchdog: service not healthy after restart (" + detail + "); restoring " + prev)
	if err := os.Rename(prev, dst); err != nil {
		uErr("watchdog: rollback failed: " + err.Error())
		return 1
	}
	uInfo("watchdog: previous binary restored to " + dst)
	if d := detectRestart(); d != "" {
		if err := performRestart(d); err != nil {
			uErr("watchdog: restart after rollback failed: " + err.Error())
			return 1
		}
		uInfo("watchdog: service restarted with the previous binary")
	}
	return 0
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

// spawnUpdateWatchdog detaches `pulsemon update --watchdog ...` (I2) so the
// API's auto-restart path keeps a guardian after this process dies. The
// watchdog polls healthz and rolls back to <exe>.prev if the new binary
// never comes up. --old-pid is us: the watchdog must not lock-acquire or
// health-poll until THIS process is gone (review 2026-10-24).
func spawnUpdateWatchdog(exe string) error {
	cmd := exec.Command(exe, "update", "watchdog",
		"--prev", exe+".prev", "--dst", exe, "--timeout", "30s",
		"--old-pid", strconv.Itoa(os.Getpid()))
	return detachSpawn(cmd)
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

// releaseSelection is the (binary, digest, sidecar) triple resolved from a
// release's asset list for the running platform.
type releaseSelection struct {
	assetURL   string
	sha        string
	sidecarURL string
}

// selectAssets picks the release assets for this platform: the binary
// (targetAsset()), its GitHub-computed digest if present, and the
// targetAsset()+".sha256" sidecar URL used when no API digest exists. URLs
// prefer the browser download URL; the API asset endpoint only works with
// Accept: application/octet-stream and carries no asset name.
func selectAssets(rel *ghRelease) releaseSelection {
	sel := releaseSelection{}
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
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
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
func installBinary(src, dst string) error {
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

	if _, err := io.Copy(tmp, srcFile); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0755); err != nil {
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
	prev := dst + ".prev"
	if err := os.Rename(dst, prev); err != nil {
		if os.IsNotExist(err) {
			uWarn("no previous binary to keep at " + prev + " (nothing to roll back to later)")
		} else {
			return fmt.Errorf("save previous binary as %s: %w", prev, err)
		}
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

// verifyDownloadedAsset enforces the mandatory SHA-256 check on a downloaded
// release asset. Primary source is the GitHub-computed asset digest from the
// release API; when that is absent (pre-2025 uploads) it falls back to the
// published sidecar asset (targetAsset()+".sha256", resolved by name in
// selectAssets — never by string-munging the binary URL, which 404'd when
// the URL was the API endpoint ".../assets/N"). When NEITHER exists it
// refuses — an unverifiable binary is worse than no update (guards against
// DNS poisoning, MITM, or a compromised release pipeline). Returns the
// verified digest. Shared by the CLI (runUpdate) and the dashboard endpoint
// (handleUpdate) so the verification contract lives in one place.
//
// Security-review note (deliberate, do NOT
// re-flag as a bug): this check is INTEGRITY, not AUTHENTICITY. The SHA-256
// comes from the SAME GitHub release as the binary (API digest or .sha256
// sidecar), so it catches corruption, DNS poisoning, and MITM — but a
// compromised repo/release that publishes both a trojaned binary and a
// matching checksum passes. Closing that gap requires release SIGNING:
// sign the assets in the pipeline with a key held in a GitHub secret
// (minisign or cosign), embed the PUBLIC key here, and verify the
// signature before the hash. That is a longer-term project — keypair
// generation the operator owns, a secret in the repo settings, and
// signing steps in BOTH release flows (the Linux cut from zenai and
// windows-release.yml) plus a migration story for already-shipped
// binaries — and is parked as a deliberate decision, not an oversight.
// (The companion F9 item, the unpinned `go install go-winres@latest` in
// windows-release.yml, is fixed: pinned to v0.3.3, because that tool
// writes the .syso resource embedded in the Windows binary.)
func verifyDownloadedAsset(client *http.Client, sel releaseSelection, tmp string) (string, error) {
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
	got, err := fileSHA256(tmp)
	if err != nil {
		return "", fmt.Errorf("verify: %v", err)
	}
	if got != verifySHA {
		return "", fmt.Errorf("SHA-256 MISMATCH — expected %s, got %s", verifySHA, got)
	}
	return got, nil
}

// detectRestart and performRestart are vars (not plain funcs) so tests can
// stub them: a unit test must NEVER run systemctl against the host it runs
// on. The real implementations shell out to systemctl; the stubs in
// update_restart_test.go just record what would have run.
var (
	detectRestart  = detectRestartSystemd
	performRestart = func(bus string) error { return runRestart(bus) }
)

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

// runRestart restarts the pulsemon service on the given bus and waits for the
// command to return. Bounded by restartTimeout: systemctl restart can wait a
// while for the unit to settle (a slow or stuck service), and the bound keeps
// a wedged dbus from hanging the update indefinitely.
func runRestart(bus string) error {
	args := []string{"restart", "pulsemon"}
	if bus == "user" {
		args = append([]string{"--user"}, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), restartTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, systemctlPath(), args...)
	// If systemctl (or a wrapper) leaves a child holding the output pipe, the
	// context kill alone would not release CombinedOutput: bound the wait too.
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// journalHint is the operator's next diagnostic step after a restart problem.
func journalHint(bus string) string {
	if bus == "user" {
		return "journalctl --user -u pulsemon"
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
func healthzTargets(db *DB) []string {
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
var openHealthzDB = func() *DB {
	db, err := NewDB(healthzDBPath())
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
func waitHealthy(db *DB) (bool, string) {
	return waitHealthyWithTimeout(db, healthzTimeout)
}

// waitHealthyWithTimeout is the timeout-parameterized form of waitHealthy
// (the watchdog passes its own budget — see runWatchdog).
func waitHealthyWithTimeout(db *DB, timeout time.Duration) (bool, string) {
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
