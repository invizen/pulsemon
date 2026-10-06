package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
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

// parseVer parses a semver-ish version ("v1.2.3", "1.2.3-beta"). ok=false
// means the string is not a version at all (e.g. the "dev" build default),
// which callers treat as "older than any release".
func parseVer(s string) (maj, min, pat int, ok bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return 0, 0, 0, false
	}
	maj, e1 := strconv.Atoi(parts[0])
	min, e2 := strconv.Atoi(parts[1])
	if e1 != nil || e2 != nil || maj < 0 || min < 0 {
		return 0, 0, 0, false
	}
	if len(parts) > 2 {
		var e3 error
		pat, e3 = strconv.Atoi(parts[2])
		if e3 != nil {
			return 0, 0, 0, false
		}
	}
	return maj, min, pat, true
}

// newerRelease reports whether the release tag is strictly newer than the
// running version. An unstamped ("dev") binary is always treated as older.
func newerRelease(releaseTag, running string) bool {
	rmaj, rmin, rpat, rok := parseVer(releaseTag)
	if !rok {
		return false
	}
	maj, min, pat, ok := parseVer(running)
	if !ok {
		return true
	}
	switch {
	case rmaj != maj:
		return rmaj > maj
	case rmin != min:
		return rmin > min
	}
	return rpat > pat
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
// on a Pi 4/5 or RK3588). It honors $GOARCH so a host can deliberately fetch
// a different architecture's release asset. The sidecar checksum asset is
// targetAsset() + ".sha256" (see the fallback below).
func targetAsset() string {
	goarch := os.Getenv("GOARCH")
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	return fmt.Sprintf("pulsemon-%s-%s", runtime.GOOS, goarch)
}

// runUpdate implements `pulsemon update`. Works from any directory: it
// locates the running binary via os.Executable, so the systemd unit and
// Docker need no changes.
//
//	pulsemon update          check + install if newer
//	pulsemon update check    check only, no install
//	pulsemon update v0.1.5   install a specific version
//	pulsemon update --restart install AND restart the running service
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
	version := "latest"
	for _, a := range args {
		switch a {
		case "check", "--check":
			checkOnly = true
		case "restart", "--restart":
			restart = true
		case "-h", "--help":
			fmt.Println("usage: pulsemon update [check|<version>] [--restart]")
			return 0
		default:
			version = a
		}
	}

	exe, err := os.Executable()
	if err != nil {
		uErr("cannot locate running binary: " + err.Error())
		return 1
	}
	// Best-effort symlink resolution (on Linux os.Executable already returns
	// the resolved path via /proc/self/exe, so this mostly matters on other
	// platforms). Never ignore the error: a failed resolution that empties
	// exe would make installBinary's filepath.Dir(dst) fall back to the CWD
	// and swap the binary into the working directory instead of the install
	// location.
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	} else {
		uWarn("could not evaluate symlink for " + exe + ": " + err.Error())
	}
	uInfo("binary:  " + exe)
	uInfo("version: " + Version)

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
	assetURL, sha := sel.assetURL, sel.sha

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

	uInfo("downloading " + rel.TagName + "...")
	tmp, err := downloadAsset(client, assetURL)
	if err != nil {
		uErr("download: " + err.Error())
		return 1
	}
	defer os.Remove(tmp)

	// Mandatory verification (security): the update must never install an
	// unverified binary. Primary source is the GitHub-computed asset digest
	// from the release API; if that is absent (pre-2025 uploads) we fall
	// back to the published sidecar asset (targetAsset()+".sha256", resolved
	// by name in selectAssets — never by string-munging the binary URL,
	// which 404'd when the URL was the API endpoint ".../assets/N"). If
	// NEITHER exists we refuse the update — an unverifiable binary is worse
	// than no update (guards against DNS poisoning, MITM, or a compromised
	// release pipeline).
	verifySHA := strings.TrimPrefix(sha, "sha256:")
	if verifySHA == "" {
		if sel.sidecarURL == "" {
			uErr("refusing to update: no trusted SHA-256 sidecar asset found in " + rel.TagName)
			return 1
		}
		sidecar, err := fetchChecksumSidecar(client, sel.sidecarURL)
		if err != nil {
			uErr("refusing to update: no trusted SHA-256 available for " + rel.TagName)
			uErr("  (sidecar fetch failed: " + err.Error() + ")")
			return 1
		}
		verifySHA = sidecar
		uInfo("sha256 source: release sidecar asset (API digest unavailable)")
	}
	got, err := fileSHA256(tmp)
	if err != nil {
		uErr("verify: " + err.Error())
		return 1
	}
	if got != verifySHA {
		uErr("SHA-256 MISMATCH — expected " + verifySHA + ", got " + got)
		uErr("refusing to install.")
		return 1
	}
	uInfo("sha256:  " + got + " ✓")

	if err := installBinary(tmp, exe); err != nil {
		uErr("install: " + err.Error())
		return 1
	}
	uInfo("installed " + rel.TagName + " to " + exe)

	return handleRestart(exe, restart)
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
	// Poll healthz to confirm the new binary actually came up.
	if ok, detail := waitHealthy(); ok {
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
		url = releaseBase + "/tags/" + version
	}
	req, _ := http.NewRequest("GET", url, nil)
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
	var got int64
	if got, err = io.Copy(f, resp.Body); err != nil {
		os.Remove(f.Name())
		return "", err
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
func installBinary(src, dst string) error {
	// Preserve the original binary's ownership (a root-installed binary
	// must stay root-owned after a root update). The rename replaces dst's
	// inode with one owned by the executing user, so restore the recorded
	// owner on EVERY original — including 0:0, which the previous
	// "uid != 0 || gid != 0" guard silently skipped.
	var wantUID, wantGID uint32
	haveOwner := false
	if fi, err := os.Stat(dst); err == nil && fi.Sys() != nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			wantUID, wantGID = st.Uid, st.Gid
			haveOwner = true
		}
	}

	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".pulsemon-swap-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename

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
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	if haveOwner {
		if err := os.Chown(dst, int(wantUID), int(wantGID)); err != nil {
			uWarn("could not restore original ownership on " + dst + ": " + err.Error())
		}
	}
	return nil
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
	cmd := exec.CommandContext(ctx, "systemctl", args...)
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
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
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

// healthzTarget derives the host:port to healthcheck from PULSEMON_ADDR, the
// same way install.sh does:
//
//	":9299"           -> "localhost:9299"  (all-interface bind)
//	"127.0.0.1:9299"  -> "127.0.0.1:9299"
//	"9299" (bare)     -> "localhost:9299"
//	"" (unset)        -> "localhost:9299"  (the binary's own default)
func healthzTarget() string {
	addr := os.Getenv("PULSEMON_ADDR")
	switch {
	case addr == "":
		return "localhost:9299"
	case strings.HasPrefix(addr, ":"):
		return "localhost" + addr
	case strings.ContainsRune(addr, ':'):
		return addr
	default: // bare port
		return "localhost:" + addr
	}
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

// waitHealthy polls the pulsemon healthz endpoint until it answers a 2xx/3xx or
// the timeout elapses. It returns ok plus a short detail for the log line.
func waitHealthy() (bool, string) {
	target := healthzTarget()
	url := "http://" + target + "/api/healthz"
	deadline := time.Now().Add(healthzTimeout)
	client := &http.Client{Timeout: 3 * time.Second}
	var lastErr error
	for {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 400 {
				return true, target
			}
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return false, target + " — " + lastErr.Error()
		}
		time.Sleep(500 * time.Millisecond)
	}
}
