package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
var releaseBase = "https://api.github.com/repos/invizen/zenmon/releases"

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
// on — "zenmon-<GOOS>-<GOARCH>" (e.g. zenmon-linux-amd64, zenmon-linux-arm64
// on a Pi 4/5 or RK3588). It honors $GOARCH so a host can deliberately fetch
// a different architecture's release asset. The sidecar checksum asset is
// targetAsset() + ".sha256" (see the fallback below).
func targetAsset() string {
	goarch := os.Getenv("GOARCH")
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	return fmt.Sprintf("zenmon-%s-%s", runtime.GOOS, goarch)
}

// runUpdate implements `zenmon update`. Works from any directory: it
// locates the running binary via os.Executable, so the systemd unit and
// Docker need no changes.
//
//	zenmon update        check + install if newer
//	zenmon update check  check only, no install
//	zenmon update v0.1.5 install a specific version
//
// Exit codes: 0 = up to date or update installed, 1 = failure,
// 2 = newer version available but --check (check-only, for scripting).
//
// It RETURNS the exit code instead of calling os.Exit itself: os.Exit skips
// the deferred os.Remove of the downloaded temp file, so every failed
// verification or check-only run would have orphaned a multi-megabyte binary
// in the system temp dir. main() performs the actual exit.
func runUpdate(args []string) int {
	checkOnly := false
	version := "latest"
	for _, a := range args {
		switch a {
		case "check", "--check":
			checkOnly = true
		case "-h", "--help":
			fmt.Println("usage: zenmon update [check|<version>]")
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
	exe, _ = filepath.EvalSymlinks(exe)
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

	if version == "latest" && !newerRelease(rel.TagName, Version) {
		if checkOnly {
			uInfo("up to date (" + Version + " is the latest release). Nothing to do.")
		} else {
			uInfo("already up to date (" + Version + "). Nothing to do.")
		}
		return 0
	}

	if checkOnly {
		uWarn("new version available: " + rel.TagName + " (running " + Version + "). Run 'zenmon update' to install.")
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

	// Restart hint: detect how this process is running.
	if exe == "/zenmon" {
		uWarn("container detected — the binary inside the image is unchanged; rebuild with `docker compose up -d --build` (pulling the new release) to update.")
		return 0
	}
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		uInfo("restart with: systemctl --user restart zenmon   (system-wide install: sudo systemctl restart zenmon)")
	} else {
		uWarn("restart the zenmon process to pick up the new binary.")
	}
	return 0
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
// returns the bare 64-hex digest. Accepts both "sha256sum" format
// ("<hex>  <name>") and a bare hex line.
func fetchChecksumSidecar(client *http.Client, url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
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
	for _, c := range hexd {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", fmt.Errorf("sidecar digest is not lowercase hex: %q", hexd)
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
	f, err := os.CreateTemp("", "zenmon-update-*")
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
	// must stay root-owned after a root update).
	var uid, gid uint32
	if fi, err := os.Stat(dst); err == nil && fi.Sys() != nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			uid, gid = st.Uid, st.Gid
		}
	}

	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".zenmon-swap-*")
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
	if uid != 0 || gid != 0 {
		if err := os.Chown(dst, int(uid), int(gid)); err != nil {
			uWarn("could not restore original ownership on " + dst + ": " + err.Error())
		}
	}
	return nil
}
