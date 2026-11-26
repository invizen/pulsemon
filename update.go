package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
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

func uErr(msg string) { fmt.Fprintf(os.Stderr, "%s%s[x]%s %s\n", uBold, uRed, uReset, msg) }

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

	client := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: releaseCheckRedirect,
	}

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
	tmp, err := downloadAsset(client, assetURL, filepath.Dir(exe))
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

// userAgent identifies this client to the GitHub API. GitHub's API
// guidelines require a custom User-Agent; the stdlib default
// (Go-http-client/1.1) gets throttled or 403'd far more aggressively
// than an app-specific one. Set on EVERY outbound request below —
// fetchRelease, fetchChecksumSidecar and downloadAsset all reach
// api.github.com (the asset-URL fallback paths included).
func userAgent() string {
	return "pulsemon-updater/" + Version
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
