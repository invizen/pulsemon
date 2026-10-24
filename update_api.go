package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// containerUpdateCommand is what the dashboard tells an operator to run when
// the install is a Docker container (the binary in the running image cannot
// be swapped from inside the container). It is deliberately generic — the
// repo is public, so no host-specific paths may be baked into the binary
// (see the strings-scrub test policy). A deployment can override it with
// PULSEMON_UPDATE_CMD to surface a box-specific one-liner (e.g. "sync source
// to vX.Y.Z && docker compose up -d --build").
const containerUpdateCommand = "docker compose up -d --build"

// updateResponse is the JSON body of POST /api/update. Status values:
//
//	container   — Docker install; the app cannot self-update, run `command`
//	up-to-date  — the running version is >= the release (nothing installed)
//	installed   — new binary on disk, no auto-restart possible (manual hint)
//	restarting  — new binary on disk, service restart issued (HTTP 202)
type updateResponse struct {
	Status  string `json:"status"`
	Running string `json:"running"`
	Target  string `json:"target,omitempty"`
	Bus     string `json:"bus,omitempty"`
	Hint    string `json:"hint,omitempty"`
	Command string `json:"command,omitempty"`
}

// updateMu serializes concurrent POST /api/update requests: two overlapping
// updates would race on the same download + rename, and a double
// `systemctl restart` is pointless churn. The lock is held until the
// restart is issued; in that path the process is about to die, so the
// deferred Unlock is a no-op safety net for the non-restart paths.
var updateMu sync.Mutex

// isContainerInstall reports whether this binary runs from the Docker image
// path (/pulsemon — the same heuristic handleRestart uses). Var so tests can
// stub it: a unit test binary is never at /pulsemon, and the test must never
// let the install path touch the real test binary.
var isContainerInstall = func() bool {
	exe, err := runningExecutable()
	return err == nil && exe == "/pulsemon"
}

// handleUpdate performs a self-update from the dashboard (POST /api/update).
// It is the HTTP twin of `pulsemon update --restart` and reuses its
// machinery: fetchRelease, selectAssets, downloadAsset, the mandatory
// SHA-256 verification (verifyDownloadedAsset), installBinary (atomic
// rename, ownership preserved), and the systemd detect/perform restart pair.
//
// Contract mirrors the CLI, with HTTP-shaped outcomes:
//
//	method not POST          -> 405
//	container install        -> 200 {status:"container", command} — a
//	read-only hint (no lock, no network, no swap), so it is served even
//	while auth is disabled
//	auth disabled            -> 403 (self-update requires an account)
//	update already running   -> 409
//	bad version pin          -> 400
//	not a newer release      -> 200 {status:"up-to-date"}
//	no platform asset        -> 409
//	download/verify failed   -> 502 (nothing installed)
//	install failed           -> 500 (nothing swapped)
//	installed, no service    -> 200 {status:"installed", hint}
//	installed + live service -> 202 {status:"restarting"} — sent BEFORE the
//	restart is issued: systemd's restart SIGTERMs this process, so the
//	client must have its answer first. The UI then polls /api/healthz for
//	the new version and reloads.
func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "use POST /api/update")
		return
	}
	// Container installs can never self-update (the image owns the binary),
	// so the answer is a static hint — no lock, no network, no swap. It is
	// deliberately served even while auth is disabled: it has none of the
	// side effects the auth gate below protects against.
	if isContainerInstall() {
		cmd := os.Getenv("PULSEMON_UPDATE_CMD")
		if cmd == "" {
			cmd = containerUpdateCommand
		}
		respondWithJSON(w, http.StatusOK, updateResponse{
			Status:  "container",
			Running: Version,
			Command: cmd,
		})
		return
	}
	// The self-update path is NOT part of the "auth off = fully open"
	// surface: it downloads a binary, overwrites the running one, and
	// restarts the service. On an auth-disabled install any LAN host
	// could otherwise trigger a restart loop — and a compromised upstream
	// release would auto-install on every auth-off box (2026-10-24 review
	// M1; the earlier deferral in docs/DEFERRED.md is lifted). Setup mode
	// (never bootstrapped) never reaches here: the auth gate 403s
	// everything outside the bootstrap surface. The CLI
	// (`pulsemon update`) remains the operator path in both states.
	if !s.auth.Enabled() {
		respondWithError(w, http.StatusForbidden,
			"self-update requires an account: create one in Settings, or run `pulsemon update`")
		return
	}
	if !updateMu.TryLock() {
		respondWithError(w, http.StatusConflict, "an update is already in progress")
		return
	}
	defer updateMu.Unlock()

	// Cross-process lock: updateMu only serializes
	// requests WITHIN this process — a concurrent `pulsemon update` CLI run
	// (or a second server instance) would race this install on the .prev
	// rename. The file lock covers the whole download→install→restart span.
	// It anchors to the executable's directory (see updateLockPath), the
	// same location the CLI's `pulsemon update` locks, so the two processes
	// serialize on the same file (review F19).
	lockFile, err := acquireUpdateLock()
	if err != nil {
		if errors.Is(err, errUpdateLockHeld) {
			respondWithError(w, http.StatusConflict, "update already in progress")
			return
		}
		respondInternal(w, "update lock", err)
		return
	}
	defer lockFile.Close()

	version := "latest"
	if r.ContentLength > 0 {
		var body struct {
			Version string `json:"version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil && body.Version != "" {
			version = body.Version
		}
	}
	// Pre-validate the pin the same way fetchRelease does, so a malformed
	// token (path traversal, whitespace) is a 400 before any network call.
	if version != "latest" {
		if !strings.HasPrefix(version, "v") {
			version = "v" + version
		}
		if !validVersionToken(version) {
			respondWithError(w, http.StatusBadRequest, "invalid version: expected a release tag like v0.3.13")
			return
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	rel, err := fetchRelease(client, version)
	if err != nil {
		// Upstream failure detail (URL/DNS/proxy) stays in the log
		// (review 2026-10-24, same class as update_check.go:80).
		log.Printf("update: fetch release: %v", err)
		respondWithError(w, http.StatusBadGateway, "could not reach GitHub releases; try again later")
		return
	}
	// Same ordering rule as the CLI: a pin that is not newer than the
	// running version is "up to date", never a downgrade.
	if !newerRelease(rel.TagName, Version) {
		respondWithJSON(w, http.StatusOK, updateResponse{
			Status:  "up-to-date",
			Running: Version,
			Target:  rel.TagName,
		})
		return
	}

	sel := selectAssets(rel)
	if sel.assetURL == "" {
		respondWithError(w, http.StatusConflict, "release "+rel.TagName+" has no "+targetAsset()+" asset")
		return
	}

	tmp, err := downloadAsset(client, sel.assetURL)
	if err != nil {
		log.Printf("update: download: %v", err)
		respondWithError(w, http.StatusBadGateway, "binary download failed; try again later")
		return
	}
	defer os.Remove(tmp)

	digest, err := verifyDownloadedAsset(client, sel, tmp)
	if err != nil {
		// Intentionally NOT redacted: this text is a SHA-256 mismatch /
		// missing-sidecar verdict — actionable, operator-facing, and
		// carries no upstream detail (review triage 2026-10-24).
		respondWithError(w, http.StatusBadGateway, "refusing to update: "+err.Error()) // redaction-ok: actionable SHA verdict
		return
	}

	exe, err := runningExecutable()
	if err != nil {
		respondInternal(w, "cannot locate running binary", err)
		return
	}
	if err := installBinary(tmp, exe, digest); err != nil {
		respondInternal(w, "install", err)
		return
	}

	// Restart decision mirrors the CLI contract: auto-restart ONLY when a
	// live systemd pulsemon service is confidently detected. Anything else
	// gets the install-and-hint answer (a bad new version must not take the
	// monitor down on its own).
	d := detectRestart()
	if d == "" {
		respondWithJSON(w, http.StatusOK, updateResponse{
			Status:  "installed",
			Running: Version,
			Target:  rel.TagName,
			Hint:    "the new binary is installed; restart the pulsemon service to pick it up",
		})
		return
	}

	// Answer first, then die: the restart SIGTERMs this process, so the
	// response must be on the wire (and flushed) before performRestart.
	res := updateResponse{Status: "restarting", Running: Version, Target: rel.TagName, Bus: d}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	// A failed encode leaves the client with an empty 202 body while the
	// restart proceeds regardless — irreversible from their side, so at
	// least make it visible in the log (review nit 2026-10-24).
	if err := json.NewEncoder(w).Encode(res); err != nil {
		log.Printf("update: 202 response encode/flush failed before restart (client sees an empty body; restart proceeds): %v", err)
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	fmt.Fprintf(os.Stderr, "pulsemon: updated to %s (sha256 %s); restarting %s service\n", rel.TagName, digest, d)
	// I2: this process dies with the restart, so a
	// broken new binary would stay broken with no one to roll it back.
	// Spawn a detached watchdog that polls healthz after the restart and
	// restores <exe>.prev if the new binary never comes up. If the spawn
	// fails, proceed with the restart and log it (per spec).
	if werr := spawnUpdateWatchdog(exe); werr != nil {
		fmt.Fprintf(os.Stderr, "pulsemon: watchdog spawn failed (proceeding without it): %v\n", werr)
	}
	if err := performRestart(d); err != nil {
		// The response is already sent; the only audience left is the log.
		fmt.Fprintf(os.Stderr, "pulsemon: update restart failed after install: %v (check: %s)\n", err, journalHint(d))
	}
}
