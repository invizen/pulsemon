package main

import (
	"encoding/json"
	"errors"
	"fmt"
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
//	update already running   -> 409
//	bad version pin          -> 400
//	container install        -> 200 {status:"container", command}
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
	// NOTE: handleUpdate deliberately has no "auth must be enabled" gate. A
	// review (M4c) proposed refusing the swap+restart on auth-off installs;
	// the owner decided to defer that (docs/DEFERRED.md), so on an auth-off
	// dashboard anyone who can reach the port can trigger an update.
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

	client := &http.Client{Timeout: 30 * time.Second}
	rel, err := fetchRelease(client, version)
	if err != nil {
		respondWithError(w, http.StatusBadGateway, "fetch release: "+err.Error())
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
		respondWithError(w, http.StatusBadGateway, "download: "+err.Error())
		return
	}
	defer os.Remove(tmp)

	digest, err := verifyDownloadedAsset(client, sel, tmp)
	if err != nil {
		respondWithError(w, http.StatusBadGateway, "refusing to update: "+err.Error())
		return
	}

	exe, err := runningExecutable()
	if err != nil {
		respondInternal(w, "cannot locate running binary", err)
		return
	}
	if err := installBinary(tmp, exe); err != nil {
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
	json.NewEncoder(w).Encode(res)
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
