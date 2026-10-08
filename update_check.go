package main

import (
	"net/http"
	"sync"
	"time"
)

// updateCheckResult is the cached outcome of a GitHub releases lookup.
// It is served from memory for updateCheckTTL to avoid hammering the
// GitHub API on every poll cycle.
type updateCheckResult struct {
	Running   string `json:"running"`
	Latest    string `json:"latest"`
	Available bool   `json:"available"`
	URL       string `json:"url"`
	CheckedAt string `json:"checked_at"`
}

var (
	updateCheckMu     sync.Mutex
	updateCheckCached *updateCheckResult
	updateCheckAt     time.Time
	updateCheckTTL    = 30 * time.Minute
)

// handleUpdateCheck reports whether a newer release is available on
// GitHub. It reuses fetchRelease + newerRelease from update.go so the
// version-comparison logic stays in one place. Results are cached for
// 30 minutes; a forced refresh can be triggered with ?refresh=1.
func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	refresh := r.URL.Query().Get("refresh") == "1"

	updateCheckMu.Lock()
	if !refresh && updateCheckCached != nil && time.Since(updateCheckAt) < updateCheckTTL {
		res := updateCheckCached
		updateCheckMu.Unlock()
		respondWithJSON(w, http.StatusOK, res)
		return
	}
	updateCheckMu.Unlock()

	client := &http.Client{Timeout: 10 * time.Second}
	rel, err := fetchRelease(client, "latest")
	if err != nil {
		respondWithError(w, http.StatusServiceUnavailable, "update check failed: "+err.Error())
		return
	}

	latest := rel.TagName
	avail := newerRelease(latest, Version)
	url := "https://github.com/invizen/pulsemon/releases/tag/" + latest

	res := &updateCheckResult{
		Running:   Version,
		Latest:    latest,
		Available: avail,
		URL:       url,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}

	updateCheckMu.Lock()
	updateCheckCached = res
	updateCheckAt = time.Now()
	updateCheckMu.Unlock()

	respondWithJSON(w, http.StatusOK, res)
}
