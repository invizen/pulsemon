package main

import (
	"net/http"
	"net/url"
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
	// Cached is true when the response was served from the last known
	// result while the GitHub check was failing (stale-but-useful), as
	// opposed to a fresh-lookup success.
	Cached bool `json:"cached,omitempty"`
}

var (
	updateCheckMu     sync.Mutex
	updateCheckCached *updateCheckResult
	updateCheckAt     time.Time
	updateCheckTTL    = 30 * time.Minute
	// How long a failed check suppresses new GitHub calls. Without this,
	// every 5s dashboard poll during an outage re-hits the API and walks
	// into a secondary rate limit, making the failure sticky.
	updateCheckFailTTL = 1 * time.Minute
	updateCheckFailed  bool
)

// handleUpdateCheck reports whether a newer release is available on
// GitHub. It reuses fetchRelease + newerRelease from update.go so the
// version-comparison logic stays in one place.
//
// Caching: successes are served from memory for updateCheckTTL; failures
// are suppressed for updateCheckFailTTL, and while suppressed the last
// known result is served as stale instead of erroring — a transient GitHub
// outage must not blank the version pill or hammer the API. With no cached
// result at all, a failure is a 503. Only a fresh success overwrites the
// cached result (the stale response carries cached:true).
func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	refresh := r.URL.Query().Get("refresh") == "1"

	// mu held across the whole check: that is the single-flight —
	// concurrent cache-miss requests queue here, and the first fetch
	// populates the cache before the next one proceeds.
	updateCheckMu.Lock()
	defer updateCheckMu.Unlock()

	if updateCheckCached != nil {
		age := time.Since(updateCheckAt)
		switch {
		case !refresh && !updateCheckFailed && age < updateCheckTTL:
			respondWithJSON(w, http.StatusOK, updateCheckCached)
			return
		case !refresh && updateCheckFailed && age < updateCheckFailTTL:
			res := *updateCheckCached
			res.Cached = true
			respondWithJSON(w, http.StatusOK, res)
			return
		}
	}

	client := &http.Client{Timeout: 10 * time.Second}
	rel, err := fetchRelease(client, "latest")
	if err != nil {
		if updateCheckCached != nil {
			updateCheckFailed = true // updateCheckAt unchanged: it ages the stale entry
			res := *updateCheckCached
			res.Cached = true
			respondWithJSON(w, http.StatusOK, res)
			return
		}
		respondWithError(w, http.StatusServiceUnavailable, "update check failed: "+err.Error())
		return
	}

	latest := rel.TagName
	avail := newerRelease(latest, Version)
	tagURL := "https://github.com/invizen/pulsemon/releases/tag/" + url.PathEscape(latest)

	res := &updateCheckResult{
		Running:   Version,
		Latest:    latest,
		Available: avail,
		URL:       tagURL,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}

	updateCheckCached = res
	updateCheckAt = time.Now()
	updateCheckFailed = false
	respondWithJSON(w, http.StatusOK, res)
}
