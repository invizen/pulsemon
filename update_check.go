package main

import (
	"log"
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
	// updateCheckAttemptAt is the time of the last fetchRelease ATTEMPT
	// (success or failure). It drives the ?refresh=1 throttle: unlike
	// updateCheckAt (the last SUCCESS, which ages the stale entry and never
	// advances on a failure), a failed attempt must also count, or an outage
	// would let ?refresh=1 keep forcing GitHub calls.
	updateCheckAttemptAt time.Time
	updateCheckTTL       = 30 * time.Minute
	// updateCheckRefreshMinInterval is the minimum time between two GitHub
	// fetches forced by ?refresh=1. Without it, an authenticated user (or
	// anyone on the LAN when auth is off) can spam the check: every ?refresh=1
	// bypasses the 30-min cache and forces fetchRelease while updateCheckMu is
	// held (blocking every other caller up to the 10s client timeout), and
	// rapid refreshes walk straight into GitHub's 60 req/hour unauthenticated
	// limit. A refresh younger than this is ignored and served from the cache
	// like a normal poll. 60s keeps an explicit "check now" useful while
	// bounding forced calls to one per minute.
	updateCheckRefreshMinInterval = 60 * time.Second
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
//
// ?refresh=1 forces a fresh lookup, but only when the last fetch attempt was
// at least updateCheckRefreshMinInterval ago; a fresher refresh is ignored
// and served from the cache like a normal poll, so the endpoint cannot be
// used to hammer the GitHub API (and block every other caller on the
// single-flight lock) by repeated refreshes.
func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	refresh := r.URL.Query().Get("refresh") == "1"
	// A ?refresh=1 younger than updateCheckRefreshMinInterval since the last
	// fetch attempt is ignored and served from the cache like a normal poll:
	// honored, it would force a fetchRelease on every click — while
	// updateCheckMu is held (blocking every other caller up to the 10s client
	// timeout) and straight into GitHub's 60 req/hour unauthenticated limit.
	// The throttle keys on the last ATTEMPT (not the last success), so a
	// failed attempt also counts and an outage can't be used to keep forcing
	// calls.
	if refresh && time.Since(updateCheckAttemptAt) < updateCheckRefreshMinInterval {
		refresh = false
	}

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

	updateCheckAttemptAt = time.Now()
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
		// The raw error can name upstream URLs, the resolver, or proxy
		// config — details belong in the log, not the response body
		// (review 2026-10-24; same contract as respondInternal).
		log.Printf("update check: %v", err)
		respondWithError(w, http.StatusServiceUnavailable, "update check failed (upstream unreachable); try again later")
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
