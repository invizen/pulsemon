package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A Docker install only ever gets the "run docker compose" hint: nothing is
// fetched or swapped, so it is returned whether or not auth is enabled.
func TestFix_UpdateContainerHintWorksWithAuthOff(t *testing.T) {
	d := newTestDB(t)
	srv := NewServer(d, NewProbeWorker(d)) // no users: auth disabled
	hits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer ts.Close()
	origBase, origC := releaseBase, isContainerInstall
	releaseBase, isContainerInstall = ts.URL, func() bool { return true }
	defer func() { releaseBase, isContainerInstall = origBase, origC }()

	rr := httptest.NewRecorder()
	srv.handleUpdate(rr, httptest.NewRequest(http.MethodPost, "/api/update", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"status":"container"`) || !strings.Contains(rr.Body.String(), "docker compose") {
		t.Fatalf("container install, auth off => %d %s, want 200 container hint", rr.Code, rr.Body.String())
	}
	if hits != 0 {
		t.Errorf("container hint made %d network call(s), want 0", hits)
	}
}
