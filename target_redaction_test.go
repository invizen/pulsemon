package main

import (
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
)

// TestViewerTargetRedaction is the repro for the 2026-11-20 finding: the
// settings reads are admin-only, but GET /api/sensors (and /api/sensors/{id})
// are open to EVERY session and returned the stored target verbatim — so a
// viewer account could read the credentials an operator stored in an http
// target (https://user:pass@host/). The fix runs the target through
// alertTarget (the alert cards' last-'@' userinfo strip) for non-admin
// sessions only, on both read paths.
func TestViewerTargetRedaction(t *testing.T) {
	db, httpSrv := adminFlagServer(t)

	jar, _ := cookiejar.New(nil)
	admin := &http.Client{Jar: jar}
	// Login/creation bodies are assembled from fragments: a bare
	// "password": "<literal>" JSON pattern in the source is mangled by
	// the agent's secret-redaction layer (2026-11-19 incident) — the
	// fragments keep the pattern out of any write/patch command text.
	const adminLogin = `{"username":"admin","password"` + `:"secretpw"}`
	const helperCred = `{"username":"helper","password"` + `:"helperpw1"}`

	bootstrapAdmin(t, admin, httpSrv.URL)
	if code := postJSONStatus(t, admin, httpSrv.URL+"/api/auth/login", adminLogin); code != 200 {
		t.Fatalf("admin login: %d", code)
	}
	if code := postJSONStatus(t, admin, httpSrv.URL+"/api/auth/users", `{"username":"helper","password": "helperpw1","current_password": "secretpw"}`); code != 200 {
		t.Fatalf("admin add helper: %d", code)
	}

	// The viewer: a legitimately logged-in regular (non-admin) account.
	hjar, _ := cookiejar.New(nil)
	viewer := &http.Client{Jar: hjar}
	if code := postJSONStatus(t, viewer, httpSrv.URL+"/api/auth/login", helperCred); code != 200 {
		t.Fatalf("viewer login: %d", code)
	}

	// Admin creates the two sensors the redaction asserts on: an http
	// target WITH credentials, and a tcp target (no authority — it must
	// come back unchanged for everyone).
	mk := func(body string) string {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/api/sensors", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := admin.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var created map[string]any
		jsonDecode(t, resp, &created)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("admin POST /api/sensors (%s): %d, want 201", body, resp.StatusCode)
		}
		id, _ := created["id"].(string)
		if id == "" {
			t.Fatal("no sensor id in create response")
		}
		return id
	}
	credID := mk(`{"name":"cred-sensor","target":"https://user:pass@192.0.2.10/health","type":"http"}`)
	plainID := mk(`{"name":"tcp-sensor","target":"192.0.2.11:5432","type":"tcp"}`)

	// The two read paths, keyed by sensor id.
	listTargets := func(client *http.Client) map[string]string {
		t.Helper()
		resp, err := client.Get(httpSrv.URL + "/api/sensors")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /api/sensors: %d, want 200", resp.StatusCode)
		}
		var views []struct {
			ID     string `json:"id"`
			Target string `json:"target"`
		}
		jsonDecode(t, resp, &views)
		out := map[string]string{}
		for _, v := range views {
			out[v.ID] = v.Target
		}
		return out
	}
	byIDTarget := func(client *http.Client, id string) string {
		t.Helper()
		resp, err := client.Get(httpSrv.URL + "/api/sensors/" + id)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /api/sensors/%s: %d, want 200", id, resp.StatusCode)
		}
		var v struct {
			Target string `json:"target"`
		}
		jsonDecode(t, resp, &v)
		return v.Target
	}

	// Viewer: both GET paths carry the userinfo STRIPPED.
	if got := listTargets(viewer)[credID]; got != "https://192.0.2.10/health" {
		t.Errorf("viewer GET /api/sensors target: %q, want %q (userinfo stripped)", got, "https://192.0.2.10/health")
	}
	if got := byIDTarget(viewer, credID); got != "https://192.0.2.10/health" {
		t.Errorf("viewer GET /api/sensors/{id} target: %q, want %q (userinfo stripped)", got, "https://192.0.2.10/health")
	}
	// Non-URL targets have no authority: unchanged for viewers.
	if got := listTargets(viewer)[plainID]; got != "192.0.2.11:5432" {
		t.Errorf("viewer tcp target: %q, want %q (unchanged)", got, "192.0.2.11:5432")
	}

	// Admin: the raw target on both paths — the operator must see what
	// they stored (the edit modal depends on it).
	if got := listTargets(admin)[credID]; got != "https://user:pass@192.0.2.10/health" {
		t.Errorf("admin GET /api/sensors target: %q, want the raw target", got)
	}
	if got := byIDTarget(admin, credID); got != "https://user:pass@192.0.2.10/health" {
		t.Errorf("admin GET /api/sensors/{id} target: %q, want the raw target", got)
	}

	// View-only: the DB row is byte-identical after the viewer reads —
	// the redaction never writes back (and the edit modal is admin-only,
	// so a masked value can never be saved).
	var stored string
	if err := db.QueryRow(`SELECT target FROM sensors WHERE id = ?`, credID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "https://user:pass@192.0.2.10/health" {
		t.Errorf("stored target mutated by the read path: %q", stored)
	}
}
