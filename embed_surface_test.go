package main

import "testing"

// TestEmbedSurfaceExcludesTests is the repro for the 2026-11-20 finding:
// //go:embed web/* also embedded web/test/*.mjs, so the frontend test
// files were served at /test/... — the app's test harness (assertions,
// DOM shims) shipped in the release binary and on every dashboard. The
// embed is now an explicit file list; this pin fails if web/test ever
// re-enters the embed surface (or a real asset leaves it).
func TestEmbedSurfaceExcludesTests(t *testing.T) {
	// The test files must NOT be readable from the embed FS.
	for _, p := range []string{"web/test/frontend.test.mjs", "web/test/poll_layout.test.mjs"} {
		if _, err := content.ReadFile(p); err == nil {
			t.Errorf("%s is embedded — the frontend tests ship in the release", p)
		}
	}
	// The real app surface must still be intact (an over-eager trim that
	// drops an asset breaks the dashboard silently).
	for _, p := range []string{
		"web/index.html", "web/app.js", "web/styles.css", "web/theme.js",
		"web/favicon.svg", "web/favicon-16x16.png", "web/favicon-32x32.png",
		"web/favicon-48x48.png", "web/apple-touch-icon.png",
		"web/vendor/fonts/fonts.css", "web/vendor/phosphor/regular.css",
	} {
		if _, err := content.ReadFile(p); err != nil {
			t.Errorf("embedded app asset missing: %s: %v", p, err)
		}
	}
	// And no "test" entry may sit at the web/ root of the FS (catches a
	// new subdirectory even if the file list above is stale).
	entries, err := content.ReadDir("web")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == "test" {
			t.Fatal(`the "web/test" directory is in the embed surface`)
		}
	}
}
