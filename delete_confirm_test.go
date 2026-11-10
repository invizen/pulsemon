package main

import (
	"strings"
	"testing"
)

// Regression guard for the v1.1.3 delete-confirm fix (source-level; the repo
// has no JS test harness).
//
// The outside-click disarm listener must NOT use e.target.closest('[data-del]'):
// clicking the trash <i> icon runs the dispatcher first, and armDeleteConfirm
// replaces the button innerHTML, detaching the clicked <i>. e.target is that
// detached node, so closest() returns null and the very click that armed the
// confirm disarms it again — CONFIRM? is never painted. composedPath() is
// snapshotted at dispatch time and still contains the armed button.
func TestDeleteConfirmDisarmUsesComposedPath(t *testing.T) {
	data, err := content.ReadFile("web/app.js")
	if err != nil {
		t.Fatalf("read embedded web/app.js: %v", err)
	}
	// Strip // line comments so the guard matches code, not prose (the fix's
	// own explanatory comment quotes the old pattern).
	var code strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		code.WriteString(line)
		code.WriteByte('\n')
	}
	src := code.String()
	if strings.Contains(src, `closest('[data-del]')`) {
		t.Fatal("outside-click disarm listener uses closest('[data-del]') — v1.1.3 regression: armDeleteConfirm detaches the clicked <i>, so closest() on e.target is null and the arming click disarms itself; use e.composedPath()")
	}
	if !strings.Contains(src, "composedPath()") {
		t.Fatal("expected composedPath() in web/app.js (delete-confirm disarm listener)")
	}
}
