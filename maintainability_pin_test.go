package main

// Maintainability regression pins (external review finding #6, 2026-11-24):
// the comment diet + auth.go split + nits-test regrouping are one-time
// moves that are easy to undo by accretion. This test fails if:
//
//  1. any top-level function in the dieted files regresses to essay-
//     length comments (more comment lines than code lines, with >= 30
//     comment lines on a function with >= 20 code lines — small helpers
//     with a dense one-paragraph doc are the accepted style),
//  2. the auth.go file split is re-merged (auth_throttle.go /
//     auth_session.go / auth_handlers.go missing, or their anchor
//     symbols moved away, or auth.go ballooning back),
//  3. a nits_<date>_test.go file reappears (tests are grouped by feature,
//     not by incident batch).
//
// History: docs/DECISIONS.md → comment-history-relocation.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var dietedFiles = []string{
	"auth.go",
	"auth_throttle.go",
	"auth_session.go",
	"auth_handlers.go",
	"alerts.go",
	"api_sensors.go",
}

func commentLinesIn(fset *token.FileSet, groups []*ast.CommentGroup, start, end int) int {
	n := 0
	for _, g := range groups {
		sl := fset.Position(g.Pos()).Line
		el := fset.Position(g.End()).Line
		// count only the span inside the function
		if el < start || sl > end {
			continue
		}
		from, to := sl, el
		if from < start {
			from = start
		}
		if to > end {
			to = end
		}
		n += to - from + 1
	}
	return n
}

func TestDietedFilesStayBelowCommentRatioOne(t *testing.T) {
	fset := token.NewFileSet()
	for _, name := range dietedFiles {
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Doc == nil {
				continue
			}
			start := fset.Position(fd.Pos()).Line
			if fd.Doc != nil {
				start = fset.Position(fd.Doc.Pos()).Line // doc comments count too
			}
			end := fset.Position(fd.End()).Line
			total := end - start + 1
			cml := commentLinesIn(fset, f.Comments, start, end)
			if cml > total-cml && cml >= 30 && total-cml >= 20 {
				t.Errorf("%s: func %s has %d comment lines vs %d code lines (ratio > 1.0) — "+
					"the dieted style is invariant + one-clause why + History pointer; "+
					"move incident history to docs/DECISIONS.md", name, fd.Name.Name, cml, total-cml)
			}
		}
	}
}

func TestAuthSplitFilesStaySplit(t *testing.T) {
	anchors := map[string][]string{
		"auth.go":          {"type AuthState", "func NewAuthState"},
		"auth_throttle.go": {"func throttleKey", "func (a *AuthState) ClientIP", "func (a *AuthState) beginAttempt"},
		"auth_session.go":  {"func (a *AuthState) CreateSession", "func (a *AuthState) CookieRenewalDue"},
		"auth_handlers.go": {"func (s *Server) handleAuthLogin", "func (s *Server) requireAdmin"},
	}
	for name, syms := range anchors {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("%s: %v — the auth.go file split (finding #6) must not be re-merged", name, err)
		}
		for _, sym := range syms {
			if !strings.Contains(string(data), sym) {
				t.Errorf("%s: missing anchor %q — the auth.go file split (finding #6) must not be re-merged", name, sym)
			}
		}
	}
	// auth.go must not balloon back toward the pre-split 2503 lines.
	data, err := os.ReadFile("auth.go")
	if err != nil {
		t.Fatalf("auth.go: %v", err)
	}
	if lines := strings.Count(string(data), "\n"); lines > 1200 {
		t.Errorf("auth.go is %d lines (> 1200) — the pre-split file was 2503; keep throttle/session/handler code in its own files", lines)
	}
}

var nitsFileRe = regexp.MustCompile(`^nits_\d{8}_test\.go$`)

func TestNoDateNamedNitTestFiles(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if nitsFileRe.MatchString(e.Name()) {
			abs, _ := filepath.Abs(e.Name())
			t.Errorf("%s: tests are grouped by feature, not by incident batch (finding #6) — move these tests into the feature test files; %s", e.Name(), abs)
		}
	}
}
