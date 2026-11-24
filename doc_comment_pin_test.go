package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestDocCommentsAttachedToDeclarations pins the 2026-11-24 external review
// finding #5: a blank line between a comment and its declaration makes the
// Go parser drop the association (Decl.Doc == nil), so go doc and gopls
// hover silently ignore the comment. Leftovers from the api.go four-way file
// split left ~50 detached docs (some on the WRONG symbol, e.g. the
// webhookMasked text above normalizeProbeType).
//
// The test walks every non-test .go file and fails if a comment group is
// separated from the next top-level declaration (or any code) by one or more
// blank lines. Exempt — intentional, not doc comments:
//   - //go:build / // +build tags (the blank line after a build tag is REQUIRED)
//   - all-dash section dividers (// ----------) — labels, not docs
//   - trailing comments on a code line (the group's line contains code)
//
// A positive control asserts the scanner still SEES attached docs, so a
// broken scanner cannot pass vacuously.
//
// History: docs/DECISIONS.md → detached-doc-comments
func TestDocCommentsAttachedToDeclarations(t *testing.T) {
	var violations []string
	attachedDocs := 0

	filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		violations, attachedDocs = scanFile(t, path, violations, attachedDocs)
		return nil
	})

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Errorf("%d detached doc comment(s) — a blank line separates the comment from its declaration, so go doc / gopls ignore it:\n  %s",
			len(violations), strings.Join(violations, "\n  "))
	}
	if attachedDocs < 40 {
		t.Errorf("positive control: only %d attached doc comments found — the scanner is not seeing what it should (want ≥40)", attachedDocs)
	}
}

var (
	buildTagRe = regexp.MustCompile(`^//\s*(go:build|\+build)\b`)
	// dashRuleRe: a line that is (or is framed by) a horizontal dash rule —
	// "// ----", "// ---------- label ----------", or a bare dash line.
	dashRuleRe = regexp.MustCompile(`^//\s*-{4,}.*-{4,}\s*$`)
)

func scanFile(t *testing.T, path string, violations []string, attached int) ([]string, int) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("%s: parse: %v", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: read: %v", path, err)
	}
	lines := strings.Split(string(data), "\n")

	// Top-level declaration start lines (1-based).
	declLines := map[int]bool{}
	for _, d := range f.Decls {
		switch v := d.(type) {
		case *ast.FuncDecl:
			declLines[fset.Position(v.Type.Pos()).Line] = true
		case *ast.GenDecl:
			declLines[fset.Position(v.Pos()).Line] = true
		}
	}
	// FuncDecl body line ranges — function-local comments are not doc comments.
	type span struct{ lo, hi int }
	var bodies []span
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
			bodies = append(bodies, span{fset.Position(fd.Body.Lbrace).Line, fset.Position(fd.Body.Rbrace).Line})
		}
	}
	inBody := func(l int) bool {
		for _, b := range bodies {
			if l >= b.lo && l <= b.hi {
				return true
			}
		}
		return false
	}

	for _, cg := range f.Comments {
		startLine, endLine := fset.Position(cg.Pos()).Line, fset.Position(cg.End()).Line
		if inBody(startLine) || inBody(endLine) {
			continue
		}
		// Trailing comment on a code line: code before the // on the group's line.
		if codeBeforeComment(lines[startLine-1]) {
			continue
		}
		if endLine >= len(lines) {
			continue
		}
		// Line immediately after the group (1-based endLine+1 -> 0-based endLine).
		if strings.TrimSpace(lines[endLine]) != "" {
			continue // no blank line -> attached
		}
		// First non-blank line after the gap (0-based j; 1-based line = j+1).
		j := endLine
		for j < len(lines) && strings.TrimSpace(lines[j]) == "" {
			j++
		}
		if j >= len(lines) {
			continue
		}
		next := lines[j]
		trimmed := strings.TrimSpace(next)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			continue // comment stack; the group nearest the decl is what matters
		}
		group := commentLines(cg)
		if exempt(group) {
			continue
		}
		what := "code"
		if declLines[j+1] {
			what = "declaration"
		}
		first := strings.TrimSpace(strings.Join(group, " "))
		if len(first) > 70 {
			first = first[:70] + "…"
		}
		violations = append(violations,
			first+" @ "+path+":"+strconv.Itoa(startLine)+" (blank line before "+what+" @"+path+":"+strconv.Itoa(j+1)+")")
	}

	// Positive control: count comment groups with NO blank line after them
	// (i.e. attached to whatever follows) at top level.
	for _, cg := range f.Comments {
		startLine, endLine := fset.Position(cg.Pos()).Line, fset.Position(cg.End()).Line
		if inBody(startLine) || inBody(endLine) || endLine >= len(lines) {
			continue
		}
		if codeBeforeComment(lines[startLine-1]) {
			continue
		}
		if strings.TrimSpace(lines[endLine]) != "" {
			attached++
		}
	}
	return violations, attached
}

func commentLines(cg *ast.CommentGroup) []string {
	var out []string
	for _, c := range cg.List {
		out = append(out, strings.TrimSpace(c.Text))
	}
	return out
}

func exempt(group []string) bool {
	if buildTagRe.MatchString(group[0]) {
		return true
	}
	// Section divider: a single dash rule, a labeled dash rule, or a label
	// block framed by dash rules. Any other group is a real doc candidate.
	return dashRuleRe.MatchString(group[0]) && dashRuleRe.MatchString(group[len(group)-1])
}

func codeBeforeComment(line string) bool {
	i := strings.Index(line, "//")
	if i < 0 {
		return false
	}
	return strings.TrimSpace(line[:i]) != ""
}
