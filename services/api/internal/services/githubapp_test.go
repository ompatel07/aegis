package services

import (
	"strings"
	"testing"

	"github.com/aegis-platform/api/internal/models"
)

func ip(i int) *int          { return &i }
func fp2(f float64) *float64  { return &f }
func sp2(s string) *string    { return &s }

func TestGhConclusionMapping(t *testing.T) {
	cases := []struct {
		passed, hasPolicy bool
		status, want      string
	}{
		{true, true, "completed", "success"},
		{false, true, "completed", "failure"},
		{true, false, "completed", "neutral"}, // no policy → never silently block
		{true, true, "failed", "failure"},
	}
	for _, c := range cases {
		if got := ghConclusion(c.passed, c.hasPolicy, c.status); got != c.want {
			t.Fatalf("ghConclusion(%v,%v,%q)=%q want %q", c.passed, c.hasPolicy, c.status, got, c.want)
		}
	}
}

func TestBuildCommentContents(t *testing.T) {
	scan := &models.Scan{OverallGrade: sp2("D"), SecurityScore: ip(20), QualityScore: ip(60),
		DeploymentScore: ip(100)}
	findings := []models.Finding{
		{Severity: "critical", Title: "SQLi", TitleHuman: sp2("SQL injection"), FilePath: "app/x.js", LineStart: ip(10), IsNew: true},
		{Severity: "low", Title: "nit", FilePath: "y.js"},
	}
	md := buildComment("http://localhost/projects/p/scans/s", scan, findings, false, true)

	for _, want := range []string{
		"<!-- aegis-report -->",              // stable marker for the single comment
		"quality gate failed",                // policy-aware header
		"| Critical | High | Medium | Low |", // severity table
		"SQL injection",                       // top finding uses title_human
		"app/x.js:10",                         // location
		"🆕",                                    // new-finding marker
		// The AI-generated-code section and its density callout were removed with the
		// Phase 2C AI fields; nothing on models.Scan/Finding renders them any more.
		"View the full report",                // dashboard link
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("comment missing %q:\n%s", want, md)
		}
	}
}

func TestBuildAnnotationsChangedLinesOnly(t *testing.T) {
	findings := []models.Finding{
		{Severity: "high", Title: "on changed line", FilePath: "a.js", LineStart: ip(5), Impact: sp2("bad")},
		{Severity: "high", Title: "on untouched line", FilePath: "a.js", LineStart: ip(99)},
		{Severity: "high", Title: "untouched file", FilePath: "b.js", LineStart: ip(5)},
		{Severity: "high", Title: "suppressed", FilePath: "a.js", LineStart: ip(5), IsSuppressed: true},
	}
	changed := map[string]map[int]bool{"a.js": {5: true}}

	ann := buildAnnotations(findings, changed)
	if len(ann) != 1 {
		t.Fatalf("expected exactly 1 annotation (only the changed, non-suppressed line), got %d: %+v", len(ann), ann)
	}
	if ann[0].Path != "a.js" || ann[0].StartLine != 5 || ann[0].AnnotationLevel != "failure" {
		t.Fatalf("wrong annotation: %+v", ann[0])
	}
}
