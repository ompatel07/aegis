package services

import (
	"strings"
	"testing"

	"github.com/aegis-platform/api/internal/models"
)

// A pillar that was never measured is a FACT, not a zero.
//
// F1 found the executive report printing "deployment 0" for a pillar that only runs in
// CI mode — the same fabricated-value defect that was removed from the scorer (ab8b4ef),
// the API, the DB and the UI, still alive in the artifact an executive actually reads.
// These tests pin every customer-facing renderer.

func ip2(v int) *int       { return &v }
func sp3(s string) *string { return &s }

// forbidden are renderings a NULL must never take in customer-facing prose.
var forbiddenForNull = []string{
	"deployment 0", "security 0", "quality 0",
	"grade **—**", "grade of —", "grade —",
}

func TestExecutiveSummaryNeverFabricatesAnUnmeasuredPillar(t *testing.T) {
	// The real F1 shape: quality measured, security not measured (trivy degraded),
	// deployment never runs outside CI mode.
	scan := &models.Scan{
		QualityScore: ip2(84),
		OverallGrade: sp3("B"),
		// SecurityScore, DeploymentScore deliberately nil.
	}
	got := templateSummary("F1-spring-petclinic", scan, nil)

	if strings.Contains(got, "deployment") {
		t.Errorf("deployment was never measured, so it must be omitted entirely "+
			"(two-pillar product, b845240), got:\n%s", got)
	}
	if !strings.Contains(got, "security "+NotMeasured) {
		t.Errorf("an unmeasured security pillar must say %q, got:\n%s", NotMeasured, got)
	}
	if !strings.Contains(got, "quality 84") {
		t.Errorf("a measured pillar must still show its number, got:\n%s", got)
	}
	for _, bad := range forbiddenForNull {
		if strings.Contains(got, bad) {
			t.Errorf("summary contains fabricated value %q:\n%s", bad, got)
		}
	}
}

func TestExecutiveSummaryKeepsRealZeroes(t *testing.T) {
	// A measured 0 is real and must survive — the NULL-vs-0 distinction the C1 work
	// introduced. dvpwa genuinely scores security 0.
	scan := &models.Scan{
		SecurityScore: ip2(0), QualityScore: ip2(65), OverallGrade: sp3("F"),
	}
	got := templateSummary("F1-dvpwa", scan, nil)
	if !strings.Contains(got, "security 0") {
		t.Errorf("a measured zero must be shown as 0, not %q:\n%s", NotMeasured, got)
	}
	if strings.Contains(got, NotMeasured) {
		t.Errorf("nothing was unmeasured here; %q must not appear:\n%s", NotMeasured, got)
	}
}

func TestGradeAndScoreTextAreHonest(t *testing.T) {
	if got := scoreText(nil); got != NotMeasured {
		t.Errorf("nil score must render %q, got %q", NotMeasured, got)
	}
	if got := scoreText(ip2(0)); got != "0" {
		t.Errorf("a real 0 must render \"0\", got %q", got)
	}
	if got := gradeText(nil); got != NotMeasured {
		t.Errorf("nil grade must render %q, got %q", NotMeasured, got)
	}
	if got := gradeText(sp3("")); got != NotMeasured {
		t.Errorf("empty grade must render %q (never a bare dash), got %q", NotMeasured, got)
	}
	if got := gradeText(sp3("B")); got != "B" {
		t.Errorf("a real grade must survive, got %q", got)
	}
}

func TestScoreDeltaRefusesToCompareAgainstAnUnmeasuredScan(t *testing.T) {
	// Subtracting through nil-as-zero invented a movement that never happened: an
	// unmeasured previous scan read as a full-score improvement.
	if _, ok := scoreDelta(ip2(84), nil); ok {
		t.Error("a delta against an unmeasured previous score must not be reported")
	}
	if _, ok := scoreDelta(nil, ip2(84)); ok {
		t.Error("a delta from an unmeasured current score must not be reported")
	}
	d, ok := scoreDelta(ip2(90), ip2(84))
	if !ok || d != 6 {
		t.Errorf("a real delta must be reported, got %d ok=%v", d, ok)
	}
}

func TestPRCommentNeverFabricatesAnUnmeasuredPillar(t *testing.T) {
	// The PR comment is the most-read artifact of all — it renders on every pull request.
	scan := &models.Scan{QualityScore: ip2(84), OverallGrade: sp3("B")}
	got := buildCheckSummary(scan, nil)
	if strings.Contains(got, "deployment") {
		t.Errorf("unmeasured deployment must be omitted from the PR check summary:\n%s", got)
	}
	if !strings.Contains(got, "security "+NotMeasured) {
		t.Errorf("unmeasured security must say %q in the PR check summary:\n%s", NotMeasured, got)
	}
	for _, bad := range forbiddenForNull {
		if strings.Contains(got, bad) {
			t.Errorf("PR check summary contains fabricated value %q:\n%s", bad, got)
		}
	}
}

func TestPolicyReasonDoesNotClaimAScoreThatWasNotMeasured(t *testing.T) {
	// An unmeasured pillar must FAIL the gate (fail closed — we cannot certify what we
	// did not measure) but the reason must not assert a score of 0.
	cfg := models.PolicyConfig{MinSecurityScore: ip2(80)}
	scan := &models.Scan{QualityScore: ip2(84)} // security nil
	passed, checks := evaluatePolicy(cfg, scan, nil)
	if passed {
		t.Error("an unmeasured security pillar must not pass a min_security_score gate")
	}
	c := checkByRule(checks, "min_security_score")
	if c == nil {
		t.Fatal("min_security_score check missing")
	}
	if strings.Contains(c.Detail, "score 0") {
		t.Errorf("policy reason claims a score of 0 for an unmeasured pillar: %q", c.Detail)
	}
	if !strings.Contains(c.Detail, NotMeasured) {
		t.Errorf("policy reason must say %q, got %q", NotMeasured, c.Detail)
	}
}
