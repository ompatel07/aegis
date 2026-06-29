package scoring

import (
	"testing"

	"github.com/aegis-platform/orchestrator/internal/types"
)

func TestSecurityScorePenalties(t *testing.T) {
	findings := []types.Finding{
		{Pillar: types.PillarSecurity, Severity: types.SeverityCritical}, // -25
		{Pillar: types.PillarSecurity, Severity: types.SeverityHigh},     // -10
		{Pillar: types.PillarSecurity, Severity: types.SeverityMedium},   // -3
		{Pillar: types.PillarSecurity, Severity: types.SeverityLow},      // -1
		{Pillar: types.PillarQuality, Severity: types.SeverityCritical},  // ignored (not security)
	}
	if got := SecurityScore(findings); got != 61 {
		t.Fatalf("SecurityScore = %d, want 61", got)
	}
}

func TestSecurityScoreFloorsAtZero(t *testing.T) {
	findings := make([]types.Finding, 5)
	for i := range findings {
		findings[i] = types.Finding{Pillar: types.PillarSecurity, Severity: types.SeverityCritical}
	}
	if got := SecurityScore(findings); got != 0 {
		t.Fatalf("SecurityScore = %d, want 0 (floored)", got)
	}
}

func TestQualityScoreWeightedAverage(t *testing.T) {
	m := &types.QualityMetrics{
		ComplexityScore:      100, // *0.30
		DuplicationScore:     100, // *0.20
		MaintainabilityScore: 100, // *0.25
		TestCoverageScore:    0,   // *0.15
		DocumentationScore:   0,   // *0.10
	}
	// 30 + 20 + 25 + 0 + 0 = 75
	if got := QualityScore(m); got != 75 {
		t.Fatalf("QualityScore = %d, want 75", got)
	}
}

func TestQualityScoreNilMetricsNeutral(t *testing.T) {
	if got := QualityScore(nil); got != 100 {
		t.Fatalf("QualityScore(nil) = %d, want 100", got)
	}
}

func TestDeploymentScoreFromSteps(t *testing.T) {
	report := &types.DeploymentReport{
		Steps: []types.DeploymentStep{
			{Name: "dependency-resolution", Success: true}, // weight 25
			{Name: "build", Success: false},                // weight 60
			{Name: "smoke", Success: true},                 // weight 15
		},
	}
	// succeeded 40 / attempted 100 = 40
	if got := DeploymentScore(report); got != 40 {
		t.Fatalf("DeploymentScore = %d, want 40", got)
	}
}

func TestDeploymentScoreNothingAttempted(t *testing.T) {
	if got := DeploymentScore(&types.DeploymentReport{}); got != 100 {
		t.Fatalf("DeploymentScore(empty) = %d, want 100", got)
	}
}

func TestOverallScoreAndGrade(t *testing.T) {
	// 80*0.40 + 90*0.35 + 100*0.25 = 32 + 31.5 + 25 = 88.5 → 89 (round), grade B.
	score, grade := OverallScore(80, 90, 100)
	if score != 89 {
		t.Fatalf("OverallScore = %d, want 89", score)
	}
	if grade != "B" {
		t.Fatalf("Grade = %s, want B", grade)
	}
}

func TestGradeThresholds(t *testing.T) {
	cases := map[int]string{95: "A", 90: "A", 80: "B", 75: "B", 60: "C", 40: "D", 39: "F", 0: "F"}
	for score, want := range cases {
		if got := Grade(score); got != want {
			t.Errorf("Grade(%d) = %s, want %s", score, got, want)
		}
	}
}
