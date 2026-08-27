package scoring

import (
	"testing"

	"github.com/aegis-platform/orchestrator/internal/types"
)

func ptr(v int) *int { return &v }

// Security score is now a severity-weighted DENSITY per KLOC (C1).
func TestSecurityScoreDensity(t *testing.T) {
	findings := []types.Finding{
		{Pillar: types.PillarSecurity, Severity: types.SeverityCritical}, // 25
		{Pillar: types.PillarSecurity, Severity: types.SeverityHigh},     // 10
		{Pillar: types.PillarSecurity, Severity: types.SeverityMedium},   // 3
		{Pillar: types.PillarSecurity, Severity: types.SeverityLow},      // 1
		{Pillar: types.PillarQuality, Severity: types.SeverityCritical},  // ignored
	}
	// weighted 39 over 10 KLOC = density 3.9; 100 - 5.5*3.9 = 78.55 -> 79
	if got := SecurityScore(findings, 10000); got == nil || *got != 79 {
		t.Fatalf("SecurityScore(density) = %v, want 79", got)
	}
}

// 1 critical in 413k LOC must score far better than 1 critical in 1k LOC — the
// whole reason for density (a constant E/0 carried no such information).
func TestSecurityScoreDensityDistinguishesSize(t *testing.T) {
	f := []types.Finding{{Pillar: types.PillarSecurity, Severity: types.SeverityCritical}}
	small := SecurityScore(f, 10000)  // density 2.5 -> 86
	large := SecurityScore(f, 500000) // density 0.05 -> ~100
	if small == nil || large == nil || !(*large > *small) {
		t.Fatalf("density must reward size: small=%v large=%v", small, large)
	}
}

// LOC unknown (quality engine failed) -> NOT MEASURED (nil), never the count-based
// formula this pass declared broken.
func TestSecurityScoreUnknownLOCNotMeasured(t *testing.T) {
	findings := []types.Finding{
		{Pillar: types.PillarSecurity, Severity: types.SeverityCritical},
		{Pillar: types.PillarSecurity, Severity: types.SeverityHigh},
	}
	if got := SecurityScore(findings, 0); got != nil {
		t.Fatalf("SecurityScore(no LOC) = %v, want nil (not measured)", got)
	}
}

func TestSecurityScoreFloorsAtZero(t *testing.T) {
	findings := make([]types.Finding, 5)
	for i := range findings {
		findings[i] = types.Finding{Pillar: types.PillarSecurity, Severity: types.SeverityCritical}
	}
	if got := SecurityScore(findings, 1000); got == nil || *got != 0 { // 125 density -> clamp 0
		t.Fatalf("SecurityScore = %v, want 0 (floored)", got)
	}
}

func TestSecurityScoreReachabilityStillWeights(t *testing.T) {
	mk := func(reachable, direct any) types.Finding {
		md := map[string]any{}
		if reachable != nil {
			md["reachable"] = reachable
		}
		if direct != nil {
			md["is_direct"] = direct
		}
		return types.Finding{Pillar: types.PillarSecurity, Severity: types.SeverityCritical, Metadata: md}
	}
	// single critical over 10 KLOC; penalty * reachability-weight / 10 * 5.5
	cases := []struct {
		name string
		f    types.Finding
		want int // round(100 - 5.5*(25*w/10))
	}{
		{"unreachable halves", mk(false, true), 93},   // 12.5/10*5.5=6.875 -> 93
		{"reachable direct +20%", mk(true, true), 84}, // 30/10*5.5=16.5 -> 83.5 -> 84
		{"reachable transitive", mk(true, false), 86}, // 25/10*5.5=13.75 -> 86
		{"undetermined full", mk(nil, nil), 86},
	}
	for _, c := range cases {
		if got := SecurityScore([]types.Finding{c.f}, 10000); got == nil || *got != c.want {
			t.Errorf("%s: got %v, want %d", c.name, got, c.want)
		}
	}
}

// Quality: complexity 0.30 + maintainability 0.55 + coverage 0.15 (duplication +
// documentation dropped from the composite).
func TestQualityScoreWeights(t *testing.T) {
	cov := 40.0
	m := &types.QualityMetrics{ComplexityScore: 90, MaintainabilityScore: 50, TestCoverageScore: &cov}
	// 90*0.30 + 50*0.55 + 40*0.15 = 27 + 27.5 + 6 = 60.5 -> 61
	if got := QualityScore(m); got == nil || *got != 61 {
		t.Fatalf("QualityScore = %v, want 61", got)
	}
}

func TestQualityScoreNilCoverageRenormalizes(t *testing.T) {
	m := &types.QualityMetrics{ComplexityScore: 90, MaintainabilityScore: 50, TestCoverageScore: nil}
	// (90*0.30 + 50*0.55) / 0.85 = 54.5/0.85 = 64.1 -> 64
	if got := QualityScore(m); got == nil || *got != 64 {
		t.Fatalf("QualityScore(nil coverage) = %v, want 64", got)
	}
}

// nil metrics = NOT MEASURED -> nil, never a fabricated 100.
func TestQualityScoreNilMetricsNotMeasured(t *testing.T) {
	if got := QualityScore(nil); got != nil {
		t.Fatalf("QualityScore(nil) = %v, want nil (not measured)", got)
	}
}

func TestDeploymentScoreFromSteps(t *testing.T) {
	report := &types.DeploymentReport{Steps: []types.DeploymentStep{
		{Name: "dependency-resolution", Success: true}, {Name: "build", Success: false},
		{Name: "smoke", Success: true},
	}}
	if got := DeploymentScore(report); got == nil || *got != 40 { // 40/100
		t.Fatalf("DeploymentScore = %v, want 40", got)
	}
}

// Nothing attempted / nil report = NOT MEASURED -> nil, never a fabricated 100.
func TestDeploymentScoreNotMeasured(t *testing.T) {
	if got := DeploymentScore(&types.DeploymentReport{}); got != nil {
		t.Fatalf("DeploymentScore(empty) = %v, want nil (not measured)", got)
	}
	if got := DeploymentScore(nil); got != nil {
		t.Fatalf("DeploymentScore(nil) = %v, want nil (not measured)", got)
	}
}

func TestOverallScoreAllMeasured(t *testing.T) {
	score, grade := OverallScore(ptr(80), ptr(90), ptr(100)) // 32+31.5+25=88.5 -> 89
	if score == nil || *score != 89 || grade != "B" {
		t.Fatalf("OverallScore = %v/%s, want 89/B", score, grade)
	}
}

// Deployment not measured -> excluded + renormalize over security+quality.
func TestOverallScoreDeploymentNotMeasuredRenormalizes(t *testing.T) {
	score, _ := OverallScore(ptr(80), ptr(90), nil) // (32+31.5)/0.75 = 84.67 -> 85
	if score == nil || *score != 85 {
		t.Fatalf("OverallScore(no deploy) = %v, want 85 (renormalized, not fabricated)", score)
	}
}

func TestOverallScoreOnlySecurityMeasured(t *testing.T) {
	score, _ := OverallScore(ptr(80), nil, nil) // 32/0.40 = 80
	if score == nil || *score != 80 {
		t.Fatalf("OverallScore(security only) = %v, want 80", score)
	}
}

// Nothing measured (e.g. LOC unknown so security nil, quality+deployment nil) ->
// nil / "N/A", never a fabricated number.
func TestOverallScoreNothingMeasured(t *testing.T) {
	score, grade := OverallScore(nil, nil, nil)
	if score != nil || grade != "N/A" {
		t.Fatalf("OverallScore(all nil) = %v/%s, want nil/N/A", score, grade)
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
