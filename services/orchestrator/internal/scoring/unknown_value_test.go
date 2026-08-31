package scoring

import (
	"testing"

	"github.com/aegis-platform/orchestrator/internal/types"
)

// TestUnknownValueContract enforces the B2 contract (Pass D1): every measurement,
// on its unknown path, returns NOT MEASURED (nil / "N/A") — never a fabricated
// number, a clean 100, or an A. Mirrors the table in docs/SCORING_CALIBRATION_C1.md.
// The pipeline-seam half of the contract (ratings nil when all pillar engines
// failed) lives in ../pipeline/aggregator_test.go.
func TestUnknownValueContract(t *testing.T) {
	// Security: LOC unknown -> nil (cannot normalize a density without a denominator).
	if got := SecurityScore(nil, 0); got != nil {
		t.Errorf("SecurityScore(_, LOC=0) = %d, want nil (not measured)", *got)
	}
	// Counter-case: LOC known + no findings IS measured (clean 100), not nil.
	if got := SecurityScore(nil, 1000); got == nil || *got != 100 {
		t.Errorf("SecurityScore(no findings, LOC=1000) = %v, want 100 (measured clean)", got)
	}

	// Quality: no metrics -> nil.
	if got := QualityScore(nil); got != nil {
		t.Errorf("QualityScore(nil) = %d, want nil (not measured)", *got)
	}
	// Counter-case: metrics present IS measured.
	m := &types.QualityMetrics{ComplexityScore: 80, MaintainabilityScore: 70}
	if got := QualityScore(m); got == nil {
		t.Error("QualityScore(metrics) = nil, want measured")
	}
	// Coverage unknown is dropped (renormalized), NOT counted as 0: a repo with no
	// coverage report must not score lower than the same repo scored on the pillars
	// that ran.
	withCov := &types.QualityMetrics{ComplexityScore: 80, MaintainabilityScore: 70}
	cov := 50.0
	withCov.TestCoverageScore = &cov
	noCov := &types.QualityMetrics{ComplexityScore: 80, MaintainabilityScore: 70}
	gotNoCov := QualityScore(noCov)
	if gotNoCov == nil {
		t.Fatal("QualityScore(no coverage) = nil, want measured on what ran")
	}
	// Unknown coverage must not drag the score below the complexity+maint blend:
	// round((80*0.30 + 70*0.55)/0.85) = 74. If coverage were counted as 0 it would
	// be round(62.5/1.0) = 63 — the fabrication this contract forbids.
	if *gotNoCov != 74 {
		t.Errorf("QualityScore(no coverage) = %d, want 74 (renormalized, coverage not counted as 0→63)", *gotNoCov)
	}

	// Overall: nothing measured -> nil score + "N/A" grade, never a number.
	if s, g := OverallScore(nil, nil, nil); s != nil || g != "N/A" {
		t.Errorf("OverallScore(nil,nil,nil) = %v/%q, want nil/\"N/A\"", s, g)
	}
	// Counter-case: one measured pillar -> measured overall (renormalized), not nil.
	sec := 60
	if s, g := OverallScore(&sec, nil, nil); s == nil || g == "N/A" {
		t.Errorf("OverallScore(security only) = %v/%q, want measured", s, g)
	}
}
