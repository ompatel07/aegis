package pipeline

import (
	"testing"

	"github.com/aegis-platform/orchestrator/internal/types"
)

func er(engine, status string) *types.EngineResult {
	return &types.EngineResult{Engine: engine, Status: status}
}

// A failed engine and a degraded engine both land in EnginesDegraded — a partial
// scan is never read as clean.
func TestAggregateSurfacesDegradation(t *testing.T) {
	trivyFail := er("trivy", "failed")
	trivyFail.Error = "trivy could not resolve deps"
	semDeg := er("semgrep", "completed")
	semDeg.Degraded = true
	semDeg.DegradedReason = "custom rule pack failed to load"
	semDeg.CoverageLost = "custom taint + bug pack"

	agg := Aggregate([]*types.EngineResult{semDeg, trivyFail, er("gitleaks", "completed")})
	if len(agg.EnginesDegraded) != 2 {
		t.Fatalf("EnginesDegraded = %d, want 2", len(agg.EnginesDegraded))
	}
	var sawFail, sawDeg bool
	for _, d := range agg.EnginesDegraded {
		if d.Engine == "trivy" && d.Reason == "trivy could not resolve deps" {
			sawFail = true
		}
		if d.Engine == "semgrep" && d.CoverageLost == "custom taint + bug pack" {
			sawDeg = true
		}
	}
	if !sawFail || !sawDeg {
		t.Fatalf("degradation not surfaced: %+v", agg.EnginesDegraded)
	}
}

// If EVERY security engine failed, the pillar is NOT MEASURED — not a clean 100/A.
// This is the all-engines-failed P0.
func TestAggregateAllSecurityEnginesFailed_NotMeasured(t *testing.T) {
	agg := Aggregate([]*types.EngineResult{
		er("semgrep", "failed"), er("trivy", "failed"), er("gitleaks", "failed"),
	})
	if agg.SecurityScore != nil {
		t.Errorf("SecurityScore = %v, want nil (not measured)", *agg.SecurityScore)
	}
	if agg.SecurityRating != nil {
		t.Errorf("SecurityRating = %v, want nil (not measured, never A)", *agg.SecurityRating)
	}
	// reliability sources (semgrep + quality) also both absent -> not measured
	if agg.ReliabilityRating != nil {
		t.Errorf("ReliabilityRating = %v, want nil (not measured)", *agg.ReliabilityRating)
	}
	// nothing measured at all -> overall nil / N/A, never a fabricated number
	if agg.OverallScore != nil || agg.OverallGrade != "N/A" {
		t.Errorf("Overall = %v/%s, want nil/N/A", agg.OverallScore, agg.OverallGrade)
	}
}

// A pillar with at least one completed engine IS measured (partial coverage still
// scores what ran).
func TestAggregatePartialSecurityMeasured(t *testing.T) {
	agg := Aggregate([]*types.EngineResult{
		er("semgrep", "failed"), er("trivy", "completed"), er("gitleaks", "failed"),
	})
	if agg.SecurityRating == nil {
		t.Fatalf("SecurityRating = nil, want measured (trivy completed)")
	}
	if len(agg.EnginesDegraded) != 2 { // semgrep + gitleaks failed
		t.Fatalf("EnginesDegraded = %d, want 2", len(agg.EnginesDegraded))
	}
}
