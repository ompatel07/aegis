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

// A pillar fed by ANY failed/degraded engine is NOT confidently measured (P4b A).
// Partial coverage does not "score what ran" — a missing security engine drops
// findings and INFLATES the score, so the pillar is nil, not a plausible number.
func TestAggregatePartialSecurityNotConfident(t *testing.T) {
	agg := Aggregate([]*types.EngineResult{
		er("semgrep", "failed"), er("trivy", "completed"), er("gitleaks", "failed"),
	})
	if agg.SecurityScore != nil {
		t.Errorf("SecurityScore = %d, want nil (semgrep+gitleaks failed → not confident)", *agg.SecurityScore)
	}
	if agg.SecurityRating != nil {
		t.Errorf("SecurityRating = %v, want nil (not confident, never a fabricated letter)", *agg.SecurityRating)
	}
	if len(agg.EnginesDegraded) != 2 { // semgrep + gitleaks failed
		t.Fatalf("EnginesDegraded = %d, want 2", len(agg.EnginesDegraded))
	}
}

// A DEGRADED engine (Status=completed, Degraded=true) also breaks confidence — a
// custom-pack fallback runs registry-only, missing the Aegis bug/taint findings.
func TestAggregateDegradedEngineBreaksConfidence(t *testing.T) {
	semDeg := er("semgrep", "completed")
	semDeg.Degraded = true
	semDeg.DegradedReason = "custom rule pack failed to load"
	q := er("quality", "completed")
	q.QualityMetrics = &types.QualityMetrics{ComplexityScore: 80, MaintainabilityScore: 70, TotalCodeLines: 10000}
	agg := Aggregate([]*types.EngineResult{semDeg, er("trivy", "completed"), er("gitleaks", "completed"), q})
	if agg.SecurityScore != nil {
		t.Errorf("SecurityScore = %d, want nil (semgrep degraded)", *agg.SecurityScore)
	}
	if agg.SecurityRating != nil || agg.ReliabilityRating != nil {
		t.Errorf("ratings should be nil when semgrep is degraded (sec=%v rel=%v)", agg.SecurityRating, agg.ReliabilityRating)
	}
	// quality was NOT degraded → still measured.
	if agg.QualityScore == nil {
		t.Errorf("QualityScore = nil, want measured (quality engine fine)")
	}
}

func secFinding(sev string) types.Finding {
	return types.Finding{Pillar: "security", Engine: "semgrep", Severity: sev, IssueType: "vulnerability"}
}

// THE regression guard (A5): a scan with a timed-out SAST engine must NOT produce a
// confident security score, and must never score HIGHER than the same fixture
// scanned fully. Degradation drops findings, and fewer findings inflate the score —
// so a naive "score what ran" scores the degraded set ABOVE the full set. Assert the
// inflation direction directly, then assert the fix returns nil instead of it.
func TestDegradedSecurityNeverOutscoresComplete(t *testing.T) {
	loc := func() *types.EngineResult {
		q := er("quality", "completed")
		q.QualityMetrics = &types.QualityMetrics{ComplexityScore: 80, MaintainabilityScore: 70, TotalCodeLines: 10000}
		return q
	}
	// FULL: semgrep found 4 criticals, trivy 1 — high density → lower score.
	semFull := er("semgrep", "completed")
	semFull.Findings = []types.Finding{secFinding("critical"), secFinding("critical"), secFinding("critical"), secFinding("critical")}
	trivy := er("trivy", "completed")
	trivy.Findings = []types.Finding{secFinding("critical")}
	full := Aggregate([]*types.EngineResult{semFull, trivy, er("gitleaks", "completed"), loc()})

	// NAIVE partial (the OLD behaviour): semgrep "completed" but empty — only trivy's
	// 1 critical scored → lower density → HIGHER score. This is the inflation.
	naive := Aggregate([]*types.EngineResult{er("semgrep", "completed"), trivy, er("gitleaks", "completed"), loc()})

	if full.SecurityScore == nil || naive.SecurityScore == nil {
		t.Fatal("expected measured scores for the full and naive-partial cases")
	}
	if !(*naive.SecurityScore > *full.SecurityScore) {
		t.Fatalf("inflation direction wrong: naive-partial %d should exceed full %d", *naive.SecurityScore, *full.SecurityScore)
	}

	// THE FIX: semgrep timed out (failed) → security is NOT measured, so it cannot
	// carry the inflated number, and a degraded scan never outscores a complete one.
	semFailed := er("semgrep", "failed")
	semFailed.Error = "semgrep timed out after 600s"
	degraded := Aggregate([]*types.EngineResult{semFailed, trivy, er("gitleaks", "completed"), loc()})
	if degraded.SecurityScore != nil {
		t.Fatalf("degraded SecurityScore = %d, want nil — a timed-out SAST must not carry a confident (inflated) score", *degraded.SecurityScore)
	}
}
