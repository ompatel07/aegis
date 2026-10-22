package pipeline

import (
	"testing"

	"github.com/aegis-platform/orchestrator/internal/types"
)

// cov builds the coverage object the scanner reports (utils/rule_coverage.py).
func cov(confident bool, strong float64, langs ...types.LanguageCoverage) *types.SecurityCoverage {
	c := &types.SecurityCoverage{
		TotalCodeLines: 5000, StrongFraction: strong, Confident: confident,
		Threshold: 0.5, Languages: langs, Summary: "test",
	}
	if !confident {
		c.Gap = "most of this repository is in languages Aegis covers thinly or not at all"
	}
	return c
}

// qualityResult is a completed quality engine, so the overall has a measured pillar
// to renormalise onto when security is withheld.
func qualityResult(maint float64) *types.EngineResult {
	q := er("quality", "completed")
	q.QualityMetrics = &types.QualityMetrics{
		ComplexityScore: 80, MaintainabilityScore: maint, TotalCodeLines: 10000,
	}
	return q
}

func semgrepWith(c *types.SecurityCoverage, findings ...types.Finding) *types.EngineResult {
	r := er("semgrep", "completed")
	r.SecurityCoverage = c
	r.Findings = findings
	return r
}

// N2 GATE: a repository in a LIMITED-coverage language with NO findings must not
// present a confident security score or an A rating. N2 wrote it for Java (seven
// rules finding nothing read as 100/A); N4 moved Java to STRONG on ground-truth
// proof, so it is asserted for Go, still LIMITED. The fabricated-clean-score
// defect, in the family of constant-A
// reliability, `return 100` deployment and "passing" unassessed controls.
//
// Asserted the way C1 asserted degraded-must-not-outscore-complete: on the real
// Aggregate output, not on a helper.
func TestLimitedLanguageRepoWithNoFindingsIsNotAConfidentA(t *testing.T) {
	golang := types.LanguageCoverage{Language: "go", Tier: "limited", LOC: 5000, Share: 1, Rules: 8}
	agg := Aggregate([]*types.EngineResult{
		semgrepWith(cov(false, 0.0, golang)),
		er("trivy", "completed"),
		er("gitleaks", "completed"),
		qualityResult(80),
	})

	if agg.SecurityScore != nil {
		t.Errorf("security score is %d on a Go-only repo we barely cover; "+
			"it must be nil (\"Not measured\"), never a number read as clean", *agg.SecurityScore)
	}
	if agg.SecurityRating != nil {
		t.Errorf("security rating is %q; a worst-severity letter over an unread "+
			"codebase is a fabricated A", *agg.SecurityRating)
	}
	// The overall must still exist (quality carried it) but, with a nil pillar, the
	// web contract renders it PARTIAL with a mandatory qualifier -- never a bare A.
	if agg.OverallScore == nil {
		t.Fatal("overall should still be computed from the measured pillar(s)")
	}
	if agg.SecurityCoverage == nil || agg.SecurityCoverage.Gap == "" {
		t.Error("the coverage gap must travel with the scan so the UI can name it")
	}
}

// The converse: coverage must not withhold a score it has no business withholding.
// A PHP repo is strongly covered, so a clean scan there IS a real result.
func TestStronglyCoveredRepoStillScores(t *testing.T) {
	php := types.LanguageCoverage{Language: "php", Tier: "strong", LOC: 11000, Share: 1, Rules: 5}
	agg := Aggregate([]*types.EngineResult{
		semgrepWith(cov(true, 1.0, php)),
		er("trivy", "completed"),
		er("gitleaks", "completed"),
		qualityResult(80),
	})
	if agg.SecurityScore == nil {
		t.Error("a strongly-covered repo with every engine clean must produce a real score")
	}
	if agg.SecurityRating == nil {
		t.Error("a strongly-covered repo must produce a security rating")
	}
}

// A scanner predating N2 reports no coverage at all. That must not silently withhold
// every score (it would read as a product-wide regression), nor claim confidence.
func TestAbsentCoverageKeepsPreN2Behaviour(t *testing.T) {
	agg := Aggregate([]*types.EngineResult{
		semgrepWith(nil),
		er("trivy", "completed"),
		er("gitleaks", "completed"),
		qualityResult(80),
	})
	if agg.SecurityScore == nil {
		t.Error("no coverage reported (pre-N2 scanner) must keep the old behaviour, not withhold")
	}
	if agg.SecurityCoverage != nil {
		t.Error("coverage must stay nil rather than being invented")
	}
}

// Thin coverage and a degraded engine are independent reasons to withhold; neither
// may cancel the other out.
func TestDegradedEngineStillWithholdsOnStrongCoverage(t *testing.T) {
	php := types.LanguageCoverage{Language: "php", Tier: "strong", LOC: 11000, Share: 1, Rules: 5}
	trivy := er("trivy", "failed")
	agg := Aggregate([]*types.EngineResult{semgrepWith(cov(true, 1.0, php)), trivy,
		er("gitleaks", "completed"), qualityResult(80)})
	if agg.SecurityScore != nil {
		t.Error("a failed trivy must still withhold the security score even on strong coverage")
	}
}
