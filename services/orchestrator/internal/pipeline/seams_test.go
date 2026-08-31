package pipeline

import (
	"testing"

	"github.com/aegis-platform/orchestrator/internal/types"
)

// ratingRank: A(best)=0 .. E(worst)=4, for ordering assertions.
func ratingRank(letter string) int {
	return map[string]int{"A": 0, "B": 1, "C": 2, "D": 3, "E": 4}[letter]
}

func vuln(sev string) types.Finding {
	return types.Finding{Pillar: "security", Engine: "semgrep", Severity: sev, IssueType: "vulnerability"}
}
func bug(sev string) types.Finding {
	return types.Finding{Pillar: "quality", Engine: "semgrep", Severity: sev, IssueType: "bug"}
}

func qualityEngine(maint, complexity float64, dupPct float64, loc int) *types.EngineResult {
	r := er("quality", "completed")
	r.QualityMetrics = &types.QualityMetrics{
		ComplexityScore: complexity, MaintainabilityScore: maint,
		DuplicatedLinePercent: dupPct, TotalCodeLines: loc,
	}
	return r
}

// Seam 3 (Pass D1) — THE important seam. Three deliberately different repos run
// through the REAL aggregator; no rating may come out constant, and a worse input
// must produce a worse letter. This is the only test that would have caught
// constant-A Reliability, constant-E Security, and the inverted maintainability
// metric — each of which passes every per-function unit test while being globally
// wrong. See the scanner-side companion (tests/test_seams.py, seam 3) which guards
// the reliability SOURCE (issue_type=bug tagging / _QUALITY_BUG_RULES).
func TestSeamRatingsNeverConstantAcrossRepos(t *testing.T) {
	// clean: nothing wrong, tidy code.
	cleanSem := er("semgrep", "completed")
	clean := Aggregate([]*types.EngineResult{
		cleanSem, er("trivy", "completed"),
		qualityEngine(95, 92, 1, 5000),
	})

	// vulnerable: a critical vuln + a high reliability bug.
	vulnSem := er("semgrep", "completed")
	vulnSem.Findings = []types.Finding{vuln(types.SeverityCritical), bug(types.SeverityHigh)}
	vulnerable := Aggregate([]*types.EngineResult{
		vulnSem, er("trivy", "completed"),
		qualityEngine(72, 80, 5, 5000),
	})

	// duplicated: no vulns/bugs, but 90% duplicated → maintainability floor.
	dupSem := er("semgrep", "completed")
	duplicated := Aggregate([]*types.EngineResult{
		dupSem, er("trivy", "completed"),
		qualityEngine(45, 70, 90, 5000),
	})

	deref := func(p *string, name string) string {
		if p == nil {
			t.Fatalf("%s rating is nil (not measured) in a fully-measured scan", name)
		}
		return *p
	}

	secClean := deref(clean.SecurityRating, "security/clean")
	secVuln := deref(vulnerable.SecurityRating, "security/vuln")
	secDup := deref(duplicated.SecurityRating, "security/dup")

	relClean := deref(clean.ReliabilityRating, "reliability/clean")
	relVuln := deref(vulnerable.ReliabilityRating, "reliability/vuln")
	relDup := deref(duplicated.ReliabilityRating, "reliability/dup")

	mntClean := deref(clean.MaintainabilityRating, "maint/clean")
	mntVuln := deref(vulnerable.MaintainabilityRating, "maint/vuln")
	mntDup := deref(duplicated.MaintainabilityRating, "maint/dup")

	notConstant := func(name string, vals ...string) {
		first := vals[0]
		for _, v := range vals {
			if v != first {
				return
			}
		}
		t.Errorf("%s rating is CONSTANT %q across clean/vulnerable/duplicated repos — a rating that never moves is not measuring anything", name, first)
	}
	worse := func(name, worseLetter, betterLetter string) {
		if ratingRank(worseLetter) <= ratingRank(betterLetter) {
			t.Errorf("%s: expected the worse repo to rate worse, got %q not worse than %q (possible inverted/broken metric)", name, worseLetter, betterLetter)
		}
	}

	// (1) Nothing is constant.
	notConstant("Security", secClean, secVuln, secDup)
	notConstant("Reliability", relClean, relVuln, relDup)
	notConstant("Maintainability", mntClean, mntVuln, mntDup)

	// (2) Correctly ordered — catches inversion, not just constancy.
	worse("Security (vuln repo)", secVuln, secClean)   // constant-E would fail (1); wrong dir fails here
	worse("Reliability (vuln repo)", relVuln, relClean) // catches constant-A reliability
	worse("Maintainability (dup repo)", mntDup, mntClean) // catches inverted maintainability

	// (3) The overall score must move too.
	if clean.OverallScore == nil || vulnerable.OverallScore == nil || duplicated.OverallScore == nil {
		t.Fatal("overall score nil in a fully-measured scan")
	}
	if *clean.OverallScore == *vulnerable.OverallScore && *clean.OverallScore == *duplicated.OverallScore {
		t.Errorf("Overall score constant %d across three different repos", *clean.OverallScore)
	}
}
