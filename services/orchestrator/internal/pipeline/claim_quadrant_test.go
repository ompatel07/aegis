package pipeline

import (
	"testing"

	"github.com/aegis-platform/orchestrator/internal/types"
)

// N6: two claims, two gates. A clean result rests on recall, a reported problem on
// precision; the scanner certifies each per repository (coverage quadrant) and the
// aggregator shows only what the certified claim can back. Asserted on the real
// Aggregate output, one test per quadrant.

func quadrantCov(q string) *types.SecurityCoverage {
	c := &types.SecurityCoverage{
		TotalCodeLines: 5000, Threshold: 0.5, Summary: "test", Quadrant: q,
		Confident:    q == types.QuadrantFull,
		CleanClaim:   q == types.QuadrantFull || q == types.QuadrantClean,
		ProblemClaim: q == types.QuadrantFull || q == types.QuadrantProblem,
		CleanLabel:   "No issues found in what we check · Java 15% held-out recall",
	}
	if q == types.QuadrantClean || q == types.QuadrantWithheld {
		c.PrecisionCaveat = "findings are not certified: on held-out real repositories our findings were PHP 25% precise"
	}
	if q == types.QuadrantWithheld {
		c.Gap = "most of this repository is in languages where neither claim is certified"
	}
	return c
}

func aggregateWith(q string, findings ...types.Finding) Aggregated {
	return Aggregate([]*types.EngineResult{
		semgrepWith(quadrantCov(q), findings...),
		er("trivy", "completed"),
		er("gitleaks", "completed"),
		qualityResult(80),
	})
}

func favourable(letter string) bool { return letter == "A" || letter == "B" }

// recall OK + precision OK -> full score and grade.
func TestFullQuadrantShowsScoreAndGrade(t *testing.T) {
	clean := aggregateWith(types.QuadrantFull)
	if clean.SecurityScore == nil || clean.SecurityRating == nil || *clean.SecurityRating != "A" {
		t.Fatalf("full quadrant, no findings: want a measured A, got score=%v rating=%v",
			clean.SecurityScore, clean.SecurityRating)
	}
	bad := aggregateWith(types.QuadrantFull, secFinding("critical"))
	if bad.SecurityRating == nil || *bad.SecurityRating != "E" {
		t.Fatalf("full quadrant, a critical finding: want rating E, got %v", bad.SecurityRating)
	}
}

// THE GATE: recall fails + precision OK, ZERO findings. A favourable grade would be a
// clean claim our recall cannot back, so nothing favourable is shown: no A, no 100.
func TestLimitedRecallRepoWithZeroFindingsNeverRendersA(t *testing.T) {
	agg := aggregateWith(types.QuadrantProblem)
	if agg.SecurityRating != nil {
		t.Errorf("limited-recall repo with no findings shows rating %q; a clean grade needs certified recall",
			*agg.SecurityRating)
	}
	if agg.SecurityScore != nil {
		t.Errorf("limited-recall repo with no findings shows score %d; a favourable score is a clean claim",
			*agg.SecurityScore)
	}
	if agg.SecurityCoverage == nil || agg.SecurityCoverage.CleanLabel == "" {
		t.Error("the clean label (what we checked, and our held-out recall) must travel with the scan")
	}
	if agg.OverallGrade == "" || agg.OverallScore == nil {
		t.Fatal("the overall still renormalises onto quality (partial), as for any unmeasured pillar")
	}
}

// recall fails + precision OK, with real findings: the problem IS certified, so an
// unfavourable result and the findings are shown.
func TestProblemOnlyQuadrantShowsAnUnfavourableResult(t *testing.T) {
	agg := aggregateWith(types.QuadrantProblem, secFinding("critical"), secFinding("high"))
	if agg.SecurityRating == nil || favourable(*agg.SecurityRating) {
		t.Fatalf("problem-only with a critical finding: want an unfavourable rating shown, got %v", agg.SecurityRating)
	}
	if agg.SecurityScore != nil && *agg.SecurityScore >= 75 {
		t.Errorf("a favourable score (%d) must never show in the problem-only quadrant", *agg.SecurityScore)
	}
	if len(agg.Findings) == 0 {
		t.Error("the findings must be shown")
	}
}

// recall OK + precision fails: a clean result may be shown...
func TestCleanOnlyQuadrantShowsACleanResult(t *testing.T) {
	agg := aggregateWith(types.QuadrantClean)
	if agg.SecurityRating == nil || *agg.SecurityRating != "A" {
		t.Fatalf("clean-only with no findings: our recall is certified, want A, got %v", agg.SecurityRating)
	}
}

// ...but no confident bad grade: the findings carry a precision caveat instead.
func TestCleanOnlyQuadrantNeverShowsAConfidentBadGrade(t *testing.T) {
	agg := aggregateWith(types.QuadrantClean, secFinding("critical"), secFinding("critical"))
	if agg.SecurityRating != nil {
		t.Errorf("clean-only with uncertified findings shows rating %q; a bad grade needs certified precision",
			*agg.SecurityRating)
	}
	if agg.SecurityScore != nil && *agg.SecurityScore < 75 {
		t.Errorf("clean-only shows an unfavourable score %d resting on uncertified findings", *agg.SecurityScore)
	}
	if len(agg.Findings) == 0 {
		t.Error("the findings must still be shown, with the caveat")
	}
	if agg.SecurityCoverage.PrecisionCaveat == "" {
		t.Error("the precision caveat must travel with the scan")
	}
}

// both fail -> withheld, the N2 contract unchanged.
func TestWithheldQuadrantWithholdsBoth(t *testing.T) {
	for _, fs := range [][]types.Finding{nil, {secFinding("critical")}} {
		agg := aggregateWith(types.QuadrantWithheld, fs...)
		if agg.SecurityScore != nil || agg.SecurityRating != nil {
			t.Errorf("withheld quadrant shows score=%v rating=%v", agg.SecurityScore, agg.SecurityRating)
		}
	}
}

// A scan from a pre-N6 scanner has no quadrant: Confident decides, as before.
func TestPreN6CoverageFallsBackToConfident(t *testing.T) {
	old := &types.SecurityCoverage{TotalCodeLines: 100, Confident: false, Gap: "thin"}
	if q := old.EffectiveQuadrant(); q != types.QuadrantWithheld {
		t.Errorf("pre-N6 unconfident coverage: want withheld, got %s", q)
	}
	old.Confident = true
	if q := old.EffectiveQuadrant(); q != types.QuadrantFull {
		t.Errorf("pre-N6 confident coverage: want full, got %s", q)
	}
	var none *types.SecurityCoverage
	if q := none.EffectiveQuadrant(); q != types.QuadrantFull {
		t.Errorf("no coverage object (no application code): want full, got %s", q)
	}
}

// A degraded security engine still withholds, whatever the quadrant (P4b).
func TestDegradedEngineWithholdsInEveryQuadrant(t *testing.T) {
	for _, q := range []string{types.QuadrantFull, types.QuadrantProblem, types.QuadrantClean} {
		agg := Aggregate([]*types.EngineResult{
			semgrepWith(quadrantCov(q)),
			er("trivy", "failed"),
			er("gitleaks", "completed"),
			qualityResult(80),
		})
		if agg.SecurityScore != nil || agg.SecurityRating != nil {
			t.Errorf("%s: a failed security engine must withhold, got score=%v rating=%v", q,
				agg.SecurityScore, agg.SecurityRating)
		}
	}
}
