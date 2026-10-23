package pipeline

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aegis-platform/orchestrator/internal/types"
)

// D2: semgrep cuts a large function's taint analysis short on a wall-clock limit, so
// findings in those files can differ between scans of one commit. The scanner reports
// the files in security_coverage.partially_analysed; it must reach the stored scan
// intact (the API stores this struct, re-encoded) and it discloses -- it does not
// change what the quadrant lets the scan show.
func TestPartiallyAnalysedFilesSurviveTheRoundTripAndChangeNothingShown(t *testing.T) {
	scanner := `{"total_code_lines": 5000, "threshold": 0.5, "summary": "test",
		"quadrant": "full", "confident": true, "clean_claim": true, "problem_claim": true,
		"partially_analysed": {"files": 2, "fixpoint_timeouts": 5, "rule_timeouts": 1,
			"sample": ["htdocs/adherents/card.php", "htdocs/takepos/invoice.php"],
			"reason": "semgrep stopped analysing part of these files on a time limit"}}`
	var cov types.SecurityCoverage
	if err := json.Unmarshal([]byte(scanner), &cov); err != nil {
		t.Fatal(err)
	}
	if cov.PartiallyAnalysed == nil || cov.PartiallyAnalysed.Files != 2 || len(cov.PartiallyAnalysed.Sample) != 2 {
		t.Fatalf("partially_analysed dropped on decode: %+v", cov.PartiallyAnalysed)
	}

	with := Aggregate([]*types.EngineResult{semgrepWith(&cov), er("trivy", "completed"),
		er("gitleaks", "completed"), qualityResult(80)})
	cov2 := *quadrantCov(types.QuadrantFull)
	without := Aggregate([]*types.EngineResult{semgrepWith(&cov2), er("trivy", "completed"),
		er("gitleaks", "completed"), qualityResult(80)})
	if (with.SecurityScore == nil) != (without.SecurityScore == nil) || len(with.EnginesDegraded) != 0 {
		t.Errorf("disclosure changed the result: score %v vs %v, degraded %v",
			with.SecurityScore, without.SecurityScore, with.EnginesDegraded)
	}

	out, err := json.Marshal(with.SecurityCoverage)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"partially_analysed":{"files":2`) ||
		!strings.Contains(string(out), "htdocs/takepos/invoice.php") {
		t.Errorf("partially_analysed lost on re-encode: %s", out)
	}
	clean, _ := json.Marshal(without.SecurityCoverage)
	if strings.Contains(string(clean), "partially_analysed") {
		t.Errorf("a complete analysis must not carry the field: %s", clean)
	}
}
