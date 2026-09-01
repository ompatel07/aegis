package pipeline

import (
	"encoding/json"

	"github.com/aegis-platform/orchestrator/internal/scoring"
	"github.com/aegis-platform/orchestrator/internal/types"
)

// Aggregated is the unified, scored result of one scan, ready to persist.
type Aggregated struct {
	Findings []types.Finding

	// All pillar scores + overall are pointers: nil = NOT MEASURED (engine
	// unavailable / nothing attempted / LOC unknown), persisted as NULL and excluded
	// from the overall, which renormalizes. Mirrors how coverage represents "not
	// measured" — never a fabricated number.
	QualityScore    *int
	SecurityScore   *int
	DeploymentScore *int
	OverallScore    *int
	OverallGrade    string

	// SonarQube-style A–E ratings (P2c). Pointers: nil = NOT MEASURED (the pillar's
	// engines all failed), persisted as NULL — never a fabricated "A".
	ReliabilityRating     *string
	SecurityRating        *string
	MaintainabilityRating *string

	// Scan-level degradation (D1): engines that ran without full coverage or failed
	// outright. A non-empty list means the scan is DEGRADED, not clean.
	EnginesDegraded []types.DegradedEngine

	// Secret matches SUPPRESSED as definitively-not-a-secret (P1), summed across
	// engines: {"placeholder": n, "expired_jwt": n}. Surfaced as "N filtered" so the
	// filtering is auditable, not silent.
	FilteredSecrets map[string]int

	QualityIssuesTotal   int
	SecurityIssuesTotal  int
	SecretsFound         int
	VulnerabilitiesFound int

	RawSemgrep  json.RawMessage
	RawTrivy    json.RawMessage
	RawGitleaks json.RawMessage
	RawQuality  json.RawMessage

	// RulePackVersion is the semgrep rule set used, recorded for reproducibility.
	RulePackVersion string

	// EngineErrors records engines that failed so the scan can note degradation.
	EngineErrors map[string]string
}

// Aggregate combines per-engine results into a single scored summary.
func Aggregate(results []*types.EngineResult) Aggregated {
	agg := Aggregated{EngineErrors: map[string]string{}}

	byEngine := map[string]*types.EngineResult{}
	for _, r := range results {
		if r == nil {
			continue
		}
		byEngine[r.Engine] = r
		if r.Error != "" {
			agg.EngineErrors[r.Engine] = r.Error
		}
		if r.Engine == "semgrep" && r.RulePackVersion != "" {
			agg.RulePackVersion = r.RulePackVersion
		}
		// Collect findings from every engine, dropping suppressed-by-default none.
		agg.Findings = append(agg.Findings, r.Findings...)
	}

	// Per-pillar / per-engine counts.
	for _, f := range agg.Findings {
		switch f.Pillar {
		case types.PillarSecurity:
			agg.SecurityIssuesTotal++
		case types.PillarQuality:
			agg.QualityIssuesTotal++
		}
		if f.Engine == "gitleaks" {
			agg.SecretsFound++
		}
		if f.Engine == "trivy" && f.CVEID != "" {
			agg.VulnerabilitiesFound++
		}
	}

	// Pillar scores. Quality metrics first — the security DENSITY needs LOC.
	var qualityMetrics *types.QualityMetrics
	if q := byEngine["quality"]; q != nil {
		qualityMetrics = q.QualityMetrics
	}
	loc := 0
	if qualityMetrics != nil {
		loc = qualityMetrics.TotalCodeLines
	}
	agg.SecurityScore = scoring.SecurityScore(agg.Findings, loc)
	agg.QualityScore = scoring.QualityScore(qualityMetrics)

	var deployReport *types.DeploymentReport
	if d := byEngine["deployment"]; d != nil {
		deployReport = d.DeploymentReport
	}
	agg.DeploymentScore = scoring.DeploymentScore(deployReport)

	// Collect scan-level degradation: outright failures + coverage-losing engines.
	coverageOf := map[string]string{
		"semgrep": "SAST (taint + injection + reliability bugs)", "trivy": "SCA (dependency CVEs)",
		"gitleaks": "secrets", "quality": "code quality + reliability bugs",
		"deployment": "deployment checks", "joern": "deep dataflow", "codeql": "deep dataflow",
	}
	for _, r := range results {
		if r == nil {
			continue
		}
		// Sum secret matches filtered as definitively-not-a-secret (P1), across engines.
		for k, v := range r.FilteredSecrets {
			if v <= 0 {
				continue
			}
			if agg.FilteredSecrets == nil {
				agg.FilteredSecrets = map[string]int{}
			}
			agg.FilteredSecrets[k] += v
		}
		switch {
		case r.Status == "failed":
			agg.EnginesDegraded = append(agg.EnginesDegraded, types.DegradedEngine{
				Engine: r.Engine, Reason: firstNonEmpty(r.Error, "engine failed"),
				CoverageLost: coverageOf[r.Engine]})
		case r.Degraded:
			agg.EnginesDegraded = append(agg.EnginesDegraded, types.DegradedEngine{
				Engine: r.Engine, Reason: firstNonEmpty(r.DegradedReason, "ran with reduced coverage"),
				CoverageLost: firstNonEmpty(r.CoverageLost, coverageOf[r.Engine])})
		}
	}

	// ── Per-pillar CONFIDENCE (P4b A) ───────────────────────────────────────────
	// A degraded or failed engine feeding a pillar does not merely make its score
	// unreliable — it INFLATES it: a missing engine produces fewer findings, and
	// fewer findings read as "cleaner". So a pillar is confidently measured ONLY when
	// EVERY engine feeding it ran to full coverage; if any is failed/degraded the
	// pillar is NOT MEASURED (nil → NULL → "Not measured"), never scored on what ran.
	// Contract reused from b845240 (deployment): nil pillars renormalize out of the
	// overall. This replaces D1's "partial coverage still scores" — that erred toward
	// clean, the exact defect we are killing.
	degradedEngine := map[string]bool{}
	for _, d := range agg.EnginesDegraded {
		degradedEngine[d.Engine] = true
	}
	confident := func(engines ...string) bool {
		for _, e := range engines {
			if degradedEngine[e] {
				return false
			}
		}
		return true
	}
	securityConfident := confident("semgrep", "trivy", "gitleaks")
	qualityConfident := confident("quality")
	reliabilityConfident := confident("semgrep", "quality") // reliability bugs from both

	if !securityConfident {
		agg.SecurityScore = nil // a degraded security engine inflates the score → not measured
	}
	if !qualityConfident {
		agg.QualityScore = nil
	}
	if !confident("deployment") {
		agg.DeploymentScore = nil
	}
	agg.OverallScore, agg.OverallGrade = scoring.OverallScore(
		agg.SecurityScore, agg.QualityScore, agg.DeploymentScore,
	)

	// Ratings — nil (NULL) when the pillar is not confidently measured, so a
	// degraded scan never shows a fabricated A (a worst-severity letter derived from
	// an incomplete finding set understates risk exactly as the score does).
	if securityConfident {
		agg.SecurityRating = strptr(scoring.SecurityRating(agg.Findings))
	}
	if reliabilityConfident {
		agg.ReliabilityRating = strptr(scoring.ReliabilityRating(agg.Findings))
	}
	if qualityConfident && qualityMetrics != nil {
		agg.MaintainabilityRating = strptr(scoring.MaintainabilityRating(qualityMetrics))
	}

	// Raw engine output (stored to scans.raw_*_output).
	agg.RawSemgrep = rawOf(byEngine["semgrep"])
	agg.RawTrivy = rawOf(byEngine["trivy"])
	agg.RawGitleaks = rawOf(byEngine["gitleaks"])
	agg.RawQuality = rawOf(byEngine["quality"])

	return agg
}

// rawOf marshals an engine's raw output, returning JSON null when absent.
func rawOf(r *types.EngineResult) json.RawMessage {
	if r == nil || r.Raw == nil {
		return json.RawMessage("null")
	}
	b, err := json.Marshal(r.Raw)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}

func strptr(s string) *string { return &s }

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
