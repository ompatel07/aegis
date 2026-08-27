package pipeline

import (
	"encoding/json"

	"github.com/aegis-platform/orchestrator/internal/scoring"
	"github.com/aegis-platform/orchestrator/internal/types"
)

// Aggregated is the unified, scored result of one scan, ready to persist.
type Aggregated struct {
	Findings []types.Finding

	// Quality and Deployment are pointers: nil = NOT MEASURED (engine unavailable /
	// nothing attempted), persisted as NULL, excluded from the overall. Security is
	// always measured. This mirrors how coverage represents "not measured".
	QualityScore    *int
	SecurityScore   int
	DeploymentScore *int
	OverallScore    int
	OverallGrade    string

	// SonarQube-style A–E ratings (P2c).
	ReliabilityRating    string
	SecurityRating       string
	MaintainabilityRating string

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

	agg.OverallScore, agg.OverallGrade = scoring.OverallScore(
		agg.SecurityScore, agg.QualityScore, agg.DeploymentScore,
	)

	// SonarQube-style A–E ratings (P2c): reliability/security from the worst
	// bug/vulnerability severity, maintainability from the maintainability sub-score.
	agg.ReliabilityRating = scoring.ReliabilityRating(agg.Findings)
	agg.SecurityRating = scoring.SecurityRating(agg.Findings)
	agg.MaintainabilityRating = scoring.MaintainabilityRating(qualityMetrics)

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
