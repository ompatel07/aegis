// Package scoring implements the Aegis scoring model: per-pillar scores plus the
// weighted overall score and letter grade.
package scoring

import "github.com/aegis-platform/orchestrator/internal/types"

// Severity penalties for the security score (start 100, floor 0).
const (
	penaltyCritical = 25
	penaltyHigh     = 10
	penaltyMedium   = 3
	penaltyLow      = 1
)

// SecurityScore computes the security pillar score from security-pillar findings.
// Suppressed findings should already be excluded by the caller.
func SecurityScore(findings []types.Finding) int {
	score := 100
	for _, f := range findings {
		if f.Pillar != types.PillarSecurity {
			continue
		}
		switch f.Severity {
		case types.SeverityCritical:
			score -= penaltyCritical
		case types.SeverityHigh:
			score -= penaltyHigh
		case types.SeverityMedium:
			score -= penaltyMedium
		case types.SeverityLow:
			score -= penaltyLow
		}
	}
	return clampScore(score)
}

func clampScore(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
