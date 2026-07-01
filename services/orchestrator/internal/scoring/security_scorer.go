// Package scoring implements the Aegis scoring model: per-pillar scores plus the
// weighted overall score and letter grade.
package scoring

import (
	"math"

	"github.com/aegis-platform/orchestrator/internal/types"
)

// Severity penalties for the security score (start 100, floor 0).
const (
	penaltyCritical = 25.0
	penaltyHigh     = 10.0
	penaltyMedium   = 3.0
	penaltyLow      = 1.0
)

// Reachability weighting for dependency (SCA) findings. A CVE in a package that
// is never imported is far less urgent than one wired into the code; a directly
// declared, reachable dependency is the most urgent. Findings without
// reachability data (SAST, secrets, or undetermined SCA) are weighted 1.0.
const (
	weightUnreachable  = 0.5 // proven not imported/used anywhere
	weightReachable    = 1.0 // imported/used
	weightDirectFactor = 1.2 // reachable AND a direct dependency: +20%
)

// SecurityScore computes the security pillar score from security-pillar findings.
// Suppressed findings should already be excluded by the caller.
func SecurityScore(findings []types.Finding) int {
	score := 100.0
	for _, f := range findings {
		if f.Pillar != types.PillarSecurity {
			continue
		}
		base := severityPenalty(f.Severity)
		if base == 0 {
			continue
		}
		score -= base * reachabilityWeight(f)
	}
	return clampScore(int(math.Round(score)))
}

func severityPenalty(severity string) float64 {
	switch severity {
	case types.SeverityCritical:
		return penaltyCritical
	case types.SeverityHigh:
		return penaltyHigh
	case types.SeverityMedium:
		return penaltyMedium
	case types.SeverityLow:
		return penaltyLow
	default:
		return 0
	}
}

// reachabilityWeight derives the penalty multiplier from a finding's reachability
// metadata (populated by the SCA engine). Unknown/absent -> full penalty, so we
// never under-count a vulnerability we couldn't analyze.
func reachabilityWeight(f types.Finding) float64 {
	if f.Metadata == nil {
		return weightReachable
	}
	reachable, ok := f.Metadata["reachable"].(bool)
	if !ok {
		return weightReachable // undetermined -> full penalty
	}
	if !reachable {
		return weightUnreachable
	}
	if direct, ok := f.Metadata["is_direct"].(bool); ok && direct {
		return weightDirectFactor
	}
	return weightReachable
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
