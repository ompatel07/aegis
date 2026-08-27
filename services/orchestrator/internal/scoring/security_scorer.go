// Package scoring implements the Aegis scoring model: per-pillar scores plus the
// weighted overall score and letter grade.
package scoring

import (
	"math"

	"github.com/aegis-platform/orchestrator/internal/types"
)

// Severity WEIGHTS for the security score. The score is a severity-weighted
// finding DENSITY per KLOC, not a raw penalty: with the old `100 - 25*critical`,
// four criticals hit 0 and every repo in Validation V1 (which all have ≥4) scored
// 0 / graded E — a constant carrying no information. Density distinguishes 1
// critical from 413. The LETTER (SecurityRating) still comes from worst-severity,
// so one unfixed critical still caps the grade at E — an auditor's view.
//
// Calibrated on the S1 corpus (127 criticals): kSecurityDensity = 5.5 spreads the
// 15 repos across 31..92, with the densest-critical repo (pterodactyl: 9 crit +
// 31 high in 53k LOC) worst and the sparsest (akaunting) best.
const (
	penaltyCritical = 25.0
	penaltyHigh     = 10.0
	penaltyMedium   = 3.0
	penaltyLow      = 1.0

	kSecurityDensity = 5.5 // score = 100 - k * weighted-severity-density-per-KLOC
)

// Reachability weighting for dependency (SCA) findings. A CVE in a package that
// is never imported is far less urgent than one wired into the code; a directly
// declared, reachable dependency is the most urgent. Findings without
// reachability data (SAST, secrets, or undetermined SCA) are weighted 1.0.
const (
	weightUnreachable  = 0.5 // proven not imported/used anywhere
	weightReachable    = 1.0 // imported/used
	weightDirectFactor = 1.2 // reachable AND a direct dependency: +20%
	// A CVE on the CISA KEV list is actively exploited in the wild — the strongest
	// urgency signal. It multiplies the penalty on top of reachability so an
	// exploited, reachable vuln dominates the score.
	weightKEVFactor = 1.5
)

// SecurityScore computes the security pillar score as a severity-weighted finding
// DENSITY per KLOC (start 100, floor 0). Reachability + KEV still weight each
// finding's contribution. `totalCodeLines` comes from the quality metrics; a
// down-ranked finding (secret_context = test-fixture/placeholder/expired) already
// carries its down-ranked severity, so it contributes less — the point of S1.
//
// Unknown value: no security findings → 100 (measured, clean). LOC unknown (quality
// engine failed) → cannot normalize, so fall back to the raw penalty sum (the old
// count-based behaviour) rather than fabricate — documented in PRECISION/scoring.
func SecurityScore(findings []types.Finding, totalCodeLines int) int {
	var weighted float64
	for _, f := range findings {
		if f.Pillar != types.PillarSecurity {
			continue
		}
		base := severityPenalty(f.Severity)
		if base == 0 {
			continue
		}
		weighted += base * reachabilityWeight(f) * kevWeight(f)
	}
	if totalCodeLines <= 0 {
		return clampScore(int(math.Round(100 - weighted))) // LOC unknown: degrade to count-based
	}
	kloc := float64(totalCodeLines) / 1000.0
	if kloc < 0.001 {
		kloc = 0.001
	}
	return clampScore(int(math.Round(100 - kSecurityDensity*(weighted/kloc))))
}

// kevWeight bumps the penalty for a CVE that is on the CISA KEV list (actively
// exploited). Non-KEV / non-SCA findings are unaffected (1.0).
func kevWeight(f types.Finding) float64 {
	if f.Metadata == nil {
		return 1.0
	}
	if exploited, ok := f.Metadata["kev"].(bool); ok && exploited {
		return weightKEVFactor
	}
	return 1.0
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
