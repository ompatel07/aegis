package scoring

import "github.com/aegis-platform/orchestrator/internal/types"

// SonarQube-style A–E ratings (P2c), derived from data Aegis already computes.
//
//   - Reliability  — from the worst-severity Bug (SonarQube: A = no bugs).
//   - Security     — from the worst-severity Vulnerability (A = no vulns).
//   - Maintainability — from the maintainability sub-score (a tech-debt proxy),
//     bucketed A..E.
//
// A is best, E is worst. The severity→letter mapping mirrors SonarQube's
// reliability/security model (one blocker/critical issue caps the rating at E).

// ratingForWorstSeverity maps the worst severity among a class of findings to a
// letter: none→A, low→B, medium→C, high→D, critical→E.
func ratingForWorstSeverity(findings []types.Finding, issueType string) string {
	worst := 0 // 0 none,1 low,2 medium,3 high,4 critical
	for _, f := range findings {
		if f.IssueType != issueType {
			continue
		}
		if r := severityRank(f.Severity); r > worst {
			worst = r
		}
	}
	return []string{"A", "B", "C", "D", "E"}[worst]
}

func severityRank(sev string) int {
	switch sev {
	case types.SeverityCritical:
		return 4
	case types.SeverityHigh:
		return 3
	case types.SeverityMedium:
		return 2
	case types.SeverityLow:
		return 1
	default:
		return 0
	}
}

// ReliabilityRating: worst-severity Bug across the findings.
func ReliabilityRating(findings []types.Finding) string {
	return ratingForWorstSeverity(findings, "bug")
}

// SecurityRating: worst-severity Vulnerability across the findings.
func SecurityRating(findings []types.Finding) string {
	return ratingForWorstSeverity(findings, "vulnerability")
}

// MaintainabilityRating: buckets the maintainability sub-score (0–100, higher is
// better) into A..E. Thresholds are documented in PER_ENGINE_ACCURACY.md.
//
//	A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 50, else E.
func MaintainabilityRating(m *types.QualityMetrics) string {
	if m == nil {
		return "N/A" // NOT MEASURED — never a fabricated "A" (unknown-value audit, C1)
	}
	return scoreToRating(m.MaintainabilityScore)
}

func scoreToRating(score float64) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 50:
		return "D"
	default:
		return "E"
	}
}
