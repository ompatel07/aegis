package scoring

import (
	"math"

	"github.com/aegis-platform/orchestrator/internal/types"
)

// Pillar weights for the overall score (must sum to 1.0).
const (
	weightSecurity   = 0.40
	weightQuality    = 0.35
	weightDeployment = 0.25
)

// Per-step weights for the deployment score.
var deploymentStepWeights = map[string]float64{
	"dependency-resolution": 25,
	"build":                 60,
	"smoke":                 15,
}

// DeploymentScore derives a 0-100 score from the deployment report's steps, or
// nil when the deployment pillar was NOT MEASURED. Nothing attempted (no build
// system, or build execution disabled) is not a 100 — it is "we don't know", and
// fabricating 100 handed every repo 25 free points for a check that never ran (the
// same defect class as the fabricated-60%-coverage bug). Nil is excluded from the
// overall and the weights renormalize, exactly as coverage does for the quality
// score. Never substitute a number.
func DeploymentScore(report *types.DeploymentReport) *int {
	if report == nil {
		return nil
	}
	var attempted, succeeded float64
	for _, step := range report.Steps {
		w, ok := deploymentStepWeights[step.Name]
		if !ok {
			continue
		}
		attempted += w
		if step.Success {
			succeeded += w
		}
	}
	if attempted == 0 {
		return nil // not measured
	}
	v := clampScore(int(math.Round(succeeded / attempted * 100)))
	return &v
}

// OverallScore combines the measured pillar scores and returns the score + grade.
// Security is always measured; quality and deployment may be nil (not measured),
// in which case they are dropped and the remaining pillar weights renormalize —
// scoring only what was actually measured.
func OverallScore(security int, quality, deployment *int) (int, string) {
	weighted := float64(security) * weightSecurity
	total := weightSecurity
	if quality != nil {
		weighted += float64(*quality) * weightQuality
		total += weightQuality
	}
	if deployment != nil {
		weighted += float64(*deployment) * weightDeployment
		total += weightDeployment
	}
	if total == 0 { // impossible (security always present), but never divide by zero
		return security, Grade(security)
	}
	overall := clampScore(int(math.Round(weighted / total)))
	return overall, Grade(overall)
}

// Grade maps an overall score to a letter grade.
func Grade(overall int) string {
	switch {
	case overall >= 90:
		return "A"
	case overall >= 75:
		return "B"
	case overall >= 60:
		return "C"
	case overall >= 40:
		return "D"
	default:
		return "F"
	}
}
