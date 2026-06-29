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

// DeploymentScore derives a 0-100 score from the deployment report's steps.
// Only attempted steps count toward the denominator, so a project with no build
// system (nothing attempted) scores 100 rather than being penalized.
func DeploymentScore(report *types.DeploymentReport) int {
	if report == nil {
		return 100
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
		return 100
	}
	return clampScore(int(math.Round(succeeded / attempted * 100)))
}

// OverallScore combines the three pillar scores and returns the score + grade.
func OverallScore(security, quality, deployment int) (int, string) {
	overall := int(math.Round(
		float64(security)*weightSecurity +
			float64(quality)*weightQuality +
			float64(deployment)*weightDeployment,
	))
	overall = clampScore(overall)
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
