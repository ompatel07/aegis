package scoring

import (
	"math"

	"github.com/aegis-platform/orchestrator/internal/types"
)

// Pillar weights for the overall score.
//
// Aegis is a TWO-PILLAR product on the default (web/API) path: Security and Code
// Quality. Their weights keep the original 0.40 : 0.35 security-to-quality ratio;
// with deployment absent, OverallScore renormalizes them to 0.533 : 0.467
// (0.40/0.75 : 0.35/0.75). Deployment (0.25) is offered ONLY in CI mode, where the
// customer's own pipeline built the workspace; there the three weights sum to 1.0.
// See docs/SCORING_CALIBRATION_C1.md (§ Two-pillar composition).
const (
	weightSecurity   = 0.40
	weightQuality    = 0.35
	weightDeployment = 0.25 // CI mode only; never contributes on the web/API path
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

// OverallScore combines the MEASURED pillar scores and returns the score + grade,
// or (nil, "N/A") when nothing was measured. Any pillar may be nil (not measured)
// — security when LOC is unknown, quality when its engine failed, deployment when
// nothing was attempted — and nil pillars are dropped with the remaining weights
// renormalized. Never substitutes a number for a pillar that did not run.
func OverallScore(security, quality, deployment *int) (*int, string) {
	var weighted, total float64
	add := func(v *int, w float64) {
		if v != nil {
			weighted += float64(*v) * w
			total += w
		}
	}
	add(security, weightSecurity)
	add(quality, weightQuality)
	add(deployment, weightDeployment)
	if total == 0 {
		return nil, "N/A" // nothing measured
	}
	overall := clampScore(int(math.Round(weighted / total)))
	return &overall, Grade(overall)
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
