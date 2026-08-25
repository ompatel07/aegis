package scoring

import (
	"math"

	"github.com/aegis-platform/orchestrator/internal/types"
)

// Quality sub-score weights (must sum to 1.0).
const (
	weightComplexity      = 0.30
	weightDuplication     = 0.20
	weightMaintainability = 0.25
	weightCoverage        = 0.15
	weightDocumentation   = 0.10
)

// QualityScore computes the weighted quality pillar score from the scanner's
// pre-computed sub-scores. A nil metrics block (quality engine unavailable)
// yields a neutral 100 so a missing engine never tanks the grade.
//
// Coverage is special: when TestCoverageScore is nil the project shipped no
// coverage report, so coverage is UNKNOWN. We must not count it as 0 (that would
// punish every repo that simply doesn't publish coverage). Instead we drop the
// coverage weight and renormalize the remaining metrics over their own weights,
// scoring only what we actually measured.
func QualityScore(m *types.QualityMetrics) int {
	if m == nil {
		return 100
	}
	weighted := m.ComplexityScore*weightComplexity +
		m.DuplicationScore*weightDuplication +
		m.MaintainabilityScore*weightMaintainability +
		m.DocumentationScore*weightDocumentation
	totalWeight := weightComplexity + weightDuplication + weightMaintainability + weightDocumentation

	if m.TestCoverageScore != nil {
		weighted += *m.TestCoverageScore * weightCoverage
		totalWeight += weightCoverage
	}
	if totalWeight == 0 { // defensive; weights are constants > 0
		return 100
	}
	return clampScore(int(math.Round(weighted / totalWeight)))
}
