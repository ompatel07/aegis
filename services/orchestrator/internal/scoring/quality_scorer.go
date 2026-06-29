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
func QualityScore(m *types.QualityMetrics) int {
	if m == nil {
		return 100
	}
	weighted := m.ComplexityScore*weightComplexity +
		m.DuplicationScore*weightDuplication +
		m.MaintainabilityScore*weightMaintainability +
		m.TestCoverageScore*weightCoverage +
		m.DocumentationScore*weightDocumentation
	return clampScore(int(math.Round(weighted)))
}
