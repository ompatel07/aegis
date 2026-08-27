package scoring

import (
	"math"

	"github.com/aegis-platform/orchestrator/internal/types"
)

// Quality sub-score weights (sum to 1.0 with coverage present).
//
// Duplication is NOT a separate weight any more — it now lives inside the
// maintainability score (which is where a 90%-duplicated codebase should show up),
// so weighting it separately would double-count. Documentation (comment density)
// is DROPPED: it rewards comment spam and SonarQube deliberately does not score it;
// its weight is redistributed to maintainability, the real tech-debt signal.
const (
	weightComplexity      = 0.30
	weightMaintainability = 0.55
	weightCoverage        = 0.15
)

// QualityScore computes the weighted quality pillar score, or nil when NOT
// MEASURED (no quality metrics — the engine failed or was unavailable). Returning
// a neutral 100 there was a fabrication (the deployment-100 defect again); nil is
// excluded from the overall and the pillar weights renormalize.
//
// Coverage is likewise special: TestCoverageScore nil = no coverage report shipped
// = UNKNOWN, so its weight is dropped and the remaining sub-scores renormalize —
// never counted as 0.
func QualityScore(m *types.QualityMetrics) *int {
	if m == nil {
		return nil // not measured
	}
	weighted := m.ComplexityScore*weightComplexity + m.MaintainabilityScore*weightMaintainability
	totalWeight := weightComplexity + weightMaintainability
	if m.TestCoverageScore != nil {
		weighted += *m.TestCoverageScore * weightCoverage
		totalWeight += weightCoverage
	}
	if totalWeight == 0 { // defensive; weights are constants > 0
		return nil
	}
	v := clampScore(int(math.Round(weighted / totalWeight)))
	return &v
}
