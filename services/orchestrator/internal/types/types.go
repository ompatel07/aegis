// Package types holds the shared data shapes exchanged with the scanner service
// and passed between the orchestrator's pipeline, aggregator, and scorers.
//
// These mirror the scanner's Pydantic models (services/scanner/models). Field
// names match the scanner's JSON so unmarshaling is direct.
package types

import "encoding/json"

// Severity levels (lowercase, matching the DB CHECK constraint).
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Pillars.
const (
	PillarQuality    = "quality"
	PillarSecurity   = "security"
	PillarDeployment = "deployment"
)

// Finding is one normalized issue from any engine.
type Finding struct {
	Pillar      string `json:"pillar"`
	Engine      string `json:"engine"`
	RuleID      string `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`

	FilePath    string `json:"file_path"`
	LineStart   *int   `json:"line_start"`
	LineEnd     *int   `json:"line_end"`
	ColumnStart *int   `json:"column_start"`
	ColumnEnd   *int   `json:"column_end"`

	CWEID         string `json:"cwe_id"`
	CVEID         string `json:"cve_id"`
	OWASPCategory string `json:"owasp_category"`

	FixSuggestion string         `json:"fix_suggestion"`
	Metadata      map[string]any `json:"metadata"`

	// Context-rich enrichment (Phase 2B), populated by the scanner.
	TitleHuman         string         `json:"title_human"`
	Impact             string         `json:"impact"`
	RiskLevel          string         `json:"risk_level"`
	RemediationAction  string         `json:"remediation_action"`
	RemediationDetails string         `json:"remediation_details"`
	EstimatedEffort    string         `json:"estimated_effort"`
	ContextMetadata    map[string]any `json:"context_metadata"`

	// Local ML false-positive filter output (advisory).
	FalsePositiveProbability *float64 `json:"false_positive_probability"`

	// Inline code + lifecycle identity (P1a/P1c), populated by the scanner.
	CodeSnippet      string `json:"code_snippet"`
	SnippetStartLine *int   `json:"snippet_start_line"`
	Fingerprint      string `json:"fingerprint"`
	// CodeKey is the fingerprint without file_path (J4). It lets the lifecycle
	// recognise a finding whose file was renamed or moved, instead of reporting
	// it as one resolved plus one new.
	CodeKey string `json:"code_key"`

	// IsNew: this finding is genuinely new versus the project's prior scans —
	// its stable fingerprint was never seen before (or was resolved and has now
	// reopened). Set by the orchestrator's lifecycle pass (P1a).
	IsNew bool `json:"is_new"`
	// LifecycleStatus: new | existing | reopened for findings present in this
	// scan. (resolved findings are absent from the scan and tracked separately in
	// project_finding_states.) Set by the lifecycle pass.
	LifecycleStatus string `json:"lifecycle_status"`

	// IssueType: SonarQube-style bug | vulnerability | code_smell (P2c), from the
	// scanner's enrichment classifier.
	IssueType string `json:"issue_type"`
}

// SeveritySummary holds per-severity counts.
type SeveritySummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// QualityMetrics holds the quality sub-scores + raw measurements.
type QualityMetrics struct {
	ComplexityScore      float64 `json:"complexity_score"`
	DuplicationScore     float64 `json:"duplication_score"`
	MaintainabilityScore float64 `json:"maintainability_score"`
	// nil = coverage not measured (no report shipped); excluded from the composite
	// quality score rather than counted as 0. A pointer so JSON null round-trips.
	TestCoverageScore     *float64 `json:"test_coverage_score"`
	DocumentationScore    float64  `json:"documentation_score"`
	AvgCyclomatic         float64  `json:"avg_cyclomatic_complexity"`
	MaxCyclomatic         int      `json:"max_cyclomatic_complexity"`
	DuplicatedLinePercent float64  `json:"duplicated_line_percentage"`
	CommentDensity        float64  `json:"comment_density"`
	TotalFunctions        int      `json:"total_functions"`
	TotalCodeLines        int      `json:"total_code_lines"`
	HasTests              bool     `json:"has_tests"`
}

// DeploymentStep is one stage of the deployment check.
type DeploymentStep struct {
	Name       string  `json:"name"`
	Command    string  `json:"command"`
	Success    bool    `json:"success"`
	Duration   float64 `json:"duration_seconds"`
	OutputTail string  `json:"output_tail"`
}

// DeploymentReport summarizes the deployment engine outcome.
type DeploymentReport struct {
	BuildAttempted         bool             `json:"build_attempted"`
	BuildSucceeded         bool             `json:"build_succeeded"`
	SmokeAttempted         bool             `json:"smoke_attempted"`
	SmokeSucceeded         bool             `json:"smoke_succeeded"`
	DependencyResolutionOK bool             `json:"dependency_resolution_ok"`
	Steps                  []DeploymentStep `json:"steps"`
}

// EngineResult is the uniform envelope returned by every scanner endpoint.
type EngineResult struct {
	Engine           string            `json:"engine"`
	Pillar           string            `json:"pillar"`
	Status           string            `json:"status"`
	Findings         []Finding         `json:"findings"`
	Summary          SeveritySummary   `json:"summary"`
	QualityMetrics   *QualityMetrics   `json:"quality_metrics"`
	DeploymentReport *DeploymentReport `json:"deployment_report"`
	Raw              map[string]any    `json:"raw"`
	DurationSeconds  float64           `json:"duration_seconds"`
	ScanID           string            `json:"scan_id"`
	Error            string            `json:"error"`
	RulePackVersion  string            `json:"rule_pack_version"`

	// Degradation (D1): the engine ran but not at full coverage (e.g. a broken
	// custom rule pack fell back to registry rules). Distinct from Status=failed.
	Degraded       bool   `json:"degraded"`
	DegradedReason string `json:"degraded_reason"`
	CoverageLost   string `json:"coverage_lost"`

	// Secret precision (P1): counts of matches SUPPRESSED as definitively-not-a-secret
	// (placeholder shape, expired JWT). Surfaced so the scan can report "N filtered"
	// instead of silently dropping them. nil/empty when nothing was filtered.
	FilteredSecrets map[string]int `json:"filtered_secrets"`

	// Bundled/minified third-party JS/TS EXCLUDED from SAST (T2). Surfaced so the
	// exclusion is visible, never a silent skip. SCA + vendored fingerprinting still
	// scan these files. nil when nothing was excluded.
	ExcludedBundled *ExcludedBundled `json:"excluded_bundled"`

	// Lifecycle evidence (N1): the semgrep rule ids that actually ran on this scan,
	// and every rule id Aegis ships. A finding may only be marked resolved by a scan
	// whose detector ran; see store.applyLifecycle. nil for engines without per-rule
	// sets and for scanners that predate N1 (treated as "every rule ran").
	RulesExecuted []string `json:"rules_executed"`
	RulesShipped  []string `json:"rules_shipped"`

	// Per-language SAST coverage (N2). nil for engines that are not language-scoped
	// and for scanners predating N2.
	SecurityCoverage *SecurityCoverage `json:"security_coverage"`
}

// SecurityCoverage is how much of a repository's code our shipped rules can actually
// see (N2, scanner utils/rule_coverage.py). A repository written mostly in a language
// we cover thinly yields few findings, and few findings read as "clean" -- so when
// Confident is false the security score and rating are withheld (NULL, "Not measured")
// and the overall renders PARTIAL with Gap as its qualifier. Same contract as a
// degraded engine (P4b/C1); thin coverage is a known limit, not a malfunction, so it
// does not claim an engine failed.
type SecurityCoverage struct {
	TotalCodeLines    int                `json:"total_code_lines"`
	StrongFraction    float64            `json:"strong_fraction"`
	LimitedFraction   float64            `json:"limited_fraction"`
	UncoveredFraction float64            `json:"uncovered_fraction"`
	Confident         bool               `json:"confident"`
	Threshold         float64            `json:"threshold"`
	Languages         []LanguageCoverage `json:"languages"`
	Summary           string             `json:"summary"`
	Gap               string             `json:"gap"`
	AlwaysOn          []string           `json:"always_on"`
	// N6: two claims, two gates. CleanClaim: the repository's code is mostly in
	// languages whose RECALL is certified (a clean result may be shown). ProblemClaim:
	// mostly in languages whose PRECISION is certified (reported issues are trusted).
	// Quadrant is full | problem-only | clean-only | withheld. Empty on pre-N6 scans,
	// which fall back to Confident (full or withheld).
	RecallFraction    float64 `json:"recall_fraction"`
	PrecisionFraction float64 `json:"precision_fraction"`
	CleanClaim        bool    `json:"clean_claim"`
	ProblemClaim      bool    `json:"problem_claim"`
	Quadrant          string  `json:"quadrant"`
	// CleanLabel replaces a favourable grade the recall cannot certify:
	// "No issues found in what we check · PHP 42% held-out recall".
	CleanLabel string `json:"clean_label"`
	// PrecisionCaveat travels with findings whose precision is not certified.
	PrecisionCaveat string `json:"precision_caveat"`
	// PartiallyAnalysed (D2): files semgrep stopped analysing on a time limit in this
	// run, so their findings can differ between scans of the same commit. Disclosed,
	// never silent; nil when the analysis was complete.
	PartiallyAnalysed *PartialAnalysis `json:"partially_analysed,omitempty"`
}

// PartialAnalysis is the scanner's semgrep_engine.partial_analysis.
type PartialAnalysis struct {
	Files            int      `json:"files"`
	FixpointTimeouts int      `json:"fixpoint_timeouts"`
	RuleTimeouts     int      `json:"rule_timeouts"`
	Sample           []string `json:"sample"`
	Reason           string   `json:"reason"`
}

// Coverage quadrants (scanner utils/tier_bar.py).
const (
	QuadrantFull     = "full"
	QuadrantProblem  = "problem-only"
	QuadrantClean    = "clean-only"
	QuadrantWithheld = "withheld"
)

// EffectiveQuadrant is the coverage's quadrant, falling back to Confident for scans
// from scanners that predate N6. A nil coverage (no application code) is full: there
// is nothing our rules failed to read.
func (c *SecurityCoverage) EffectiveQuadrant() string {
	if c == nil {
		return QuadrantFull
	}
	switch c.Quadrant {
	case QuadrantFull, QuadrantProblem, QuadrantClean, QuadrantWithheld:
		return c.Quadrant
	}
	if c.Confident {
		return QuadrantFull
	}
	return QuadrantWithheld
}

// LanguageCoverage is one language's share of the repository and how well we cover it.
type LanguageCoverage struct {
	Language   string  `json:"language"`
	Tier       string  `json:"tier"` // strong | limited | none
	LOC        int     `json:"loc"`
	Share      float64 `json:"share"`
	Rules      int     `json:"rules"`
	CWEClasses int     `json:"cwe_classes"`
	// The measured evidence behind the tier (N5). Carried through untouched: before
	// N6 this struct had no field for it, so the orchestrator dropped it and the web's
	// per-language evidence never reached a real scan.
	Evidence json.RawMessage `json:"evidence,omitempty"`
}

// LifecycleEvidence records which detectors actually ran on a scan, so lifecycle
// never records "we stopped looking" as "it was fixed" (N1). A finding absent from
// a scan is RESOLVED only when its engine completed and, where the engine reports
// per-rule sets, its rule executed. Its rule no longer shipping makes it RETIRED
// (neither open nor fixed). Anything else -- engine failed, skipped, or not run;
// rule shipped but not executed -- leaves it untouched.
type LifecycleEvidence struct {
	// Completed is keyed by the engine name findings carry (state rows use it).
	Completed map[string]bool
	// RulesExecuted / RulesShipped: engine -> rule id set. An engine absent from
	// RulesExecuted has no per-rule reporting (or predates N1): all its rules count
	// as executed and none as retired -- the pre-N1 behaviour, deliberately.
	RulesExecuted map[string]map[string]bool
	RulesShipped  map[string]map[string]bool
}

// ExcludedBundled summarizes the bundled/minified third-party JS/TS files that SAST
// skipped (T2): count, total bytes, per-reason counts, and a capped sample of paths.
type ExcludedBundled struct {
	Files   int            `json:"files"`
	Bytes   int64          `json:"bytes"`
	Reasons map[string]int `json:"reasons"`
	Sample  []string       `json:"sample"`
}

// DegradedEngine is one scan-level degradation: an engine that ran but lost
// coverage, or failed outright. Surfaced so a partial scan is never read as clean.
type DegradedEngine struct {
	Engine       string `json:"engine"`
	Reason       string `json:"reason"`
	CoverageLost string `json:"coverage_lost"`
}
