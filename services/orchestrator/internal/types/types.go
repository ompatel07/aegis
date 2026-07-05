// Package types holds the shared data shapes exchanged with the scanner service
// and passed between the orchestrator's pipeline, aggregator, and scorers.
//
// These mirror the scanner's Pydantic models (services/scanner/models). Field
// names match the scanner's JSON so unmarshaling is direct.
package types

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

	// AI-generated-code tagging (Phase 2C), set by the orchestrator from the
	// AI-code pass's per-file scores.
	InAIGeneratedCode      bool     `json:"in_ai_generated_code"`
	AIGeneratedProbability *float64 `json:"ai_generated_probability"`

	// IsNew: this finding deviates from the project baseline (its rule was not
	// seen before). Set by the orchestrator's baseline pass (Phase 2C TASK 4).
	IsNew bool `json:"is_new"`
}

// AICodeResult mirrors the scanner's AI-generated-code analysis for a repo.
type AICodeResult struct {
	Status          string             `json:"status"`
	FilesScored     int                `json:"files_scored"`
	AIFileCount     int                `json:"ai_file_count"`
	AIGeneratedPct  float64            `json:"ai_generated_pct"`
	Threshold       float64            `json:"threshold"`
	ModelAvailable  bool               `json:"model_available"`
	FileScores      map[string]float64 `json:"file_scores"`
	TopSignals      []string           `json:"top_signals"`
	DurationSeconds float64            `json:"duration_seconds"`
	Error           string             `json:"error"`
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
	ComplexityScore       float64 `json:"complexity_score"`
	DuplicationScore      float64 `json:"duplication_score"`
	MaintainabilityScore  float64 `json:"maintainability_score"`
	TestCoverageScore     float64 `json:"test_coverage_score"`
	DocumentationScore    float64 `json:"documentation_score"`
	AvgCyclomatic         float64 `json:"avg_cyclomatic_complexity"`
	MaxCyclomatic         int     `json:"max_cyclomatic_complexity"`
	DuplicatedLinePercent float64 `json:"duplicated_line_percentage"`
	CommentDensity        float64 `json:"comment_density"`
	TotalFunctions        int     `json:"total_functions"`
	TotalCodeLines        int     `json:"total_code_lines"`
	HasTests              bool    `json:"has_tests"`
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
}
