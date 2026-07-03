package models

import (
	"time"
)

// Pillar / engine / severity enumerations (mirror DB CHECK constraints).
const (
	PillarQuality    = "quality"
	PillarSecurity   = "security"
	PillarDeployment = "deployment"

	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Finding is a single normalized issue produced by any engine.
type Finding struct {
	ID          string  `db:"id" json:"id"`
	ScanID      string  `db:"scan_id" json:"scan_id"`
	Pillar      string  `db:"pillar" json:"pillar"`
	Engine      string  `db:"engine" json:"engine"`
	RuleID      string  `db:"rule_id" json:"rule_id"`
	RuleName    string  `db:"rule_name" json:"rule_name"`
	Severity    string  `db:"severity" json:"severity"`
	Title       string  `db:"title" json:"title"`
	Description *string `db:"description" json:"description,omitempty"`

	FilePath    string `db:"file_path" json:"file_path"`
	LineStart   *int   `db:"line_start" json:"line_start,omitempty"`
	LineEnd     *int   `db:"line_end" json:"line_end,omitempty"`
	ColumnStart *int   `db:"column_start" json:"column_start,omitempty"`
	ColumnEnd   *int   `db:"column_end" json:"column_end,omitempty"`

	CWEID         *string `db:"cwe_id" json:"cwe_id,omitempty"`
	CVEID         *string `db:"cve_id" json:"cve_id,omitempty"`
	OWASPCategory *string `db:"owasp_category" json:"owasp_category,omitempty"`

	IsFalsePositive bool    `db:"is_false_positive" json:"is_false_positive"`
	IsSuppressed    bool    `db:"is_suppressed" json:"is_suppressed"`
	FixSuggestion   *string `db:"fix_suggestion" json:"fix_suggestion,omitempty"`
	Metadata        JSONB   `db:"metadata" json:"metadata,omitempty"`

	// Context-rich enrichment (Phase 2B).
	TitleHuman         *string `db:"title_human" json:"title_human,omitempty"`
	Impact             *string `db:"impact" json:"impact,omitempty"`
	RiskLevel          *string `db:"risk_level" json:"risk_level,omitempty"`
	RemediationAction  *string `db:"remediation_action" json:"remediation_action,omitempty"`
	RemediationDetails *string `db:"remediation_details" json:"remediation_details,omitempty"`
	EstimatedEffort    *string `db:"estimated_effort" json:"estimated_effort,omitempty"`
	ContextMetadata    JSONB   `db:"context_metadata" json:"context_metadata,omitempty"`

	// Local ML false-positive filter output (advisory: sorts + badge, never hides).
	FalsePositiveProbability *float64 `db:"false_positive_probability" json:"false_positive_probability,omitempty"`

	CreatedAt time.Time `db:"created_at" json:"created_at"`
}
