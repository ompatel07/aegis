package models

import (
	"encoding/json"
	"time"
)

// Scan trigger + status enumerations (mirror DB CHECK constraints).
const (
	TriggerManual    = "manual"
	TriggerWebhook   = "webhook"
	TriggerScheduled = "scheduled"

	StatusQueued    = "queued"
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
)

// Scan is one run of the two-pillar pipeline (Security + Code Quality; deployment
// is CI-mode only). Score fields are nullable until the
// scan completes, so they are pointers and omitted from JSON when absent.
type Scan struct {
	ID        string  `db:"id" json:"id"`
	ProjectID string  `db:"project_id" json:"project_id"`
	Trigger   string  `db:"trigger" json:"trigger"`
	Status    string  `db:"status" json:"status"`
	Branch    *string `db:"branch" json:"branch,omitempty"`
	CommitSHA *string `db:"commit_sha" json:"commit_sha,omitempty"`

	QualityScore    *int    `db:"quality_score" json:"quality_score,omitempty"`
	SecurityScore   *int    `db:"security_score" json:"security_score,omitempty"`
	DeploymentScore *int    `db:"deployment_score" json:"deployment_score,omitempty"`
	OverallScore    *int    `db:"overall_score" json:"overall_score,omitempty"`
	OverallGrade    *string `db:"overall_grade" json:"overall_grade,omitempty"`

	// SonarQube-style A–E ratings (P2c). nil = NOT MEASURED (omitted from JSON; the
	// web renders "Not measured", never a blank or a fabricated A).
	ReliabilityRating     *string `db:"reliability_rating" json:"reliability_rating,omitempty"`
	SecurityRating        *string `db:"security_rating" json:"security_rating,omitempty"`
	MaintainabilityRating *string `db:"maintainability_rating" json:"maintainability_rating,omitempty"`

	// Scan-level degradation (D1): [{engine, reason, coverage_lost}]. Non-empty means
	// the scan is DEGRADED — engines ran without full coverage, or failed.
	EnginesDegraded json.RawMessage `db:"engines_degraded" json:"engines_degraded"`

	QualityIssuesTotal   int `db:"quality_issues_total" json:"quality_issues_total"`
	SecurityIssuesTotal  int `db:"security_issues_total" json:"security_issues_total"`
	SecretsFound         int `db:"secrets_found" json:"secrets_found"`
	VulnerabilitiesFound int `db:"vulnerabilities_found" json:"vulnerabilities_found"`

	QueuedAt        time.Time  `db:"queued_at" json:"queued_at"`
	StartedAt       *time.Time `db:"started_at" json:"started_at,omitempty"`
	CompletedAt     *time.Time `db:"completed_at" json:"completed_at,omitempty"`
	DurationSeconds *int       `db:"duration_seconds" json:"duration_seconds,omitempty"`

	ErrorMessage *string `db:"error_message" json:"error_message,omitempty"`

	// Live pipeline stage (Phase 2C TASK 6): cloning|detecting|scanning|…|completed.
	Stage *string `db:"stage" json:"stage,omitempty"`

	// Phase 2B: rule reproducibility + retroactive re-evaluation.
	RulePackVersion *string `db:"rule_pack_version" json:"rule_pack_version,omitempty"`
	NeedsReeval     bool    `db:"needs_reeval" json:"needs_reeval"`
	ReevalReason    *string `db:"reeval_reason" json:"reeval_reason,omitempty"`

	// Phase 2C: AI-generated-code analysis.

	CreatedAt time.Time `db:"created_at" json:"created_at"`
}
