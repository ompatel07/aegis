package models

import (
	"encoding/json"
	"time"
)

// PolicyConfig is the tunable gate configuration (stored as config_json). A zero
// value gates nothing; each set field adds a gate.
type PolicyConfig struct {
	// Fail if any (non-suppressed) finding is at or above this severity.
	MaxSeverity string `json:"max_severity,omitempty"`
	// Fail if ANY finding deviates from the baseline (grandfathering).
	BlockNewFindings bool `json:"block_new_findings,omitempty"`
	// Fail if any NEW finding is at or above this severity.
	BlockNewSeverity string `json:"block_new_severity,omitempty"`
	// Score floors (fail if the scan scores below).
	MinSecurityScore *int `json:"min_security_score,omitempty"`
	MinQualityScore  *int `json:"min_quality_score,omitempty"`
	MinAISafetyScore *int `json:"min_ai_safety_score,omitempty"`
	// Fail if the estimated share of AI-generated (unreviewed) code exceeds this %.
	MaxAIGeneratedPct *int `json:"max_ai_generated_pct,omitempty"`
}

// Policy is a stored, per-project gate configuration.
type Policy struct {
	ID         string    `db:"id" json:"id"`
	ProjectID  string    `db:"project_id" json:"project_id"`
	Name       string    `db:"name" json:"name"`
	Template   *string   `db:"template" json:"template,omitempty"`
	ConfigJSON JSONB     `db:"config_json" json:"config"`
	IsActive   bool      `db:"is_active" json:"is_active"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
	UpdatedAt  time.Time `db:"updated_at" json:"updated_at"`
}

// Config decodes the stored config_json.
func (p *Policy) Config() PolicyConfig {
	var c PolicyConfig
	if len(p.ConfigJSON) > 0 {
		_ = json.Unmarshal(p.ConfigJSON, &c)
	}
	return c
}

// PolicyCheck is one gate's result.
type PolicyCheck struct {
	Rule   string `json:"rule"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// PolicyEvaluation is a scan's evaluation against its project's active policy.
type PolicyEvaluation struct {
	ID        string        `db:"id" json:"id"`
	ScanID    string        `db:"scan_id" json:"scan_id"`
	PolicyID  *string       `db:"policy_id" json:"policy_id,omitempty"`
	Passed    bool          `db:"passed" json:"passed"`
	Reasons   []PolicyCheck `db:"-" json:"reasons"`
	CreatedAt time.Time     `db:"created_at" json:"created_at"`
}

// PolicyTemplates are the named presets offered in the UI.
var PolicyTemplates = map[string]PolicyConfig{
	// Permissive — only block newly-introduced critical vulns.
	"startup": {BlockNewSeverity: SeverityCritical},
	// Moderate — block new high+ findings and a security floor.
	"growing": {BlockNewSeverity: SeverityHigh, MinSecurityScore: intp(60)},
	// Strict — no new findings, solid score + AI-safety floors.
	"enterprise": {BlockNewFindings: true, MinSecurityScore: intp(80), MinAISafetyScore: intp(60)},
	// Maximum — nothing outside the approved baseline; tight AI limits.
	"compliance": {
		BlockNewFindings: true, MinSecurityScore: intp(90), MinQualityScore: intp(80),
		MinAISafetyScore: intp(70), MaxAIGeneratedPct: intp(10),
	},
}

func intp(i int) *int { return &i }
