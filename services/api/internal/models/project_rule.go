package models

import "time"

// ProjectRule is a customer-supplied Semgrep rule applied to one project's scans
// in addition to the registry + Aegis rule packs.
type ProjectRule struct {
	ID        string    `db:"id" json:"id"`
	ProjectID string    `db:"project_id" json:"project_id"`
	Name      string    `db:"name" json:"name"`
	RuleYAML  string    `db:"rule_yaml" json:"rule_yaml"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}
