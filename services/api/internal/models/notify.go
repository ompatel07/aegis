package models

import "time"

// NotificationSettings holds a user's per-event email preferences.
type NotificationSettings struct {
	UserID            string    `db:"user_id" json:"user_id"`
	EmailEnabled      bool      `db:"email_enabled" json:"email_enabled"`
	EmailScanComplete bool      `db:"email_scan_complete" json:"email_scan_complete"`
	EmailNewCritical  bool      `db:"email_new_critical" json:"email_new_critical"`
	DigestFrequency   string    `db:"digest_frequency" json:"digest_frequency"` // daily|weekly|never
	SeverityThreshold string    `db:"severity_threshold" json:"severity_threshold"`
	UpdatedAt         time.Time `db:"updated_at" json:"updated_at"`
}

// ProjectSlack is a project's Slack incoming-webhook routing.
type ProjectSlack struct {
	ProjectID   string    `db:"project_id" json:"project_id"`
	WebhookURL  string    `db:"webhook_url" json:"webhook_url"`
	Enabled     bool      `db:"enabled" json:"enabled"`
	MinSeverity string    `db:"min_severity" json:"min_severity"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
}
