package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jmoiron/sqlx"

	"github.com/aegis-platform/api/internal/models"
)

// NotifyRepository persists notification settings + drives dispatch.
type NotifyRepository struct {
	db *sqlx.DB
}

func NewNotifyRepository(db *sqlx.DB) *NotifyRepository { return &NotifyRepository{db: db} }

// GetSettings returns a user's settings, or defaults when none are stored.
func (r *NotifyRepository) GetSettings(ctx context.Context, userID string) (*models.NotificationSettings, error) {
	var s models.NotificationSettings
	err := r.db.GetContext(ctx, &s, `SELECT * FROM notification_settings WHERE user_id = $1`, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return &models.NotificationSettings{
			UserID: userID, EmailEnabled: true, EmailScanComplete: false, EmailNewCritical: true,
			DigestFrequency: "weekly", SeverityThreshold: "high",
		}, nil
	}
	return &s, err
}

func (r *NotifyRepository) UpsertSettings(ctx context.Context, s *models.NotificationSettings) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO notification_settings (user_id, email_enabled, email_scan_complete, email_new_critical, digest_frequency, severity_threshold, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6, now())
		ON CONFLICT (user_id) DO UPDATE SET
			email_enabled = EXCLUDED.email_enabled, email_scan_complete = EXCLUDED.email_scan_complete,
			email_new_critical = EXCLUDED.email_new_critical, digest_frequency = EXCLUDED.digest_frequency,
			severity_threshold = EXCLUDED.severity_threshold, updated_at = now()`,
		s.UserID, s.EmailEnabled, s.EmailScanComplete, s.EmailNewCritical, s.DigestFrequency, s.SeverityThreshold)
	return err
}

func (r *NotifyRepository) GetProjectSlack(ctx context.Context, projectID string) (*models.ProjectSlack, error) {
	var s models.ProjectSlack
	err := r.db.GetContext(ctx, &s, `SELECT * FROM project_slack WHERE project_id = $1`, projectID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &s, err
}

func (r *NotifyRepository) SetProjectSlack(ctx context.Context, projectID, webhookURL string, enabled bool, minSeverity string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO project_slack (project_id, webhook_url, enabled, min_severity, updated_at)
		VALUES ($1,$2,$3,$4, now())
		ON CONFLICT (project_id) DO UPDATE SET
			webhook_url = EXCLUDED.webhook_url, enabled = EXCLUDED.enabled,
			min_severity = EXCLUDED.min_severity, updated_at = now()`,
		projectID, webhookURL, enabled, minSeverity)
	return err
}

// ScanNotifyRow is a completed scan awaiting notification dispatch.
type ScanNotifyRow struct {
	ScanID      string `db:"scan_id"`
	ProjectID   string `db:"project_id"`
	ProjectName string `db:"project_name"`
	OrgID       string `db:"org_id"`
}

// UndeliveredScans returns completed scans not yet notified (notified_at NULL).
func (r *NotifyRepository) UndeliveredScans(ctx context.Context, limit int) ([]ScanNotifyRow, error) {
	out := []ScanNotifyRow{}
	err := r.db.SelectContext(ctx, &out, `
		SELECT s.id AS scan_id, p.id AS project_id, p.name AS project_name, COALESCE(p.organization_id::text,'') AS org_id
		  FROM scans s
		  JOIN projects p ON p.id = s.project_id
		 WHERE s.status = 'completed' AND s.notified_at IS NULL
		 ORDER BY s.completed_at ASC LIMIT $1`, limit)
	return out, err
}

func (r *NotifyRepository) MarkNotified(ctx context.Context, scanID string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE scans SET notified_at = now() WHERE id = $1`, scanID)
	return err
}

// Recipient is an org member + their notification settings.
type Recipient struct {
	Email             string `db:"email"`
	EmailEnabled      bool   `db:"email_enabled"`
	EmailScanComplete bool   `db:"email_scan_complete"`
	EmailNewCritical  bool   `db:"email_new_critical"`
}

// Recipients returns an org's members with their (defaulted) notification prefs.
func (r *NotifyRepository) Recipients(ctx context.Context, orgID string) ([]Recipient, error) {
	out := []Recipient{}
	err := r.db.SelectContext(ctx, &out, `
		SELECT u.email,
		       COALESCE(ns.email_enabled, TRUE)        AS email_enabled,
		       COALESCE(ns.email_scan_complete, FALSE) AS email_scan_complete,
		       COALESCE(ns.email_new_critical, TRUE)   AS email_new_critical
		  FROM organization_members m
		  JOIN users u ON u.id = m.user_id
		  LEFT JOIN notification_settings ns ON ns.user_id = u.id
		 WHERE m.org_id = $1`, orgID)
	return out, err
}
