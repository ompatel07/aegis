package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jmoiron/sqlx"

	"github.com/aegis-platform/api/internal/models"
)

// scanColumns lists the scalar scan columns. We avoid SELECT * because the
// table also has raw_* JSONB columns that the API's Scan model deliberately omits.
const scanColumns = `
	id, project_id, trigger, status, branch, commit_sha,
	quality_score, security_score, deployment_score, overall_score, overall_grade,
	quality_issues_total, security_issues_total, secrets_found, vulnerabilities_found,
	queued_at, started_at, completed_at, duration_seconds, error_message, created_at`

// ScanRepository handles persistence for scans.
type ScanRepository struct {
	db *sqlx.DB
}

func NewScanRepository(db *sqlx.DB) *ScanRepository {
	return &ScanRepository{db: db}
}

// Create inserts a queued scan and populates generated columns.
func (r *ScanRepository) Create(ctx context.Context, s *models.Scan) error {
	const q = `
		INSERT INTO scans (project_id, trigger, status, branch, commit_sha)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, status, queued_at, created_at`
	return r.db.QueryRowxContext(ctx, q,
		s.ProjectID, s.Trigger, s.Status, s.Branch, s.CommitSHA,
	).Scan(&s.ID, &s.Status, &s.QueuedAt, &s.CreatedAt)
}

// MarkFailed transitions a scan to the failed state with an error message.
// Used by the API when a job cannot be enqueued.
func (r *ScanRepository) MarkFailed(ctx context.Context, id, msg string) error {
	const q = `
		UPDATE scans
		SET status = 'failed', error_message = $2, completed_at = now()
		WHERE id = $1`
	_, err := r.db.ExecContext(ctx, q, id, msg)
	return err
}

// GetByIDForUser loads a scan, enforcing ownership through the project.
func (r *ScanRepository) GetByIDForUser(ctx context.Context, id, userID string) (*models.Scan, error) {
	q := `
		SELECT ` + scanColumns + `
		FROM scans s
		JOIN projects p ON p.id = s.project_id
		WHERE s.id = $1 AND p.user_id = $2`
	var s models.Scan
	if err := r.db.GetContext(ctx, &s, q, id, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &s, nil
}

// ListByProject returns a page of scans for a project plus the total count.
func (r *ScanRepository) ListByProject(ctx context.Context, projectID string, limit, offset int) ([]models.Scan, int, error) {
	const countQ = `SELECT COUNT(*) FROM scans WHERE project_id = $1`
	var total int
	if err := r.db.GetContext(ctx, &total, countQ, projectID); err != nil {
		return nil, 0, err
	}

	q := `
		SELECT ` + scanColumns + `
		FROM scans
		WHERE project_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`
	scans := []models.Scan{}
	if err := r.db.SelectContext(ctx, &scans, q, projectID, limit, offset); err != nil {
		return nil, 0, err
	}
	return scans, total, nil
}
