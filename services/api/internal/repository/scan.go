package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jmoiron/sqlx"

	"github.com/aegis-platform/api/internal/models"
)

// scanColumns lists the scalar scan columns, qualified with the `s` alias so
// the list is safe inside JOINs (scans and projects share column names like
// `id` and `created_at`). We avoid SELECT * because the table also has raw_*
// JSONB columns that the API's Scan model deliberately omits. Postgres strips
// the `s.` qualifier from result column names, so sqlx StructScan still maps them.
const scanColumns = `
	s.id, s.project_id, s.trigger, s.status, s.branch, s.commit_sha,
	s.quality_score, s.security_score, s.deployment_score, s.overall_score, s.overall_grade,
	s.quality_issues_total, s.security_issues_total, s.secrets_found, s.vulnerabilities_found,
	s.queued_at, s.started_at, s.completed_at, s.duration_seconds, s.error_message, s.created_at,
	s.rule_pack_version, s.needs_reeval, s.reeval_reason, s.stage`

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
		WHERE s.id = $1 AND p.organization_id IN (SELECT org_id FROM organization_members WHERE user_id = $2)`
	var s models.Scan
	if err := r.db.GetContext(ctx, &s, q, id, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &s, nil
}

// GetByID loads a scan without ownership checks (internal use: webhooks, PR
// finalization). Callers must not expose it to unauthenticated users directly.
func (r *ScanRepository) GetByID(ctx context.Context, id string) (*models.Scan, error) {
	q := `SELECT ` + scanColumns + ` FROM scans s WHERE s.id = $1`
	var s models.Scan
	if err := r.db.GetContext(ctx, &s, q, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &s, nil
}

// PreviousCompleted returns the most recent completed scan of a project before
// the given time — for trend comparison. Returns ErrNotFound if there is none.
func (r *ScanRepository) PreviousCompleted(ctx context.Context, projectID string, before interface{}) (*models.Scan, error) {
	q := `
		SELECT ` + scanColumns + `
		FROM scans s
		WHERE s.project_id = $1 AND s.status = 'completed' AND s.created_at < $2
		ORDER BY s.created_at DESC
		LIMIT 1`
	var s models.Scan
	if err := r.db.GetContext(ctx, &s, q, projectID, before); err != nil {
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
		FROM scans s
		WHERE s.project_id = $1
		ORDER BY s.created_at DESC
		LIMIT $2 OFFSET $3`
	scans := []models.Scan{}
	if err := r.db.SelectContext(ctx, &scans, q, projectID, limit, offset); err != nil {
		return nil, 0, err
	}
	return scans, total, nil
}

// GetSBOM returns the stored SBOM document for a scan in the given format
// (cyclonedx | spdx), or ErrNotFound if none was generated (e.g. no lockfile).
func (r *ScanRepository) GetSBOM(ctx context.Context, scanID, format string) (string, error) {
	col := map[string]string{"cyclonedx": "cyclonedx", "spdx": "spdx"}[format]
	if col == "" {
		return "", ErrNotFound
	}
	var content sql.NullString
	err := r.db.GetContext(ctx, &content, `SELECT `+col+` FROM scan_sboms WHERE scan_id = $1`, scanID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (!content.Valid || content.String == "")) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return content.String, nil
}
