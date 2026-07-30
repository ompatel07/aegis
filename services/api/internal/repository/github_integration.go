package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jmoiron/sqlx"

	"github.com/aegis-platform/api/internal/models"
)

// GithubIntegrationRepository reads/writes the github_integrations table.
type GithubIntegrationRepository struct {
	db *sqlx.DB
}

func NewGithubIntegrationRepository(db *sqlx.DB) *GithubIntegrationRepository {
	return &GithubIntegrationRepository{db: db}
}

// FindByRepoURLs resolves the integration whose project's repo_url matches one
// of the candidate URLs (GitHub sends both an html_url and a clone_url). Used by
// the webhook handler to obtain the per-project secret before verifying HMAC.
func (r *GithubIntegrationRepository) FindByRepoURLs(ctx context.Context, url1, url2 string) (*models.GithubIntegration, error) {
	const q = `
		SELECT gi.*
		FROM github_integrations gi
		JOIN projects p ON p.id = gi.project_id
		WHERE p.repo_url = $1 OR p.repo_url = $2
		LIMIT 1`
	var gi models.GithubIntegration
	if err := r.db.GetContext(ctx, &gi, q, url1, url2); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &gi, nil
}

// GetByProjectForUser returns the integration for a project the user owns.
func (r *GithubIntegrationRepository) GetByProjectForUser(ctx context.Context, projectID, userID string) (*models.GithubIntegration, error) {
	const q = `
		SELECT gi.*
		FROM github_integrations gi
		JOIN projects p ON p.id = gi.project_id
		WHERE gi.project_id = $1 AND p.organization_id IN (SELECT org_id FROM organization_members WHERE user_id = $2)`
	var gi models.GithubIntegration
	if err := r.db.GetContext(ctx, &gi, q, projectID, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &gi, nil
}

// GetByProject returns the integration for a project WITHOUT a user filter — for
// server-side use only (the scan worker resolving a clone credential). Access is
// already gated by project ownership at scan-trigger time.
func (r *GithubIntegrationRepository) GetByProject(ctx context.Context, projectID string) (*models.GithubIntegration, error) {
	var gi models.GithubIntegration
	if err := r.db.GetContext(ctx, &gi, `SELECT * FROM github_integrations WHERE project_id = $1`, projectID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &gi, nil
}

// DeleteByIDForUser removes an integration the user owns (via project ownership).
func (r *GithubIntegrationRepository) DeleteByIDForUser(ctx context.Context, id, userID string) error {
	const q = `
		DELETE FROM github_integrations gi
		USING projects p
		WHERE gi.id = $1 AND p.id = gi.project_id AND p.organization_id IN (SELECT org_id FROM organization_members WHERE user_id = $2)`
	res, err := r.db.ExecContext(ctx, q, id, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Upsert creates or replaces the integration for a project.
func (r *GithubIntegrationRepository) Upsert(ctx context.Context, gi *models.GithubIntegration) error {
	const q = `
		INSERT INTO github_integrations (user_id, project_id, installation_id, webhook_secret, access_token_encrypted)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (project_id) DO UPDATE
		SET installation_id = EXCLUDED.installation_id,
		    webhook_secret = EXCLUDED.webhook_secret,
		    access_token_encrypted = EXCLUDED.access_token_encrypted
		RETURNING id, created_at`
	return r.db.QueryRowxContext(ctx, q,
		gi.UserID, gi.ProjectID, gi.InstallationID, gi.WebhookSecret, gi.AccessTokenEncrypted,
	).Scan(&gi.ID, &gi.CreatedAt)
}
