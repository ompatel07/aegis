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
