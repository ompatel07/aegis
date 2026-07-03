package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/jmoiron/sqlx"

	"github.com/aegis-platform/api/internal/models"
)

// ProjectRepository handles persistence for projects.
type ProjectRepository struct {
	db *sqlx.DB
}

func NewProjectRepository(db *sqlx.DB) *ProjectRepository {
	return &ProjectRepository{db: db}
}

func (r *ProjectRepository) Create(ctx context.Context, p *models.Project) error {
	const q = `
		INSERT INTO projects (user_id, name, slug, description, repo_url, repo_type, default_branch, language)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at, updated_at`
	err := r.db.QueryRowxContext(ctx, q,
		p.UserID, p.Name, p.Slug, p.Description, p.RepoURL, p.RepoType, p.DefaultBranch, p.Language,
	).Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate key") {
			return ErrConflict
		}
		return err
	}
	return nil
}

// GetByIDForUser enforces ownership: a project is only visible to its owner.
func (r *ProjectRepository) GetByIDForUser(ctx context.Context, id, userID string) (*models.Project, error) {
	const q = `SELECT * FROM projects WHERE id = $1 AND user_id = $2`
	var p models.Project
	if err := r.db.GetContext(ctx, &p, q, id, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &p, nil
}

// GetByID loads a project regardless of owner (internal use, e.g. webhooks).
func (r *ProjectRepository) GetByID(ctx context.Context, id string) (*models.Project, error) {
	const q = `SELECT * FROM projects WHERE id = $1`
	var p models.Project
	if err := r.db.GetContext(ctx, &p, q, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &p, nil
}

// ListByUser returns a page of a user's projects plus the total count.
func (r *ProjectRepository) ListByUser(ctx context.Context, userID string, limit, offset int) ([]models.Project, int, error) {
	const countQ = `SELECT COUNT(*) FROM projects WHERE user_id = $1`
	var total int
	if err := r.db.GetContext(ctx, &total, countQ, userID); err != nil {
		return nil, 0, err
	}

	const q = `
		SELECT * FROM projects
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`
	projects := []models.Project{}
	if err := r.db.SelectContext(ctx, &projects, q, userID, limit, offset); err != nil {
		return nil, 0, err
	}
	return projects, total, nil
}

// Update modifies mutable fields of a project owned by userID.
func (r *ProjectRepository) Update(ctx context.Context, p *models.Project) error {
	const q = `
		UPDATE projects
		SET name = $1, description = $2, repo_url = $3, repo_type = $4,
		    default_branch = $5, language = $6, ai_fix_enabled = $7
		WHERE id = $8 AND user_id = $9
		RETURNING updated_at`
	err := r.db.QueryRowxContext(ctx, q,
		p.Name, p.Description, p.RepoURL, p.RepoType, p.DefaultBranch, p.Language, p.AIFixEnabled, p.ID, p.UserID,
	).Scan(&p.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

// Delete removes a project owned by userID (cascades to scans + findings).
func (r *ProjectRepository) Delete(ctx context.Context, id, userID string) error {
	const q = `DELETE FROM projects WHERE id = $1 AND user_id = $2`
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
