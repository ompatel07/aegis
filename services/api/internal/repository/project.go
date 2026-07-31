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
		INSERT INTO projects (user_id, organization_id, name, slug, description, repo_url, repo_type, default_branch, language)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at, updated_at`
	err := r.db.QueryRowxContext(ctx, q,
		p.UserID, p.OrganizationID, p.Name, p.Slug, p.Description, p.RepoURL, p.RepoType, p.DefaultBranch, p.Language,
	).Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate key") {
			return ErrConflict
		}
		return err
	}
	return nil
}

// GetByIDForUser enforces access: a project is visible to members of its org.
func (r *ProjectRepository) GetByIDForUser(ctx context.Context, id, userID string) (*models.Project, error) {
	const q = `SELECT * FROM projects
		WHERE id = $1
		  AND organization_id IN (SELECT org_id FROM organization_members WHERE user_id = $2)`
	var p models.Project
	if err := r.db.GetContext(ctx, &p, q, id, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &p, nil
}

// RoleInProjectOrg returns the caller's role in the project's owning org, or
// ErrNotFound if the project does not exist or the caller is not a member of its
// org. Callers use this to gate write actions on a minimum role while keeping
// cross-tenant isolation: a non-member is indistinguishable from a missing
// project (both ErrNotFound → 404, no existence leak).
func (r *ProjectRepository) RoleInProjectOrg(ctx context.Context, projectID, userID string) (string, error) {
	const q = `SELECT om.role
		FROM projects p
		JOIN organization_members om ON om.org_id = p.organization_id
		WHERE p.id = $1 AND om.user_id = $2`
	var role string
	if err := r.db.GetContext(ctx, &role, q, projectID, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return role, nil
}

// FindIDByRepo returns a project id whose repo_url contains the given repo
// full name (owner/name) — used to route GitHub App webhooks to a project.
func (r *ProjectRepository) FindIDByRepo(ctx context.Context, fullName string) (string, error) {
	var id string
	err := r.db.GetContext(ctx, &id,
		`SELECT id FROM projects WHERE repo_url ILIKE '%' || $1 || '%' ORDER BY created_at ASC LIMIT 1`, fullName)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return id, err
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
	const countQ = `SELECT COUNT(*) FROM projects
		WHERE organization_id IN (SELECT org_id FROM organization_members WHERE user_id = $1)`
	var total int
	if err := r.db.GetContext(ctx, &total, countQ, userID); err != nil {
		return nil, 0, err
	}

	const q = `
		SELECT * FROM projects
		WHERE organization_id IN (SELECT org_id FROM organization_members WHERE user_id = $1)
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
		    default_branch = $5, language = $6, ai_fix_enabled = $7, grandfather_mode = $8
		WHERE id = $9
		  AND organization_id IN (SELECT org_id FROM organization_members
		                          WHERE user_id = $10 AND role IN ('owner','admin','member'))
		RETURNING updated_at`
	err := r.db.QueryRowxContext(ctx, q,
		p.Name, p.Description, p.RepoURL, p.RepoType, p.DefaultBranch, p.Language,
		p.AIFixEnabled, p.GrandfatherMode, p.ID, p.UserID,
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
	const q = `DELETE FROM projects
		WHERE id = $1
		  AND organization_id IN (SELECT org_id FROM organization_members
		                          WHERE user_id = $2 AND role IN ('owner','admin','member'))`
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
