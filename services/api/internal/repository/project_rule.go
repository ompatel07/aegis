package repository

import (
	"context"

	"github.com/jmoiron/sqlx"

	"github.com/aegis-platform/api/internal/models"
)

// ProjectRuleRepository persists per-project custom Semgrep rules.
type ProjectRuleRepository struct {
	db *sqlx.DB
}

func NewProjectRuleRepository(db *sqlx.DB) *ProjectRuleRepository {
	return &ProjectRuleRepository{db: db}
}

func (r *ProjectRuleRepository) Create(ctx context.Context, pr *models.ProjectRule) error {
	return r.db.QueryRowxContext(ctx,
		`INSERT INTO project_rules (project_id, name, rule_yaml)
		 VALUES ($1, $2, $3) RETURNING id, created_at`,
		pr.ProjectID, pr.Name, pr.RuleYAML,
	).Scan(&pr.ID, &pr.CreatedAt)
}

// ListByProjectForUser returns a project's rules (ownership-checked). rule_yaml
// is included so the dashboard can show it.
func (r *ProjectRuleRepository) ListByProjectForUser(ctx context.Context, projectID, userID string) ([]models.ProjectRule, error) {
	out := []models.ProjectRule{}
	err := r.db.SelectContext(ctx, &out,
		`SELECT pr.id, pr.project_id, pr.name, pr.rule_yaml, pr.created_at
		   FROM project_rules pr
		   JOIN projects p ON p.id = pr.project_id
		  WHERE pr.project_id = $1 AND p.user_id = $2
		  ORDER BY pr.created_at DESC`,
		projectID, userID)
	return out, err
}

// YAMLForProject returns just the rule bodies for a project — used at scan time
// (internal; the caller has already resolved the project).
func (r *ProjectRuleRepository) YAMLForProject(ctx context.Context, projectID string) ([]string, error) {
	out := []string{}
	err := r.db.SelectContext(ctx, &out,
		`SELECT rule_yaml FROM project_rules WHERE project_id = $1 ORDER BY created_at`, projectID)
	return out, err
}

func (r *ProjectRuleRepository) DeleteByIDForUser(ctx context.Context, id, userID string) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM project_rules pr USING projects p
		  WHERE pr.id = $1 AND p.id = pr.project_id AND p.user_id = $2`,
		id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
