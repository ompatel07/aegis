package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/jmoiron/sqlx"

	"github.com/aegis-platform/api/internal/models"
)

// PolicyRepository handles per-project policies + scan evaluations.
type PolicyRepository struct {
	db *sqlx.DB
}

func NewPolicyRepository(db *sqlx.DB) *PolicyRepository {
	return &PolicyRepository{db: db}
}

// GetActive returns a project's active policy, or ErrNotFound if none set.
func (r *PolicyRepository) GetActive(ctx context.Context, projectID string) (*models.Policy, error) {
	var p models.Policy
	err := r.db.GetContext(ctx, &p,
		`SELECT * FROM project_policies WHERE project_id = $1 AND is_active = TRUE`, projectID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// SetPolicy upserts the project's single active policy (config + template).
func (r *PolicyRepository) SetPolicy(ctx context.Context, projectID, name, template string, cfg models.PolicyConfig) (*models.Policy, error) {
	raw, _ := json.Marshal(cfg)
	var p models.Policy
	err := r.db.GetContext(ctx, &p,
		`SELECT * FROM project_policies WHERE project_id = $1 AND is_active = TRUE`, projectID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		err = r.db.GetContext(ctx, &p, `
			INSERT INTO project_policies (project_id, name, template, config_json, is_active)
			VALUES ($1, $2, NULLIF($3,''), $4, TRUE)
			RETURNING *`, projectID, name, template, raw)
		return &p, err
	case err != nil:
		return nil, err
	default:
		err = r.db.GetContext(ctx, &p, `
			UPDATE project_policies
			SET name = $2, template = NULLIF($3,''), config_json = $4, updated_at = now()
			WHERE id = $1
			RETURNING *`, p.ID, name, template, raw)
		return &p, err
	}
}

// SaveEvaluation upserts a scan's policy evaluation (one per scan).
func (r *PolicyRepository) SaveEvaluation(ctx context.Context, scanID string, policyID *string, passed bool, reasons []models.PolicyCheck) error {
	raw, _ := json.Marshal(reasons)
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO policy_evaluations (scan_id, policy_id, passed, reasons_json)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (scan_id) DO UPDATE SET
			policy_id = EXCLUDED.policy_id, passed = EXCLUDED.passed,
			reasons_json = EXCLUDED.reasons_json, created_at = now()`,
		scanID, policyID, passed, raw)
	return err
}

// GetEvaluation loads a scan's stored evaluation.
func (r *PolicyRepository) GetEvaluation(ctx context.Context, scanID string) (*models.PolicyEvaluation, error) {
	row := struct {
		models.PolicyEvaluation
		ReasonsJSON []byte `db:"reasons_json"`
	}{}
	err := r.db.GetContext(ctx, &row,
		`SELECT id, scan_id, policy_id, passed, reasons_json, created_at FROM policy_evaluations WHERE scan_id = $1`, scanID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	eval := row.PolicyEvaluation
	_ = json.Unmarshal(row.ReasonsJSON, &eval.Reasons)
	return &eval, nil
}
