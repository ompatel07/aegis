package repository

import (
	"context"
	"time"

	"github.com/jmoiron/sqlx"
)

// AIAudit is one row of the AI call audit trail.
type AIAudit struct {
	UserID      *string
	ProjectID   *string
	FindingID   *string
	Feature     string
	Provider    string
	Model       string
	PromptHash  string
	PromptChars int
	Success     bool
	Error       string
}

// AIAuditEntry is the read model for listing the trail.
type AIAuditEntry struct {
	ID        string    `db:"id" json:"id"`
	ProjectID *string   `db:"project_id" json:"project_id,omitempty"`
	FindingID *string   `db:"finding_id" json:"finding_id,omitempty"`
	Feature   string    `db:"feature" json:"feature"`
	Provider  string    `db:"provider" json:"provider"`
	Model     *string   `db:"model" json:"model,omitempty"`
	Success   bool      `db:"success" json:"success"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

type AIAuditRepository struct {
	db *sqlx.DB
}

func NewAIAuditRepository(db *sqlx.DB) *AIAuditRepository {
	return &AIAuditRepository{db: db}
}

// Log records one AI call. The prompt text is never stored — only its hash.
func (r *AIAuditRepository) Log(ctx context.Context, a AIAudit) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO ai_audit_log
		   (user_id, project_id, finding_id, feature, provider, model, prompt_hash, prompt_chars, success, error)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		a.UserID, a.ProjectID, a.FindingID, a.Feature, a.Provider,
		nullStr(a.Model), a.PromptHash, a.PromptChars, a.Success, nullStr(a.Error),
	)
	return err
}

// RecentForUser lists a user's recent AI calls (audit view).
func (r *AIAuditRepository) RecentForUser(ctx context.Context, userID string, limit int) ([]AIAuditEntry, error) {
	out := []AIAuditEntry{}
	err := r.db.SelectContext(ctx, &out,
		`SELECT a.id, a.project_id, a.finding_id, a.feature, a.provider, a.model, a.success, a.created_at
		   FROM ai_audit_log a
		   LEFT JOIN projects p ON p.id = a.project_id
		  WHERE a.user_id = $1 OR p.user_id = $1
		  ORDER BY a.created_at DESC LIMIT $2`,
		userID, limit)
	return out, err
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
