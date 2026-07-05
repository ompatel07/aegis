package repository

import (
	"context"

	"github.com/jmoiron/sqlx"
)

// VCSTracking is a GitLab/Bitbucket PR/MR awaiting comment+status finalization.
type VCSTracking struct {
	ID           string `db:"id"`
	Provider     string `db:"provider"`
	ScanID       string `db:"scan_id"`
	ProjectRef   string `db:"project_ref"`
	RepoFullName string `db:"repo_full_name"`
	PRNumber     int    `db:"pr_number"`
	HeadSHA      string `db:"head_sha"`
	CommentID    *int64 `db:"comment_id"`
	Finalized    bool   `db:"finalized"`
}

// VCSRepository tracks cross-provider PR/MR comment state.
type VCSRepository struct {
	db *sqlx.DB
}

func NewVCSRepository(db *sqlx.DB) *VCSRepository { return &VCSRepository{db: db} }

func (r *VCSRepository) CreateTracking(ctx context.Context, t *VCSTracking) error {
	return r.db.QueryRowxContext(ctx, `
		INSERT INTO vcs_pr_tracking (provider, scan_id, project_ref, repo_full_name, pr_number, head_sha)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		t.Provider, t.ScanID, t.ProjectRef, t.RepoFullName, t.PRNumber, t.HeadSHA).Scan(&t.ID)
}

func (r *VCSRepository) SetCommentID(ctx context.Context, id string, commentID int64) error {
	_, err := r.db.ExecContext(ctx, `UPDATE vcs_pr_tracking SET comment_id = $2, updated_at = now() WHERE id = $1`, id, commentID)
	return err
}

func (r *VCSRepository) MarkFinalized(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE vcs_pr_tracking SET finalized = TRUE, updated_at = now() WHERE id = $1`, id)
	return err
}

func (r *VCSRepository) PendingFinalizations(ctx context.Context, limit int) ([]VCSTracking, error) {
	out := []VCSTracking{}
	err := r.db.SelectContext(ctx, &out, `
		SELECT t.id, t.provider, t.scan_id, t.project_ref, t.repo_full_name, t.pr_number,
		       t.head_sha, t.comment_id, t.finalized
		  FROM vcs_pr_tracking t
		  JOIN scans s ON s.id = t.scan_id
		 WHERE t.finalized = FALSE AND s.status IN ('completed','failed')
		 ORDER BY t.created_at ASC LIMIT $1`, limit)
	return out, err
}
