package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jmoiron/sqlx"
)

// GitHubAppRepository persists installations, repos, and PR check-run tracking.
type GitHubAppRepository struct {
	db *sqlx.DB
}

func NewGitHubAppRepository(db *sqlx.DB) *GitHubAppRepository {
	return &GitHubAppRepository{db: db}
}

// UpsertInstallation records (or revives) an installation.
func (r *GitHubAppRepository) UpsertInstallation(ctx context.Context, installationID int64, login, accountType string, permsJSON []byte) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO github_app_installations (installation_id, account_login, account_type, permissions_json)
		VALUES ($1, $2, $3, COALESCE($4,'{}')::jsonb)
		ON CONFLICT (installation_id) DO UPDATE SET
			account_login = EXCLUDED.account_login, account_type = EXCLUDED.account_type,
			permissions_json = EXCLUDED.permissions_json, deleted_at = NULL`,
		installationID, login, accountType, permsJSON)
	return err
}

func (r *GitHubAppRepository) DeleteInstallation(ctx context.Context, installationID int64) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE github_app_installations SET deleted_at = now() WHERE installation_id = $1`, installationID)
	return err
}

// UpsertRepo records a repo under an installation.
func (r *GitHubAppRepository) UpsertRepo(ctx context.Context, installationID, repoID int64, name, fullName, defaultBranch string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO github_repositories (installation_id, repo_id, name, full_name, default_branch)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (installation_id, repo_id) DO UPDATE SET
			name = EXCLUDED.name, full_name = EXCLUDED.full_name, default_branch = EXCLUDED.default_branch`,
		installationID, repoID, name, fullName, defaultBranch)
	return err
}

func (r *GitHubAppRepository) RemoveRepo(ctx context.Context, installationID, repoID int64) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM github_repositories WHERE installation_id = $1 AND repo_id = $2`, installationID, repoID)
	return err
}

// RepoEnabled reports whether a repo is enabled for scanning (default true).
func (r *GitHubAppRepository) RepoEnabled(ctx context.Context, installationID int64, fullName string) (bool, error) {
	var enabled bool
	err := r.db.GetContext(ctx, &enabled,
		`SELECT enabled FROM github_repositories WHERE installation_id = $1 AND full_name = $2`, installationID, fullName)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil // unknown repo → allow (installation covers it)
	}
	return enabled, err
}

// SetRepoEnabled toggles a repo's scanning (dashboard control).
func (r *GitHubAppRepository) SetRepoEnabled(ctx context.Context, id string, enabled bool) error {
	_, err := r.db.ExecContext(ctx, `UPDATE github_repositories SET enabled = $2 WHERE id = $1`, id, enabled)
	return err
}

// GHInstallationView is an installation + its repos, for the dashboard.
type GHInstallationView struct {
	InstallationID int64  `db:"installation_id" json:"installation_id"`
	AccountLogin   string `db:"account_login" json:"account_login"`
	AccountType    string `db:"account_type" json:"account_type"`
}

type GHRepoView struct {
	ID            string `db:"id" json:"id"`
	InstallationID int64 `db:"installation_id" json:"installation_id"`
	FullName      string `db:"full_name" json:"full_name"`
	DefaultBranch *string `db:"default_branch" json:"default_branch,omitempty"`
	Enabled       bool   `db:"enabled" json:"enabled"`
}

func (r *GitHubAppRepository) ListInstallations(ctx context.Context) ([]GHInstallationView, error) {
	out := []GHInstallationView{}
	err := r.db.SelectContext(ctx, &out,
		`SELECT installation_id, account_login, COALESCE(account_type,'') account_type
		   FROM github_app_installations WHERE deleted_at IS NULL ORDER BY created_at DESC`)
	return out, err
}

func (r *GitHubAppRepository) ListRepos(ctx context.Context, installationID int64) ([]GHRepoView, error) {
	out := []GHRepoView{}
	err := r.db.SelectContext(ctx, &out,
		`SELECT id, installation_id, full_name, default_branch, enabled
		   FROM github_repositories WHERE installation_id = $1 ORDER BY full_name`, installationID)
	return out, err
}

// ── PR check runs ─────────────────────────────────────────────────────────────

type PRCheckRun struct {
	ID             string `db:"id"`
	ScanID         string `db:"scan_id"`
	InstallationID int64  `db:"installation_id"`
	RepoFullName   string `db:"repo_full_name"`
	PRNumber       int    `db:"pr_number"`
	HeadSHA        string `db:"head_sha"`
	CheckRunID     *int64 `db:"check_run_id"`
	CommentID      *int64 `db:"comment_id"`
	Finalized      bool   `db:"finalized"`
}

func (r *GitHubAppRepository) CreatePRCheckRun(ctx context.Context, pr *PRCheckRun) error {
	return r.db.QueryRowxContext(ctx, `
		INSERT INTO pr_check_runs (scan_id, installation_id, repo_full_name, pr_number, head_sha, check_run_id)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		pr.ScanID, pr.InstallationID, pr.RepoFullName, pr.PRNumber, pr.HeadSHA, pr.CheckRunID).Scan(&pr.ID)
}

func (r *GitHubAppRepository) SetCheckRunID(ctx context.Context, id string, checkRunID int64) error {
	_, err := r.db.ExecContext(ctx, `UPDATE pr_check_runs SET check_run_id = $2, updated_at = now() WHERE id = $1`, id, checkRunID)
	return err
}

func (r *GitHubAppRepository) SetCommentID(ctx context.Context, id string, commentID int64) error {
	_, err := r.db.ExecContext(ctx, `UPDATE pr_check_runs SET comment_id = $2, updated_at = now() WHERE id = $1`, id, commentID)
	return err
}

func (r *GitHubAppRepository) MarkFinalized(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE pr_check_runs SET finalized = TRUE, updated_at = now() WHERE id = $1`, id)
	return err
}

// PendingFinalizations returns PR check runs whose scan has completed but which
// haven't yet been finalized on GitHub (driven by the reconciler).
func (r *GitHubAppRepository) PendingFinalizations(ctx context.Context, limit int) ([]PRCheckRun, error) {
	out := []PRCheckRun{}
	err := r.db.SelectContext(ctx, &out, `
		SELECT pr.id, pr.scan_id, pr.installation_id, pr.repo_full_name, pr.pr_number,
		       pr.head_sha, pr.check_run_id, pr.comment_id, pr.finalized
		  FROM pr_check_runs pr
		  JOIN scans s ON s.id = pr.scan_id
		 WHERE pr.finalized = FALSE AND s.status IN ('completed','failed')
		 ORDER BY pr.created_at ASC LIMIT $1`, limit)
	return out, err
}
