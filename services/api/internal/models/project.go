package models

import "time"

// Repo type enumeration (mirrors DB CHECK constraint).
const (
	RepoTypeGitHub    = "github"
	RepoTypeGitLab    = "gitlab"
	RepoTypeBitbucket = "bitbucket"
	RepoTypeUpload    = "upload"
)

// Project describes a codebase owned by a user.
type Project struct {
	ID            string    `db:"id" json:"id"`
	UserID        string    `db:"user_id" json:"user_id"`
	Name          string    `db:"name" json:"name"`
	Slug          string    `db:"slug" json:"slug"`
	Description   *string   `db:"description" json:"description,omitempty"`
	RepoURL       *string   `db:"repo_url" json:"repo_url,omitempty"`
	RepoType      *string   `db:"repo_type" json:"repo_type,omitempty"`
	DefaultBranch string    `db:"default_branch" json:"default_branch"`
	Language      *string   `db:"language" json:"language,omitempty"`
	AIFixEnabled  bool      `db:"ai_fix_enabled" json:"ai_fix_enabled"`
	CreatedAt     time.Time `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time `db:"updated_at" json:"updated_at"`
}
