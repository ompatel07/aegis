package models

import "time"

// GithubIntegration links a project to a GitHub repo for webhook-driven scans.
// AccessTokenEncrypted holds an AES-GCM ciphertext; WebhookSecret verifies the
// HMAC signature on incoming webhook deliveries.
type GithubIntegration struct {
	ID                   string    `db:"id" json:"id"`
	UserID               string    `db:"user_id" json:"user_id"`
	ProjectID            string    `db:"project_id" json:"project_id"`
	InstallationID       *string   `db:"installation_id" json:"installation_id,omitempty"`
	WebhookSecret        string    `db:"webhook_secret" json:"-"`
	AccessTokenEncrypted *string   `db:"access_token_encrypted" json:"-"`
	CreatedAt            time.Time `db:"created_at" json:"created_at"`
}
