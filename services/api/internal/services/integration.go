package services

import (
	"context"
	"errors"

	"github.com/aegis-platform/api/internal/auth"
	"github.com/aegis-platform/api/internal/models"
	"github.com/aegis-platform/api/internal/repository"
)

// webhookPath is where GitHub should POST deliveries; the dashboard prefixes it
// with the deployment's public origin.
const webhookPath = "/api/v1/webhooks/github"

// IntegrationService manages per-project GitHub integrations, enforcing project
// ownership and encrypting access tokens at rest.
type IntegrationService struct {
	projects *repository.ProjectRepository
	repo     *repository.GithubIntegrationRepository
	enc      *auth.Encryptor
}

func NewIntegrationService(
	projects *repository.ProjectRepository,
	repo *repository.GithubIntegrationRepository,
	enc *auth.Encryptor,
) *IntegrationService {
	return &IntegrationService{projects: projects, repo: repo, enc: enc}
}

// ConnectGitHubInput carries the optional installation id and access token.
type ConnectGitHubInput struct {
	InstallationID string
	AccessToken    string
}

// ConnectGitHubResult returns the integration plus the webhook URL and the
// freshly-generated secret — the secret is shown exactly once, at creation.
type ConnectGitHubResult struct {
	Integration   *models.GithubIntegration `json:"integration"`
	WebhookURL    string                    `json:"webhook_url"`
	WebhookSecret string                    `json:"webhook_secret"`
}

// ConnectGitHub creates or replaces the integration for a project the user owns.
func (s *IntegrationService) ConnectGitHub(
	ctx context.Context, projectID, userID string, in ConnectGitHubInput,
) (*ConnectGitHubResult, error) {
	if _, err := s.projects.GetByIDForUser(ctx, projectID, userID); err != nil {
		return nil, err
	}

	secret := randomHex(32) // 32 random bytes -> 64-char hex webhook secret

	gi := &models.GithubIntegration{UserID: userID, ProjectID: projectID, WebhookSecret: secret}
	if in.InstallationID != "" {
		gi.InstallationID = &in.InstallationID
	}
	if in.AccessToken != "" {
		ciphertext, err := s.enc.Encrypt(in.AccessToken)
		if err != nil {
			return nil, err
		}
		gi.AccessTokenEncrypted = &ciphertext
	}

	if err := s.repo.Upsert(ctx, gi); err != nil {
		return nil, err
	}
	return &ConnectGitHubResult{Integration: gi, WebhookURL: webhookPath, WebhookSecret: secret}, nil
}

// ListForProject returns the project's integration (0 or 1), secrets stripped by
// the model's JSON tags.
func (s *IntegrationService) ListForProject(
	ctx context.Context, projectID, userID string,
) ([]models.GithubIntegration, error) {
	gi, err := s.repo.GetByProjectForUser(ctx, projectID, userID)
	if errors.Is(err, repository.ErrNotFound) {
		return []models.GithubIntegration{}, nil
	}
	if err != nil {
		return nil, err
	}
	return []models.GithubIntegration{*gi}, nil
}

// Delete removes an integration the user owns.
func (s *IntegrationService) Delete(ctx context.Context, integrationID, userID string) error {
	return s.repo.DeleteByIDForUser(ctx, integrationID, userID)
}
