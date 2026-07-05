package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/aegis-platform/api/internal/models"
	"github.com/aegis-platform/api/internal/repository"
)

// ProjectService implements project CRUD with slug generation + ownership.
type ProjectService struct {
	projects *repository.ProjectRepository
}

func NewProjectService(projects *repository.ProjectRepository) *ProjectService {
	return &ProjectService{projects: projects}
}

// ProjectInput is the validated create/update payload.
type ProjectInput struct {
	Name          string
	Description   *string
	RepoURL       *string
	RepoType      *string
	DefaultBranch   string
	Language        *string
	AIFixEnabled    *bool
	GrandfatherMode *bool
}

func (s *ProjectService) Create(ctx context.Context, userID string, in ProjectInput) (*models.Project, error) {
	branch := in.DefaultBranch
	if branch == "" {
		branch = "main"
	}
	p := &models.Project{
		UserID:        userID,
		Name:          in.Name,
		Slug:          slugify(in.Name),
		Description:   in.Description,
		RepoURL:       in.RepoURL,
		RepoType:      in.RepoType,
		DefaultBranch:   branch,
		Language:        in.Language,
		GrandfatherMode: true, // DB default; set here so the response matches
	}
	if err := s.projects.Create(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *ProjectService) Get(ctx context.Context, id, userID string) (*models.Project, error) {
	return s.projects.GetByIDForUser(ctx, id, userID)
}

func (s *ProjectService) List(ctx context.Context, userID string, limit, offset int) ([]models.Project, int, error) {
	return s.projects.ListByUser(ctx, userID, limit, offset)
}

func (s *ProjectService) Update(ctx context.Context, id, userID string, in ProjectInput) (*models.Project, error) {
	// Load to confirm ownership and to keep the immutable slug.
	existing, err := s.projects.GetByIDForUser(ctx, id, userID)
	if err != nil {
		return nil, err
	}
	existing.Name = in.Name
	existing.Description = in.Description
	existing.RepoURL = in.RepoURL
	existing.RepoType = in.RepoType
	if in.DefaultBranch != "" {
		existing.DefaultBranch = in.DefaultBranch
	}
	existing.Language = in.Language
	if in.AIFixEnabled != nil {
		existing.AIFixEnabled = *in.AIFixEnabled
	}
	if in.GrandfatherMode != nil {
		existing.GrandfatherMode = *in.GrandfatherMode
	}

	if err := s.projects.Update(ctx, existing); err != nil {
		return nil, err
	}
	return existing, nil
}

func (s *ProjectService) Delete(ctx context.Context, id, userID string) error {
	return s.projects.Delete(ctx, id, userID)
}

// Baseline returns the project's memory: baseline profile, per-rule baseline, and
// team-learning feedback stats. Ownership is enforced via GetByIDForUser.
func (s *ProjectService) Baseline(ctx context.Context, id, userID string) (*repository.BaselineData, error) {
	p, err := s.projects.GetByIDForUser(ctx, id, userID)
	if err != nil {
		return nil, err
	}
	return s.projects.Baseline(ctx, p.ID, p.GrandfatherMode)
}

// AICodeMemory returns how the project's AI-generated-code footprint evolved.
func (s *ProjectService) AICodeMemory(ctx context.Context, id, userID string) (*repository.AICodeMemory, error) {
	p, err := s.projects.GetByIDForUser(ctx, id, userID)
	if err != nil {
		return nil, err
	}
	return s.projects.AICodeMemory(ctx, p.ID)
}

var slugInvalid = regexp.MustCompile(`[^a-z0-9]+`)

// slugify produces a URL-safe, globally-unique slug from a project name.
func slugify(name string) string {
	base := strings.ToLower(strings.TrimSpace(name))
	base = slugInvalid.ReplaceAllString(base, "-")
	base = strings.Trim(base, "-")
	if base == "" {
		base = "project"
	}
	if len(base) > 40 {
		base = strings.Trim(base[:40], "-")
	}
	return base + "-" + randomHex(4)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// rand.Read effectively never fails; fall back to a fixed marker.
		return "0000"
	}
	return hex.EncodeToString(b)
}
