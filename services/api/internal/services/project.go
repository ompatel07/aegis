package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"
	"time"

	"github.com/aegis-platform/api/internal/gitremote"
	"github.com/aegis-platform/api/internal/models"
	"github.com/aegis-platform/api/internal/repository"
)

// ProjectService implements project CRUD with slug generation + org ownership.
type ProjectService struct {
	projects *repository.ProjectRepository
	orgs     *repository.OrganizationRepository
}

// DetectBranches inspects a remote repository without cloning and returns its
// default branch + branch list — powering the "auto-detect vs choose a branch"
// UI when connecting a repo. token is optional (needed only for private repos).
func (s *ProjectService) DetectBranches(ctx context.Context, repoURL, token string) (string, []string, error) {
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return gitremote.Detect(dctx, repoURL, token)
}

func NewProjectService(projects *repository.ProjectRepository, orgs *repository.OrganizationRepository) *ProjectService {
	return &ProjectService{projects: projects, orgs: orgs}
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
	OrganizationID  *string
}

func (s *ProjectService) Create(ctx context.Context, userID string, in ProjectInput) (*models.Project, error) {
	// Branch resolution (Phase 2G): never assume "main". Use the branch the user
	// specified; otherwise best-effort auto-detect the remote's real default. If
	// detection fails (e.g. a private repo whose token is connected later), leave
	// it empty — the orchestrator clones the remote's default HEAD when no branch
	// is set, so scanning still works for master/develop/etc.
	branch := in.DefaultBranch
	isUpload := in.RepoType != nil && *in.RepoType == "upload"
	if branch == "" && !isUpload && in.RepoURL != nil && *in.RepoURL != "" {
		dctx, cancel := context.WithTimeout(ctx, 12*time.Second)
		if def, _, derr := gitremote.Detect(dctx, *in.RepoURL, ""); derr == nil && def != "" {
			branch = def
		}
		cancel()
	}

	// Resolve the owning org: the one requested (member+ required) or the user's
	// personal org.
	var orgID string
	if in.OrganizationID != nil && *in.OrganizationID != "" {
		role, err := s.orgs.RoleOf(ctx, *in.OrganizationID, userID)
		if err != nil {
			return nil, ErrForbidden
		}
		if !models.RoleAtLeast(role, models.OrgRoleMember) {
			return nil, ErrForbidden
		}
		orgID = *in.OrganizationID
	} else {
		pid, err := s.orgs.PersonalOrgID(ctx, userID)
		if err != nil {
			return nil, err
		}
		orgID = pid
	}

	p := &models.Project{
		UserID:          userID,
		OrganizationID:  &orgID,
		Name:            in.Name,
		Slug:            slugify(in.Name),
		Description:     in.Description,
		RepoURL:         in.RepoURL,
		RepoType:        in.RepoType,
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
	// Editing project settings is a state-changing action: viewers are read-only.
	if err := ensureWriteRole(s.projects.RoleInProjectOrg(ctx, id, userID)); err != nil {
		return nil, err
	}
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
	// Deleting a project is a state-changing action: viewers are read-only. (The
	// repo query also restricts to owner/admin/member as defense in depth.)
	if err := ensureWriteRole(s.projects.RoleInProjectOrg(ctx, id, userID)); err != nil {
		return err
	}
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
