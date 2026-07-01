package services

import (
	"context"

	"github.com/aegis-platform/api/internal/models"
	"github.com/aegis-platform/api/internal/queue"
	"github.com/aegis-platform/api/internal/repository"
)

// ScanService triggers scans and reads scan/report data, enforcing ownership.
type ScanService struct {
	projects  *repository.ProjectRepository
	scans     *repository.ScanRepository
	findings  *repository.FindingRepository
	publisher *queue.Publisher
}

func NewScanService(
	projects *repository.ProjectRepository,
	scans *repository.ScanRepository,
	findings *repository.FindingRepository,
	publisher *queue.Publisher,
) *ScanService {
	return &ScanService{projects: projects, scans: scans, findings: findings, publisher: publisher}
}

// TriggerInput carries optional overrides for a manual scan.
type TriggerInput struct {
	Branch         string
	CommitSHA      string
	Trigger        string // defaults to manual
	DeepScan       bool   // opt-in interprocedural taint analysis
	DeepScanEngine string // joern (default) | codeql
}

// resolveDeepEngine defaults an opt-in deep scan to Joern (the bundled engine).
func resolveDeepEngine(enabled bool, engine string) string {
	if !enabled {
		return ""
	}
	if engine == "" {
		return "joern"
	}
	return engine
}

// Trigger creates a queued scan and publishes the job. On publish failure the
// scan is marked failed so it never lingers as "queued" forever.
func (s *ScanService) Trigger(ctx context.Context, projectID, userID string, in TriggerInput) (*models.Scan, error) {
	project, err := s.projects.GetByIDForUser(ctx, projectID, userID)
	if err != nil {
		return nil, err
	}
	if project.RepoURL == nil || *project.RepoURL == "" {
		return nil, ErrProjectHasNoRepo
	}

	branch := in.Branch
	if branch == "" {
		branch = project.DefaultBranch
	}
	trigger := in.Trigger
	if trigger == "" {
		trigger = models.TriggerManual
	}

	scan := &models.Scan{
		ProjectID: projectID,
		Trigger:   trigger,
		Status:    models.StatusQueued,
		Branch:    &branch,
	}
	if in.CommitSHA != "" {
		scan.CommitSHA = &in.CommitSHA
	}
	if err := s.scans.Create(ctx, scan); err != nil {
		return nil, err
	}

	payload := queue.ScanPayload{
		ScanID:          scan.ID,
		ProjectID:       projectID,
		RepoURL:         *project.RepoURL,
		Branch:          branch,
		CommitSHA:       in.CommitSHA,
		Trigger:         trigger,
		DeepScanEnabled: in.DeepScan,
		DeepScanEngine:  resolveDeepEngine(in.DeepScan, in.DeepScanEngine),
	}
	if project.RepoType != nil {
		payload.RepoType = *project.RepoType
	}
	if project.Language != nil {
		payload.Language = *project.Language
	}

	if _, err := s.publisher.EnqueueScan(ctx, payload); err != nil {
		// Roll the scan into a failed state rather than leaving it queued.
		_ = s.scans.MarkFailed(ctx, scan.ID, "failed to enqueue scan job")
		return nil, err
	}
	return scan, nil
}

// TriggerWebhook creates and enqueues a scan from a verified webhook delivery.
// It bypasses user-ownership checks (there is no user in a webhook context) but
// still validates the project exists and has a repo configured.
func (s *ScanService) TriggerWebhook(ctx context.Context, projectID, branch, commitSHA string) (*models.Scan, error) {
	project, err := s.projects.GetByID(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if project.RepoURL == nil || *project.RepoURL == "" {
		return nil, ErrProjectHasNoRepo
	}
	if branch == "" {
		branch = project.DefaultBranch
	}

	scan := &models.Scan{
		ProjectID: projectID,
		Trigger:   models.TriggerWebhook,
		Status:    models.StatusQueued,
		Branch:    &branch,
	}
	if commitSHA != "" {
		scan.CommitSHA = &commitSHA
	}
	if err := s.scans.Create(ctx, scan); err != nil {
		return nil, err
	}

	payload := queue.ScanPayload{
		ScanID: scan.ID, ProjectID: projectID, RepoURL: *project.RepoURL,
		Branch: branch, CommitSHA: commitSHA, Trigger: models.TriggerWebhook,
	}
	if project.RepoType != nil {
		payload.RepoType = *project.RepoType
	}
	if project.Language != nil {
		payload.Language = *project.Language
	}
	if _, err := s.publisher.EnqueueScan(ctx, payload); err != nil {
		_ = s.scans.MarkFailed(ctx, scan.ID, "failed to enqueue scan job")
		return nil, err
	}
	return scan, nil
}

// List returns a project's scans after verifying ownership.
func (s *ScanService) List(ctx context.Context, projectID, userID string, limit, offset int) ([]models.Scan, int, error) {
	if _, err := s.projects.GetByIDForUser(ctx, projectID, userID); err != nil {
		return nil, 0, err
	}
	return s.scans.ListByProject(ctx, projectID, limit, offset)
}

// Get returns a single scan owned by the user.
func (s *ScanService) Get(ctx context.Context, scanID, userID string) (*models.Scan, error) {
	return s.scans.GetByIDForUser(ctx, scanID, userID)
}

// Report bundles a scan with its finding breakdown.
type Report struct {
	Scan      *models.Scan               `json:"scan"`
	Breakdown []repository.SeverityCount `json:"breakdown"`
}

// BuildReport assembles the report JSON for a scan the user owns.
func (s *ScanService) BuildReport(ctx context.Context, scanID, userID string) (*Report, error) {
	scan, err := s.scans.GetByIDForUser(ctx, scanID, userID)
	if err != nil {
		return nil, err
	}
	breakdown, err := s.findings.AggregateByPillarSeverity(ctx, scanID)
	if err != nil {
		return nil, err
	}
	return &Report{Scan: scan, Breakdown: breakdown}, nil
}

// ListFindings returns filtered findings for a scan the user owns.
func (s *ScanService) ListFindings(
	ctx context.Context, scanID, userID string, filter repository.FindingFilter, limit, offset int,
) ([]models.Finding, int, error) {
	if _, err := s.scans.GetByIDForUser(ctx, scanID, userID); err != nil {
		return nil, 0, err
	}
	return s.findings.ListByScan(ctx, scanID, filter, limit, offset)
}

// UpdateFindingTriage flips suppression / false-positive flags for the user's finding.
func (s *ScanService) UpdateFindingTriage(
	ctx context.Context, findingID, userID string, isFalsePositive, isSuppressed *bool,
) (*models.Finding, error) {
	return s.findings.UpdateTriage(ctx, findingID, userID, isFalsePositive, isSuppressed)
}
