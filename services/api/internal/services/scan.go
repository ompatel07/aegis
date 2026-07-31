package services

import (
	"context"
	"strconv"

	"github.com/aegis-platform/api/internal/auth"
	"github.com/aegis-platform/api/internal/githubapp"
	"github.com/aegis-platform/api/internal/models"
	"github.com/aegis-platform/api/internal/queue"
	"github.com/aegis-platform/api/internal/repository"
	"github.com/aegis-platform/api/internal/sarif"
)

// ScanService triggers scans and reads scan/report data, enforcing ownership.
type ScanService struct {
	projects     *repository.ProjectRepository
	scans        *repository.ScanRepository
	findings     *repository.FindingRepository
	rules        *repository.ProjectRuleRepository
	integrations *repository.GithubIntegrationRepository
	enc          *auth.Encryptor
	app          *githubapp.App // may be nil if the GitHub App isn't configured
	publisher    *queue.Publisher
}

func NewScanService(
	projects *repository.ProjectRepository,
	scans *repository.ScanRepository,
	findings *repository.FindingRepository,
	rules *repository.ProjectRuleRepository,
	integrations *repository.GithubIntegrationRepository,
	enc *auth.Encryptor,
	app *githubapp.App,
	publisher *queue.Publisher,
) *ScanService {
	return &ScanService{
		projects: projects, scans: scans, findings: findings, rules: rules,
		integrations: integrations, enc: enc, app: app, publisher: publisher,
	}
}

// cloneToken resolves the credential used to clone a project's repo, or "" for a
// public/anonymous clone. Prefers a GitHub App installation token; falls back to
// a per-project encrypted PAT (direct URL / GitLab / Bitbucket). The token is
// returned only to be placed in the transient job payload — never persisted or
// logged.
func (s *ScanService) cloneToken(ctx context.Context, projectID string) string {
	if s.integrations == nil {
		return ""
	}
	gi, err := s.integrations.GetByProject(ctx, projectID)
	if err != nil {
		return "" // no integration → anonymous (fine for public repos)
	}
	// GitHub App installation → mint a short-lived (9-min) installation token.
	if gi.InstallationID != nil && *gi.InstallationID != "" && s.app != nil {
		if id, perr := strconv.ParseInt(*gi.InstallationID, 10, 64); perr == nil {
			if tok, terr := s.app.InstallationToken(ctx, id); terr == nil {
				return tok
			}
		}
	}
	// Stored personal access token (direct URL / GitLab / Bitbucket).
	if gi.AccessTokenEncrypted != nil && *gi.AccessTokenEncrypted != "" && s.enc != nil {
		if tok, derr := s.enc.Decrypt(*gi.AccessTokenEncrypted); derr == nil {
			return tok
		}
	}
	return ""
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
	// Triggering a scan is a state-changing action: viewers are read-only.
	if err := ensureWriteRole(s.projects.RoleInProjectOrg(ctx, projectID, userID)); err != nil {
		return nil, err
	}
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
		CloneToken:      s.cloneToken(ctx, projectID),
		DeepScanEnabled: in.DeepScan,
		DeepScanEngine:  resolveDeepEngine(in.DeepScan, in.DeepScanEngine),
	}
	if project.RepoType != nil {
		payload.RepoType = *project.RepoType
	}
	if project.Language != nil {
		payload.Language = *project.Language
	}
	if rules, rerr := s.rules.YAMLForProject(ctx, projectID); rerr == nil && len(rules) > 0 {
		payload.CustomRules = rules
	}

	if _, err := s.publisher.EnqueueScan(ctx, payload); err != nil {
		// Roll the scan into a failed state rather than leaving it queued.
		_ = s.scans.MarkFailed(ctx, scan.ID, "failed to enqueue scan job")
		return nil, err
	}
	return scan, nil
}

// TriggerUpload creates and enqueues a scan of an uploaded code archive (Method
// B). archivePath is a .zip/.tar.gz already saved to the shared workspace by the
// handler; the orchestrator extracts it into a per-scan sandbox instead of
// cloning. No repo_url or credential is involved.
func (s *ScanService) TriggerUpload(ctx context.Context, projectID, userID, archivePath string) (*models.Scan, error) {
	// Uploading code to scan is a state-changing action: viewers are read-only.
	if err := ensureWriteRole(s.projects.RoleInProjectOrg(ctx, projectID, userID)); err != nil {
		return nil, err
	}
	if _, err := s.projects.GetByIDForUser(ctx, projectID, userID); err != nil {
		return nil, err
	}
	branch := "upload"
	scan := &models.Scan{
		ProjectID: projectID,
		Trigger:   models.TriggerManual,
		Status:    models.StatusQueued,
		Branch:    &branch,
	}
	if err := s.scans.Create(ctx, scan); err != nil {
		return nil, err
	}
	payload := queue.ScanPayload{
		ScanID:     scan.ID,
		ProjectID:  projectID,
		Trigger:    models.TriggerManual,
		UploadPath: archivePath,
	}
	if rules, rerr := s.rules.YAMLForProject(ctx, projectID); rerr == nil && len(rules) > 0 {
		payload.CustomRules = rules
	}
	if _, err := s.publisher.EnqueueScan(ctx, payload); err != nil {
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
		CloneToken: s.cloneToken(ctx, projectID),
	}
	if project.RepoType != nil {
		payload.RepoType = *project.RepoType
	}
	if project.Language != nil {
		payload.Language = *project.Language
	}
	if rules, rerr := s.rules.YAMLForProject(ctx, projectID); rerr == nil && len(rules) > 0 {
		payload.CustomRules = rules
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

// ExportSARIF builds a SARIF 2.1.0 log for a scan the user owns, for upload to
// GitHub code scanning or any SARIF consumer.
// ExportSBOM returns the stored SBOM document (format = cyclonedx | spdx) for a
// scan the caller owns.
func (s *ScanService) ExportSBOM(ctx context.Context, scanID, userID, format string) (string, error) {
	if _, err := s.scans.GetByIDForUser(ctx, scanID, userID); err != nil {
		return "", err
	}
	return s.scans.GetSBOM(ctx, scanID, format)
}

func (s *ScanService) ExportSARIF(ctx context.Context, scanID, userID string) (*sarif.Log, error) {
	scan, err := s.scans.GetByIDForUser(ctx, scanID, userID)
	if err != nil {
		return nil, err
	}
	findings, err := s.findings.AllByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	repoURL := ""
	if project, perr := s.projects.GetByID(ctx, scan.ProjectID); perr == nil && project.RepoURL != nil {
		repoURL = *project.RepoURL
	}
	return sarif.Build(scan, findings, repoURL), nil
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

// RecordFeedback stores a user's action on a finding (for the FP classifier) and
// reflects it on the finding's triage flags.
func (s *ScanService) RecordFeedback(ctx context.Context, findingID, userID, action, reason string) error {
	// Feedback writes finding_feedback + team-learning stats and flips triage:
	// viewers are read-only.
	if err := ensureWriteRole(s.findings.RoleInFindingOrg(ctx, findingID, userID)); err != nil {
		return err
	}
	if err := s.findings.InsertFeedback(ctx, findingID, userID, action, reason); err != nil {
		return err
	}
	// Team pattern learning: fold this action into the project's per-rule stats.
	_ = s.findings.UpsertRuleStats(ctx, findingID, userID, action)
	yes, no := true, false
	switch action {
	case "marked_fp":
		_, _ = s.findings.UpdateTriage(ctx, findingID, userID, &yes, nil)
	case "suppressed", "ignored":
		_, _ = s.findings.UpdateTriage(ctx, findingID, userID, nil, &yes)
	case "confirmed", "fixed":
		_, _ = s.findings.UpdateTriage(ctx, findingID, userID, &no, &no)
	}
	return nil
}

// UpdateFindingTriage flips suppression / false-positive flags for the user's finding.
func (s *ScanService) UpdateFindingTriage(
	ctx context.Context, findingID, userID string, isFalsePositive, isSuppressed *bool,
) (*models.Finding, error) {
	// Triage mutates shared finding state: viewers are read-only.
	if err := ensureWriteRole(s.findings.RoleInFindingOrg(ctx, findingID, userID)); err != nil {
		return nil, err
	}
	return s.findings.UpdateTriage(ctx, findingID, userID, isFalsePositive, isSuppressed)
}
