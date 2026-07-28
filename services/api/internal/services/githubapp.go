package services

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/githubapp"
	"github.com/aegis-platform/api/internal/models"
	"github.com/aegis-platform/api/internal/repository"
)

// GitHubAppService wires GitHub App webhooks to scans and posts PR checks +
// a single updateable comment when a scan completes.
type GitHubAppService struct {
	app      *githubapp.App
	repo     *repository.GitHubAppRepository
	projects *repository.ProjectRepository
	scans    *ScanService
	scanRepo *repository.ScanRepository
	findings *repository.FindingRepository
	policy   *PolicyService
	dashURL  string
	log      zerolog.Logger
}

func NewGitHubAppService(
	app *githubapp.App, repo *repository.GitHubAppRepository, projects *repository.ProjectRepository,
	scans *ScanService, scanRepo *repository.ScanRepository, findings *repository.FindingRepository,
	policy *PolicyService, dashURL string, log zerolog.Logger,
) *GitHubAppService {
	return &GitHubAppService{app: app, repo: repo, projects: projects, scans: scans,
		scanRepo: scanRepo, findings: findings, policy: policy, dashURL: dashURL, log: log}
}

func (s *GitHubAppService) App() *githubapp.App { return s.app }

// HandleWebhook routes a verified GitHub App event.
func (s *GitHubAppService) HandleWebhook(ctx context.Context, event string, payload []byte) error {
	switch event {
	case "push":
		e, err := githubapp.Parse[githubapp.PushEvent](payload)
		if err != nil {
			return err
		}
		return s.onPush(ctx, e)
	case "pull_request":
		e, err := githubapp.Parse[githubapp.PullRequestEvent](payload)
		if err != nil {
			return err
		}
		return s.onPullRequest(ctx, e)
	case "installation":
		e, err := githubapp.Parse[githubapp.InstallationEvent](payload)
		if err != nil {
			return err
		}
		return s.onInstallation(ctx, e)
	case "installation_repositories":
		e, err := githubapp.Parse[githubapp.InstallationRepositoriesEvent](payload)
		if err != nil {
			return err
		}
		return s.onInstallationRepos(ctx, e)
	case "check_run":
		e, err := githubapp.Parse[githubapp.CheckRunEvent](payload)
		if err != nil {
			return err
		}
		if e.Action == "rerequested" {
			_, err := s.triggerForRepo(ctx, e.Repository, e.Repository.DefaultBranch, e.CheckRun.HeadSHA)
			return err
		}
	}
	return nil
}

func (s *GitHubAppService) onInstallation(ctx context.Context, e githubapp.InstallationEvent) error {
	switch e.Action {
	case "deleted":
		return s.repo.DeleteInstallation(ctx, e.Installation.ID)
	default: // created, new_permissions_accepted, unsuspend
		if err := s.repo.UpsertInstallation(ctx, e.Installation.ID, e.Installation.Account.Login, e.Installation.Account.Type, nil); err != nil {
			return err
		}
		for _, r := range e.Repositories {
			_ = s.repo.UpsertRepo(ctx, e.Installation.ID, r.ID, r.Name, r.FullName, r.DefaultBranch)
		}
	}
	return nil
}

func (s *GitHubAppService) onInstallationRepos(ctx context.Context, e githubapp.InstallationRepositoriesEvent) error {
	for _, r := range e.RepositoriesAdded {
		_ = s.repo.UpsertRepo(ctx, e.Installation.ID, r.ID, r.Name, r.FullName, r.DefaultBranch)
	}
	for _, r := range e.RepositoriesRemoved {
		_ = s.repo.RemoveRepo(ctx, e.Installation.ID, r.ID)
	}
	return nil
}

func (s *GitHubAppService) onPush(ctx context.Context, e githubapp.PushEvent) error {
	if e.Branch() != e.Repository.DefaultBranch {
		return nil // only scan the default branch on push
	}
	if ok, _ := s.repo.RepoEnabled(ctx, e.Installation.ID, e.Repository.FullName); !ok {
		return nil
	}
	_, err := s.triggerForRepo(ctx, e.Repository, e.Branch(), e.After)
	return err
}

func (s *GitHubAppService) onPullRequest(ctx context.Context, e githubapp.PullRequestEvent) error {
	if e.Action != "opened" && e.Action != "synchronize" && e.Action != "reopened" {
		return nil
	}
	if ok, _ := s.repo.RepoEnabled(ctx, e.Installation.ID, e.Repository.FullName); !ok {
		return nil
	}
	scan, err := s.triggerForRepo(ctx, e.Repository, e.PullRequest.Head.Ref, e.PullRequest.Head.SHA)
	if err != nil || scan == nil {
		return err
	}

	// Open a pending check and record the PR check-run for finalization.
	pr := &repository.PRCheckRun{
		ScanID: scan.ID, InstallationID: e.Installation.ID, RepoFullName: e.Repository.FullName,
		PRNumber: e.Number, HeadSHA: e.PullRequest.Head.SHA,
	}
	if s.app.Enabled() {
		if id, cerr := s.app.Client(e.Installation.ID).CreateCheckRun(ctx,
			e.Repository.FullName, "Aegis Security", e.PullRequest.Head.SHA, "in_progress",
			s.scanURL(scan.ProjectID, scan.ID)); cerr == nil {
			pr.CheckRunID = &id
		} else {
			s.log.Warn().Err(cerr).Msg("create check-run failed")
		}
	}
	return s.repo.CreatePRCheckRun(ctx, pr)
}

// triggerForRepo maps a GitHub repo to an Aegis project and enqueues a scan.
func (s *GitHubAppService) triggerForRepo(ctx context.Context, repo githubapp.Repo, branch, sha string) (*models.Scan, error) {
	projectID, err := s.projects.FindIDByRepo(ctx, repo.FullName)
	if err != nil {
		s.log.Info().Str("repo", repo.FullName).Msg("no Aegis project connected for repo; skipping scan")
		return nil, nil
	}
	if branch == "" {
		branch = repo.DefaultBranch
	}
	return s.scans.TriggerWebhook(ctx, projectID, branch, sha)
}

// ── Reconciler: finalize PR checks + comment once a scan completes ────────────

// Reconcile finalizes any completed PR scans: evaluates the policy, updates the
// check-run conclusion, and upserts the single PR comment + inline annotations.
func (s *GitHubAppService) Reconcile(ctx context.Context) {
	if !s.app.Enabled() {
		return
	}
	pending, err := s.repo.PendingFinalizations(ctx, 20)
	if err != nil {
		s.log.Warn().Err(err).Msg("pr reconcile query failed")
		return
	}
	for _, pr := range pending {
		if err := s.finalize(ctx, pr); err != nil {
			s.log.Warn().Err(err).Str("scan_id", pr.ScanID).Msg("pr finalize failed")
			continue
		}
		_ = s.repo.MarkFinalized(ctx, pr.ID)
	}
}

func (s *GitHubAppService) finalize(ctx context.Context, pr repository.PRCheckRun) error {
	scan, err := s.scanRepo.GetByID(ctx, pr.ScanID)
	if err != nil {
		return err
	}
	findings, _ := s.findings.AllByScan(ctx, pr.ScanID)
	// Policy → conclusion. Evaluate against the project's active policy.
	passed, hasPolicy := true, false
	if policy, perr := s.policy.EvaluateSystem(ctx, pr.ScanID); perr == nil && policy != nil {
		passed, hasPolicy = policy.Passed, policy.HasPolicy
	}
	client := s.app.Client(pr.InstallationID)

	// Inline annotations on changed lines only.
	var annotations []githubapp.Annotation
	if changed, cerr := client.ChangedLines(ctx, pr.RepoFullName, pr.PRNumber); cerr == nil {
		annotations = buildAnnotations(findings, changed)
	}

	conclusion := ghConclusion(passed, hasPolicy, scan.Status)
	output := githubapp.CheckRunOutput{
		Title:       ghCheckTitle(passed, hasPolicy),
		Summary:     buildCheckSummary(scan, findings),
		Annotations: annotations,
	}
	if pr.CheckRunID != nil {
		if err := client.UpdateCheckRun(ctx, pr.RepoFullName, *pr.CheckRunID, conclusion, output); err != nil {
			return err
		}
	}

	// Single updateable PR comment.
	md := buildComment(s.scanURL(scan.ProjectID, scan.ID), scan, findings, passed, hasPolicy)
	var existing int64
	if pr.CommentID != nil {
		existing = *pr.CommentID
	}
	cid, err := client.UpsertIssueComment(ctx, pr.RepoFullName, pr.PRNumber, existing, md)
	if err != nil {
		return err
	}
	if pr.CommentID == nil || *pr.CommentID != cid {
		_ = s.repo.SetCommentID(ctx, pr.ID, cid)
	}
	return nil
}

func (s *GitHubAppService) scanURL(projectID, scanID string) string {
	base := strings.TrimSuffix(s.dashURL, "/")
	return fmt.Sprintf("%s/projects/%s/scans/%s", base, projectID, scanID)
}

// ── Pure builders (unit-tested) ───────────────────────────────────────────────

// ghConclusion maps the policy outcome to a GitHub check conclusion. Passing (or
// no policy) is success; a failed scan is failure; a policy violation is failure;
// with no policy configured we stay neutral so we never silently block.
func ghConclusion(passed, hasPolicy bool, scanStatus string) string {
	if scanStatus == "failed" {
		return "failure"
	}
	if !hasPolicy {
		return "neutral"
	}
	if passed {
		return "success"
	}
	return "failure"
}

func ghCheckTitle(passed, hasPolicy bool) string {
	if !hasPolicy {
		return "Aegis scan complete"
	}
	if passed {
		return "Quality gate passed"
	}
	return "Quality gate failed"
}

func buildCheckSummary(scan *models.Scan, findings []models.Finding) string {
	c := severityCounts(findings)
	return fmt.Sprintf("Aegis scanned this change. Grade **%s** (security %d, quality %d, deployment %d).\n\n"+
		"Findings — critical: %d, high: %d, medium: %d, low: %d.",
		orDash(derefStr(scan.OverallGrade)), derefIntP(scan.SecurityScore), derefIntP(scan.QualityScore),
		derefIntP(scan.DeploymentScore), c["critical"], c["high"], c["medium"], c["low"])
}

// buildComment renders the single PR comment: severity summary, top 5 findings,
// an AI-generated-code section, and a dashboard link. A hidden marker lets the
// updater find/replace the same comment (belt-and-suspenders alongside the id).
func buildComment(dashURL string, scan *models.Scan, findings []models.Finding, passed, hasPolicy bool) string {
	c := severityCounts(findings)
	var b strings.Builder
	b.WriteString("<!-- aegis-report -->\n")
	gate := "🔍 **Aegis scan complete**"
	if hasPolicy {
		if passed {
			gate = "✅ **Aegis quality gate passed**"
		} else {
			gate = "❌ **Aegis quality gate failed**"
		}
	}
	fmt.Fprintf(&b, "%s — grade **%s**\n\n", gate, orDash(derefStr(scan.OverallGrade)))
	fmt.Fprintf(&b, "| Critical | High | Medium | Low |\n|--:|--:|--:|--:|\n| %d | %d | %d | %d |\n\n",
		c["critical"], c["high"], c["medium"], c["low"])

	top := topFindings(findings, 5)
	if len(top) > 0 {
		b.WriteString("**Top findings**\n")
		for _, f := range top {
			title := derefStr(f.TitleHuman)
			if title == "" {
				title = f.Title
			}
			loc := f.FilePath
			if f.LineStart != nil {
				loc = fmt.Sprintf("%s:%d", f.FilePath, *f.LineStart)
			}
			newTag := ""
			if f.IsNew {
				newTag = " 🆕"
			}
			fmt.Fprintf(&b, "- **%s** `%s` — %s%s\n", strings.ToUpper(f.Severity), loc, title, newTag)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "[View the full report in Aegis](%s)\n", dashURL)
	return b.String()
}

// buildAnnotations emits inline annotations for findings on CHANGED lines only.
func buildAnnotations(findings []models.Finding, changed map[string]map[int]bool) []githubapp.Annotation {
	out := []githubapp.Annotation{}
	for _, f := range findings {
		if f.IsSuppressed || f.LineStart == nil {
			continue
		}
		lines, ok := changed[f.FilePath]
		if !ok || !lines[*f.LineStart] {
			continue // not a line this PR touched
		}
		title := derefStr(f.TitleHuman)
		if title == "" {
			title = f.Title
		}
		end := *f.LineStart
		if f.LineEnd != nil && *f.LineEnd >= *f.LineStart {
			end = *f.LineEnd
		}
		out = append(out, githubapp.Annotation{
			Path: f.FilePath, StartLine: *f.LineStart, EndLine: end,
			AnnotationLevel: ghAnnotationLevel(f.Severity), Title: title,
			Message: derefStr(f.Impact),
		})
	}
	return out
}

func ghAnnotationLevel(sev string) string {
	switch sev {
	case models.SeverityCritical, models.SeverityHigh:
		return "failure"
	case models.SeverityMedium:
		return "warning"
	default:
		return "notice"
	}
}

func severityCounts(findings []models.Finding) map[string]int {
	c := map[string]int{}
	for _, f := range findings {
		if f.IsSuppressed {
			continue
		}
		c[f.Severity]++
	}
	return c
}

func topFindings(findings []models.Finding, n int) []models.Finding {
	sorted := make([]models.Finding, 0, len(findings))
	for _, f := range findings {
		if !f.IsSuppressed && f.Severity != models.SeverityInfo {
			sorted = append(sorted, f)
		}
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		return sevRank(sorted[i].Severity) < sevRank(sorted[j].Severity)
	})
	if len(sorted) > n {
		sorted = sorted[:n]
	}
	return sorted
}

var _ = time.Now // reserved for future rate limiting
