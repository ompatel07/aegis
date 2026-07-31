package services

import (
	"context"
	"strings"

	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/models"
	"github.com/aegis-platform/api/internal/notify"
	"github.com/aegis-platform/api/internal/repository"
)

// NotificationService dispatches email + Slack notifications for scan events and
// manages per-user / per-project notification preferences.
type NotificationService struct {
	sender   notify.Sender
	slack    *notify.Slack
	repo     *repository.NotifyRepository
	scanRepo *repository.ScanRepository
	findings *repository.FindingRepository
	projects *repository.ProjectRepository
	dashURL  string
	log      zerolog.Logger
}

func NewNotificationService(
	sender notify.Sender, slack *notify.Slack, repo *repository.NotifyRepository,
	scanRepo *repository.ScanRepository, findings *repository.FindingRepository,
	projects *repository.ProjectRepository, dashURL string, log zerolog.Logger,
) *NotificationService {
	return &NotificationService{sender: sender, slack: slack, repo: repo, scanRepo: scanRepo,
		findings: findings, projects: projects, dashURL: dashURL, log: log}
}

func (s *NotificationService) EmailProvider() string { return s.sender.Name() }

// Dispatch sends notifications for any completed-but-unnotified scans, then marks
// them delivered. Runs on a background ticker.
func (s *NotificationService) Dispatch(ctx context.Context) {
	rows, err := s.repo.UndeliveredScans(ctx, 20)
	if err != nil {
		return
	}
	for _, row := range rows {
		s.dispatchOne(ctx, row)
		_ = s.repo.MarkNotified(ctx, row.ScanID)
	}
}

func (s *NotificationService) dispatchOne(ctx context.Context, row repository.ScanNotifyRow) {
	scan, err := s.scanRepo.GetByID(ctx, row.ScanID)
	if err != nil {
		return
	}
	findings, _ := s.findings.AllByScan(ctx, row.ScanID)
	newCriticals := newCriticalFindings(findings)
	scanURL := strings.TrimSuffix(s.dashURL, "/") + "/projects/" + row.ProjectID + "/scans/" + row.ScanID

	// Email — per recipient preference.
	if row.OrgID != "" {
		recipients, _ := s.repo.Recipients(ctx, row.OrgID)
		for _, rcpt := range recipients {
			if !rcpt.EmailEnabled {
				continue
			}
			if rcpt.EmailScanComplete {
				_ = s.sender.Send(ctx, notify.ScanCompleteEmail(rcpt.Email, scanURL, row.ProjectName, scan, findings))
			}
			if rcpt.EmailNewCritical && len(newCriticals) > 0 {
				_ = s.sender.Send(ctx, notify.NewCriticalEmail(rcpt.Email, scanURL, row.ProjectName, scan, newCriticals))
			}
		}
	}

	// Slack — per-project routing.
	if sl, _ := s.repo.GetProjectSlack(ctx, row.ProjectID); sl != nil && sl.Enabled && sl.WebhookURL != "" {
		if severityMeets(findings, sl.MinSeverity) {
			_ = s.slack.Post(ctx, sl.WebhookURL, notify.SlackScanMessage(scanURL, row.ProjectName, scan, findings))
		}
	}
}

// SendInvitation emails an org invitation (called from the invite flow).
func (s *NotificationService) SendInvitation(ctx context.Context, email, orgName, inviter, token string) {
	_ = s.sender.Send(ctx, notify.InvitationEmail(email, s.dashURL, orgName, inviter, token))
}

// ── Settings (user + project scoped) ──────────────────────────────────────────

func (s *NotificationService) GetSettings(ctx context.Context, userID string) (*models.NotificationSettings, error) {
	return s.repo.GetSettings(ctx, userID)
}

func (s *NotificationService) UpdateSettings(ctx context.Context, st *models.NotificationSettings) error {
	return s.repo.UpsertSettings(ctx, st)
}

func (s *NotificationService) GetProjectSlack(ctx context.Context, projectID, userID string) (*models.ProjectSlack, error) {
	if _, err := s.projects.GetByIDForUser(ctx, projectID, userID); err != nil {
		return nil, err
	}
	return s.repo.GetProjectSlack(ctx, projectID)
}

func (s *NotificationService) SetProjectSlack(ctx context.Context, projectID, userID, webhookURL string, enabled bool, minSeverity string) error {
	// Changing Slack notification settings is state-changing: viewers are read-only.
	if err := ensureWriteRole(s.projects.RoleInProjectOrg(ctx, projectID, userID)); err != nil {
		return err
	}
	if _, err := s.projects.GetByIDForUser(ctx, projectID, userID); err != nil {
		return err
	}
	if minSeverity == "" {
		minSeverity = "high"
	}
	return s.repo.SetProjectSlack(ctx, projectID, webhookURL, enabled, minSeverity)
}

// ── Pure helpers (unit-tested) ────────────────────────────────────────────────

// newCriticalFindings returns critical findings that deviate from the baseline.
func newCriticalFindings(findings []models.Finding) []models.Finding {
	out := []models.Finding{}
	for _, f := range findings {
		if f.IsSuppressed {
			continue
		}
		if f.Severity == models.SeverityCritical && f.IsNew {
			out = append(out, f)
		}
	}
	return out
}

// severityMeets reports whether any finding is at/above the threshold ("all"
// matches anything present).
func severityMeets(findings []models.Finding, threshold string) bool {
	want := sevRank(threshold)
	if threshold == "all" {
		want = 99
	}
	for _, f := range findings {
		if f.IsSuppressed {
			continue
		}
		if sevRank(f.Severity) <= want {
			return true
		}
	}
	return false
}
