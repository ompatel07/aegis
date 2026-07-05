package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog"

	"github.com/aegis-platform/api/internal/models"
	"github.com/aegis-platform/api/internal/repository"
	"github.com/aegis-platform/api/internal/vcs"
)

// VCSService wires GitLab/Bitbucket webhooks to scans and posts a single
// updateable MR/PR comment + a commit/pipeline status when the scan completes.
// It reuses the same comment builder + quality-gate engine as the GitHub App, so
// PR feedback is identical across every provider.
type VCSService struct {
	providers map[string]vcs.VCSProvider
	repo      *repository.VCSRepository
	projects  *repository.ProjectRepository
	scans     *ScanService
	scanRepo  *repository.ScanRepository
	findings  *repository.FindingRepository
	policy    *PolicyService
	dashURL   string
	log       zerolog.Logger
}

func NewVCSService(
	providers map[string]vcs.VCSProvider, repo *repository.VCSRepository, projects *repository.ProjectRepository,
	scans *ScanService, scanRepo *repository.ScanRepository, findings *repository.FindingRepository,
	policy *PolicyService, dashURL string, log zerolog.Logger,
) *VCSService {
	return &VCSService{providers: providers, repo: repo, projects: projects, scans: scans,
		scanRepo: scanRepo, findings: findings, policy: policy, dashURL: dashURL, log: log}
}

// Provider returns the named provider, or nil.
func (s *VCSService) Provider(name string) vcs.VCSProvider { return s.providers[name] }

// HandleWebhook processes a verified GitLab/Bitbucket event.
func (s *VCSService) HandleWebhook(ctx context.Context, providerName, eventHeader string, body []byte) error {
	p := s.providers[providerName]
	if p == nil {
		return nil
	}
	ev, err := p.ParseEvent(eventHeader, body)
	if err != nil {
		return err
	}
	switch ev.Kind {
	case vcs.EventPush:
		if ev.Branch != "" && ev.DefaultBranch != "" && ev.Branch != ev.DefaultBranch {
			return nil
		}
		_, err := s.triggerForRepo(ctx, ev)
		return err
	case vcs.EventMergeOpen:
		scan, err := s.triggerForRepo(ctx, ev)
		if err != nil || scan == nil {
			return err
		}
		// Pending status + tracking for finalization.
		_ = p.SetStatus(ctx, ev.ProjectRef, ev.CommitSHA, vcs.StatePending, "Aegis is scanning…", s.scanURL(scan.ProjectID, scan.ID))
		return s.repo.CreateTracking(ctx, &repository.VCSTracking{
			Provider: providerName, ScanID: scan.ID, ProjectRef: ev.ProjectRef,
			RepoFullName: ev.RepoFullName, PRNumber: ev.PRNumber, HeadSHA: ev.CommitSHA,
		})
	}
	return nil
}

func (s *VCSService) triggerForRepo(ctx context.Context, ev vcs.Event) (*models.Scan, error) {
	projectID, err := s.projects.FindIDByRepo(ctx, ev.RepoFullName)
	if err != nil {
		s.log.Info().Str("repo", ev.RepoFullName).Msg("no Aegis project for repo; skipping scan")
		return nil, nil
	}
	branch := ev.Branch
	if branch == "" {
		branch = ev.DefaultBranch
	}
	return s.scans.TriggerWebhook(ctx, projectID, branch, ev.CommitSHA)
}

// Reconcile finalizes completed MR/PR scans: comment + status, once per scan.
func (s *VCSService) Reconcile(ctx context.Context) {
	pending, err := s.repo.PendingFinalizations(ctx, 20)
	if err != nil {
		return
	}
	for _, t := range pending {
		p := s.providers[t.Provider]
		if p == nil {
			continue
		}
		if err := s.finalize(ctx, p, t); err != nil {
			s.log.Warn().Err(err).Str("provider", t.Provider).Str("scan_id", t.ScanID).Msg("vcs finalize failed")
			continue
		}
		_ = s.repo.MarkFinalized(ctx, t.ID)
	}
}

func (s *VCSService) finalize(ctx context.Context, p vcs.VCSProvider, t repository.VCSTracking) error {
	scan, err := s.scanRepo.GetByID(ctx, t.ScanID)
	if err != nil {
		return err
	}
	findings, _ := s.findings.AllByScan(ctx, t.ScanID)
	passed, hasPolicy := true, false
	if res, perr := s.policy.EvaluateSystem(ctx, t.ScanID); perr == nil && res != nil {
		passed, hasPolicy = res.Passed, res.HasPolicy
	}

	md := buildComment(s.scanURL(scan.ProjectID, scan.ID), scan, findings, passed, hasPolicy)
	var existing int64
	if t.CommentID != nil {
		existing = *t.CommentID
	}
	cid, err := p.UpsertComment(ctx, t.ProjectRef, t.PRNumber, existing, md)
	if err != nil {
		return err
	}
	if t.CommentID == nil || *t.CommentID != cid {
		_ = s.repo.SetCommentID(ctx, t.ID, cid)
	}

	state := vcs.StateSuccess
	if scan.Status == "failed" || (hasPolicy && !passed) {
		state = vcs.StateFailed
	}
	desc := ghCheckTitle(passed, hasPolicy)
	return p.SetStatus(ctx, t.ProjectRef, t.HeadSHA, state, desc, s.scanURL(scan.ProjectID, scan.ID))
}

func (s *VCSService) scanURL(projectID, scanID string) string {
	return fmt.Sprintf("%s/projects/%s/scans/%s", strings.TrimSuffix(s.dashURL, "/"), projectID, scanID)
}
