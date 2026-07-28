package services

import (
	"context"
	"fmt"

	"github.com/aegis-platform/api/internal/models"
	"github.com/aegis-platform/api/internal/repository"
)

// PolicyService configures per-project gates and evaluates scans against them.
type PolicyService struct {
	policies *repository.PolicyRepository
	projects *repository.ProjectRepository
	scans    *repository.ScanRepository
	findings *repository.FindingRepository
}

func NewPolicyService(
	policies *repository.PolicyRepository, projects *repository.ProjectRepository,
	scans *repository.ScanRepository, findings *repository.FindingRepository,
) *PolicyService {
	return &PolicyService{policies: policies, projects: projects, scans: scans, findings: findings}
}

// Templates returns the named preset configurations for the UI.
func (s *PolicyService) Templates() map[string]models.PolicyConfig { return models.PolicyTemplates }

// Get returns a project's active policy (ownership enforced).
func (s *PolicyService) Get(ctx context.Context, projectID, userID string) (*models.Policy, error) {
	if _, err := s.projects.GetByIDForUser(ctx, projectID, userID); err != nil {
		return nil, err
	}
	return s.policies.GetActive(ctx, projectID)
}

// Set upserts the project's active policy. A template name expands to its preset
// unless an explicit config is supplied.
func (s *PolicyService) Set(ctx context.Context, projectID, userID, name, template string, cfg *models.PolicyConfig) (*models.Policy, error) {
	if _, err := s.projects.GetByIDForUser(ctx, projectID, userID); err != nil {
		return nil, err
	}
	config := models.PolicyConfig{}
	if cfg != nil {
		config = *cfg
	} else if preset, ok := models.PolicyTemplates[template]; ok {
		config = preset
	}
	if name == "" {
		name = template
		if name == "" {
			name = "custom"
		}
	}
	return s.policies.SetPolicy(ctx, projectID, name, template, config)
}

// PolicyResult is a scan's evaluation.
type PolicyResult struct {
	Passed   bool                 `json:"passed"`
	HasPolicy bool                `json:"has_policy"`
	PolicyName string             `json:"policy_name,omitempty"`
	Checks   []models.PolicyCheck `json:"checks"`
}

// Evaluate runs the project's active policy against a completed scan, stores the
// result, and returns it. With no policy configured, the scan trivially passes.
func (s *PolicyService) Evaluate(ctx context.Context, scanID, userID string) (*PolicyResult, error) {
	scan, err := s.scans.GetByIDForUser(ctx, scanID, userID)
	if err != nil {
		return nil, err
	}
	policy, err := s.policies.GetActive(ctx, scan.ProjectID)
	if err != nil {
		if err == repository.ErrNotFound {
			return &PolicyResult{Passed: true, HasPolicy: false, Checks: []models.PolicyCheck{}}, nil
		}
		return nil, err
	}
	findings, err := s.findings.AllByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}

	passed, checks := evaluatePolicy(policy.Config(), scan, findings)
	_ = s.policies.SaveEvaluation(ctx, scanID, &policy.ID, passed, checks)
	return &PolicyResult{Passed: passed, HasPolicy: true, PolicyName: policy.Name, Checks: checks}, nil
}

// EvaluateSystem evaluates + stores a scan's policy result WITHOUT a user
// context (for the GitHub App PR reconciler). Returns a nil result when there's
// no active policy.
func (s *PolicyService) EvaluateSystem(ctx context.Context, scanID string) (*PolicyResult, error) {
	scan, err := s.scans.GetByID(ctx, scanID)
	if err != nil {
		return nil, err
	}
	policy, err := s.policies.GetActive(ctx, scan.ProjectID)
	if err != nil {
		if err == repository.ErrNotFound {
			return &PolicyResult{Passed: true, HasPolicy: false, Checks: []models.PolicyCheck{}}, nil
		}
		return nil, err
	}
	findings, err := s.findings.AllByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	passed, checks := evaluatePolicy(policy.Config(), scan, findings)
	_ = s.policies.SaveEvaluation(ctx, scanID, &policy.ID, passed, checks)
	return &PolicyResult{Passed: passed, HasPolicy: true, PolicyName: policy.Name, Checks: checks}, nil
}

// evaluatePolicy is the pure gate engine — deterministic given the config, the
// scan's scores, and its findings (severity + new-vs-baseline).
func evaluatePolicy(cfg models.PolicyConfig, scan *models.Scan, findings []models.Finding) (bool, []models.PolicyCheck) {
	checks := []models.PolicyCheck{}
	add := func(rule string, passed bool, detail string) {
		checks = append(checks, models.PolicyCheck{Rule: rule, Passed: passed, Detail: detail})
	}

	worst, newCount, newWorst := "", 0, ""
	for _, f := range findings {
		if f.IsSuppressed || f.IsFalsePositive {
			continue
		}
		if sevRank(f.Severity) < sevRank(worst) {
			worst = f.Severity
		}
		if f.IsNew {
			newCount++
			if sevRank(f.Severity) < sevRank(newWorst) {
				newWorst = f.Severity
			}
		}
	}

	if cfg.MaxSeverity != "" {
		pass := !sevAtLeast(worst, cfg.MaxSeverity)
		add("max_severity", pass, fmt.Sprintf("worst finding: %s (gate: block %s+)", orNone(worst), cfg.MaxSeverity))
	}
	if cfg.BlockNewFindings {
		add("block_new_findings", newCount == 0, fmt.Sprintf("%d new finding(s) vs baseline", newCount))
	}
	if cfg.BlockNewSeverity != "" {
		pass := !sevAtLeast(newWorst, cfg.BlockNewSeverity)
		add("block_new_severity", pass, fmt.Sprintf("worst NEW finding: %s (gate: block new %s+)", orNone(newWorst), cfg.BlockNewSeverity))
	}
	if cfg.MinSecurityScore != nil {
		v := derefIntP(scan.SecurityScore)
		add("min_security_score", v >= *cfg.MinSecurityScore, fmt.Sprintf("security score %d (min %d)", v, *cfg.MinSecurityScore))
	}
	if cfg.MinQualityScore != nil {
		v := derefIntP(scan.QualityScore)
		add("min_quality_score", v >= *cfg.MinQualityScore, fmt.Sprintf("quality score %d (min %d)", v, *cfg.MinQualityScore))
	}

	passed := true
	for _, c := range checks {
		if !c.Passed {
			passed = false
		}
	}
	return passed, checks
}

// sevRank orders severities (lower = more severe); "" ranks below everything.
func sevRank(s string) int {
	switch s {
	case models.SeverityCritical:
		return 0
	case models.SeverityHigh:
		return 1
	case models.SeverityMedium:
		return 2
	case models.SeverityLow:
		return 3
	case models.SeverityInfo:
		return 4
	default:
		return 99
	}
}

// sevAtLeast reports whether a is at least as severe as threshold b.
func sevAtLeast(a, b string) bool {
	if a == "" {
		return false
	}
	return sevRank(a) <= sevRank(b)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
