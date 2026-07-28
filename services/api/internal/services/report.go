package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/aegis-platform/api/internal/ai"
	"github.com/aegis-platform/api/internal/models"
	"github.com/aegis-platform/api/internal/repository"
)

// ExecReport is a CISO-level, metadata-only executive summary of a scan.
type ExecReport struct {
	Project     string         `json:"project"`
	Scan        *models.Scan   `json:"scan"`
	Summary     string         `json:"summary"`
	TopRisks    []RiskItem     `json:"top_risks"`
	Trend       *Trend         `json:"trend,omitempty"`
	Priorities  []string       `json:"priorities"`
	GeneratedBy string         `json:"generated_by"` // template | ai:<provider>
}

type RiskItem struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Impact   string `json:"impact"`
	File     string `json:"file"`
}

type Trend struct {
	PreviousGrade string `json:"previous_grade"`
	CurrentGrade  string `json:"current_grade"`
	OverallDelta  int    `json:"overall_delta"`
	SecurityDelta int    `json:"security_delta"`
	Note          string `json:"note"`
}

// ReportService builds executive reports from findings metadata (never code).
type ReportService struct {
	scans    *repository.ScanRepository
	findings *repository.FindingRepository
	projects *repository.ProjectRepository
	backend  ai.Backend
	audit    *repository.AIAuditRepository
}

func NewReportService(
	scans *repository.ScanRepository, findings *repository.FindingRepository,
	projects *repository.ProjectRepository, backend ai.Backend, audit *repository.AIAuditRepository,
) *ReportService {
	return &ReportService{scans: scans, findings: findings, projects: projects, backend: backend, audit: audit}
}

func (s *ReportService) Executive(ctx context.Context, scanID, userID string) (*ExecReport, error) {
	scan, err := s.scans.GetByIDForUser(ctx, scanID, userID)
	if err != nil {
		return nil, err
	}
	project, err := s.projects.GetByIDForUser(ctx, scan.ProjectID, userID)
	if err != nil {
		return nil, err
	}
	findings, err := s.findings.AllByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}

	report := &ExecReport{
		Project:     project.Name,
		Scan:        scan,
		TopRisks:    topRisks(findings, 5),
		Trend:       s.trend(ctx, project.ID, scan),
		Priorities:  priorities(findings),
		GeneratedBy: "template",
		Summary:     templateSummary(project.Name, scan, findings),
	}

	// Optional AI-written prose — only if the project opted in and a backend is
	// configured. Sends ONLY metadata (counts + finding titles), never code.
	if project.AIFixEnabled && s.backend != nil {
		if prose := s.aiSummary(ctx, userID, project, scan, findings); prose != "" {
			report.Summary = prose
			report.GeneratedBy = "ai:" + s.backend.Provider()
		}
	}
	return report, nil
}

func (s *ReportService) aiSummary(ctx context.Context, userID string, project *models.Project, scan *models.Scan, findings []models.Finding) string {
	system := "You are a security analyst writing a concise CISO-level executive summary. " +
		"You are given ONLY finding statistics and titles (never code). Write one clear paragraph " +
		"(4-6 sentences) covering overall posture, the most serious risks, and the recommended focus."
	user := metadataDigest(project.Name, scan, findings)
	hash := ai.PromptHash(system, user)
	out, err := s.backend.Complete(ctx, system, user)
	_ = s.audit.Log(ctx, repository.AIAudit{
		UserID: &userID, ProjectID: &project.ID,
		Feature: "exec_report", Provider: s.backend.Provider(), Model: s.backend.Model(),
		PromptHash: hash, PromptChars: len(system) + len(user), Success: err == nil, Error: errString(err),
	})
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func (s *ReportService) trend(ctx context.Context, projectID string, scan *models.Scan) *Trend {
	prev, err := s.scans.PreviousCompleted(ctx, projectID, scan.CreatedAt)
	if err != nil {
		return nil
	}
	t := &Trend{
		PreviousGrade: derefStr(prev.OverallGrade),
		CurrentGrade:  derefStr(scan.OverallGrade),
		OverallDelta:  derefIntP(scan.OverallScore) - derefIntP(prev.OverallScore),
		SecurityDelta: derefIntP(scan.SecurityScore) - derefIntP(prev.SecurityScore),
	}
	switch {
	case t.OverallDelta > 0:
		t.Note = fmt.Sprintf("Overall score improved by %d points since the previous scan.", t.OverallDelta)
	case t.OverallDelta < 0:
		t.Note = fmt.Sprintf("Overall score dropped by %d points since the previous scan.", -t.OverallDelta)
	default:
		t.Note = "Overall score is unchanged from the previous scan."
	}
	return t
}

// ── Deterministic helpers (metadata only) ─────────────────────────────────────
func topRisks(findings []models.Finding, n int) []RiskItem {
	out := make([]RiskItem, 0, n)
	for _, f := range findings {
		if f.IsSuppressed || f.Severity == models.SeverityLow || f.Severity == models.SeverityInfo {
			continue
		}
		out = append(out, RiskItem{
			Title: firstNonEmpty(derefStr(f.TitleHuman), f.Title), Severity: f.Severity,
			Impact: derefStr(f.Impact), File: f.FilePath,
		})
		if len(out) >= n {
			break
		}
	}
	return out
}

func priorities(findings []models.Finding) []string {
	var crit, high, med int
	for _, f := range findings {
		if f.IsSuppressed {
			continue
		}
		switch f.Severity {
		case models.SeverityCritical:
			crit++
		case models.SeverityHigh:
			high++
		case models.SeverityMedium:
			med++
		}
	}
	var p []string
	if crit > 0 {
		p = append(p, fmt.Sprintf("Remediate %d critical finding(s) immediately — these are exploitable now.", crit))
	}
	if high > 0 {
		p = append(p, fmt.Sprintf("Schedule %d high-severity finding(s) into the current sprint.", high))
	}
	if med > 0 {
		p = append(p, fmt.Sprintf("Plan %d medium-severity finding(s) into the next release cycle.", med))
	}
	if len(p) == 0 {
		p = append(p, "No critical/high/medium findings — maintain current controls and monitor.")
	}
	return p
}

func templateSummary(project string, scan *models.Scan, findings []models.Finding) string {
	grade := derefStr(scan.OverallGrade)
	return fmt.Sprintf(
		"Project %q scored an overall grade of %s (security %d, quality %d, deployment %d). "+
			"The scan surfaced %d security issue(s), %d secret(s), and %d vulnerable dependency(ies). "+
			"See the prioritized risks below for the recommended order of remediation.",
		project, orDash(grade), derefIntP(scan.SecurityScore), derefIntP(scan.QualityScore),
		derefIntP(scan.DeploymentScore), scan.SecurityIssuesTotal, scan.SecretsFound, scan.VulnerabilitiesFound,
	)
}

func metadataDigest(project string, scan *models.Scan, findings []models.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Project: %s\nOverall grade: %s (security %d, quality %d, deployment %d)\n",
		project, orDash(derefStr(scan.OverallGrade)), derefIntP(scan.SecurityScore),
		derefIntP(scan.QualityScore), derefIntP(scan.DeploymentScore))
	fmt.Fprintf(&b, "Security issues: %d, secrets: %d, vulnerable deps: %d\n",
		scan.SecurityIssuesTotal, scan.SecretsFound, scan.VulnerabilitiesFound)
	b.WriteString("\nTop findings (title | severity):\n")
	for i, r := range topRisks(findings, 10) {
		fmt.Fprintf(&b, "%d. %s | %s\n", i+1, r.Title, r.Severity)
	}
	return b.String()
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefIntP(i *int) int {
	if i == nil {
		return 0
	}
	return *i
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
