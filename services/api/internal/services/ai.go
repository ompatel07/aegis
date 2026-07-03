package services

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/aegis-platform/api/internal/ai"
	"github.com/aegis-platform/api/internal/models"
	"github.com/aegis-platform/api/internal/repository"
)

// ErrAIDisabled — no AI backend is configured on this instance.
var ErrAIDisabled = errors.New("AI features are not configured on this instance")

// ErrAINotEnabled — the project has not opted in to AI fix suggestions.
var ErrAINotEnabled = errors.New("AI fix suggestions are not enabled for this project")

// AIService produces opt-in, snippet-only, fully-audited fix suggestions.
type AIService struct {
	backend  ai.Backend
	findings *repository.FindingRepository
	audit    *repository.AIAuditRepository
}

func NewAIService(backend ai.Backend, findings *repository.FindingRepository, audit *repository.AIAuditRepository) *AIService {
	return &AIService{backend: backend, findings: findings, audit: audit}
}

// Enabled reports whether any backend is configured (for the UI to show the button).
func (s *AIService) Enabled() bool { return s.backend != nil }

// Provider returns the active backend name (or "disabled").
func (s *AIService) Provider() string {
	if s.backend == nil {
		return "disabled"
	}
	return s.backend.Provider()
}

// RecentAudit returns the user's recent AI-call audit entries.
func (s *AIService) RecentAudit(ctx context.Context, userID string, limit int) ([]repository.AIAuditEntry, error) {
	return s.audit.RecentForUser(ctx, userID, limit)
}

// SuggestFix returns an advisory fix for a finding the user owns, if the project
// has opted in. Every call — success or failure — is written to the audit log.
func (s *AIService) SuggestFix(ctx context.Context, findingID, userID string) (*ai.Suggestion, error) {
	if s.backend == nil {
		return nil, ErrAIDisabled
	}
	finding, err := s.findings.GetByIDForUser(ctx, findingID, userID)
	if err != nil {
		return nil, err
	}
	projectID, aiEnabled, language, err := s.findings.ProjectContextForFinding(ctx, findingID, userID)
	if err != nil {
		return nil, err
	}
	if !aiEnabled {
		return nil, ErrAINotEnabled
	}

	in := ai.FixInput{
		RuleName: firstNonEmpty(finding.RuleName, finding.Title),
		Message:  deref(finding.Description),
		CWE:      deref(finding.CWEID),
		File:     finding.FilePath,
		Line:     derefInt(finding.LineStart),
		Language: deref(language),
		Snippet:  snippetFrom(finding),
	}
	system, user := ai.BuildFixPrompt(in)
	hash := ai.PromptHash(system, user)

	completion, cerr := s.backend.Complete(ctx, system, user)

	_ = s.audit.Log(ctx, repository.AIAudit{
		UserID: &userID, ProjectID: &projectID, FindingID: &findingID,
		Feature: "fix_suggestion", Provider: s.backend.Provider(), Model: s.backend.Model(),
		PromptHash: hash, PromptChars: len(system) + len(user),
		Success: cerr == nil, Error: errString(cerr),
	})
	if cerr != nil {
		return nil, cerr
	}
	return &ai.Suggestion{Suggestion: completion, Model: s.backend.Model(), Provider: s.backend.Provider()}, nil
}

// snippetFrom returns the vulnerable snippet already captured with the finding —
// never the full file. Falls back to the description if no snippet was stored.
func snippetFrom(f *models.Finding) string {
	if len(f.Metadata) > 0 {
		var m map[string]any
		if json.Unmarshal(f.Metadata, &m) == nil {
			if lines, ok := m["lines"].(string); ok && lines != "" {
				return lines
			}
			if snip, ok := m["snippet"].(string); ok && snip != "" {
				return snip
			}
		}
	}
	if f.Description != nil {
		return *f.Description
	}
	return f.Title
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefInt(i *int) int {
	if i == nil {
		return 0
	}
	return *i
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return "finding"
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
