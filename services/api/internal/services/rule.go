package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/aegis-platform/api/internal/models"
	"github.com/aegis-platform/api/internal/repository"
)

// InvalidRuleError is returned when semgrep rejects an uploaded rule; the handler
// maps it to a 400 with the validation detail.
type InvalidRuleError struct{ Detail string }

func (e *InvalidRuleError) Error() string { return "invalid rule: " + e.Detail }

// RuleService manages per-project custom rules, validating them with the scanner
// (semgrep --validate) before they are stored.
type RuleService struct {
	projects   *repository.ProjectRepository
	rules      *repository.ProjectRuleRepository
	scannerURL string
	http       *http.Client
}

func NewRuleService(
	projects *repository.ProjectRepository,
	rules *repository.ProjectRuleRepository,
	scannerURL string,
) *RuleService {
	return &RuleService{
		projects:   projects,
		rules:      rules,
		scannerURL: scannerURL,
		http:       &http.Client{Timeout: 30 * time.Second},
	}
}

// Create validates the rule via the scanner, then stores it for the project.
func (s *RuleService) Create(ctx context.Context, projectID, userID, name, ruleYAML string) (*models.ProjectRule, error) {
	// Creating a custom rule is a state-changing action: viewers are read-only.
	if err := ensureWriteRole(s.projects.RoleInProjectOrg(ctx, projectID, userID)); err != nil {
		return nil, err
	}
	if _, err := s.projects.GetByIDForUser(ctx, projectID, userID); err != nil {
		return nil, err
	}
	if valid, detail, err := s.validate(ctx, ruleYAML); err != nil {
		return nil, err
	} else if !valid {
		return nil, &InvalidRuleError{Detail: detail}
	}
	pr := &models.ProjectRule{ProjectID: projectID, Name: name, RuleYAML: ruleYAML}
	if err := s.rules.Create(ctx, pr); err != nil {
		return nil, err
	}
	return pr, nil
}

func (s *RuleService) List(ctx context.Context, projectID, userID string) ([]models.ProjectRule, error) {
	if _, err := s.projects.GetByIDForUser(ctx, projectID, userID); err != nil {
		return nil, err
	}
	return s.rules.ListByProjectForUser(ctx, projectID, userID)
}

func (s *RuleService) Delete(ctx context.Context, ruleID, userID string) error {
	// Deleting a custom rule is a state-changing action: viewers are read-only.
	if err := ensureWriteRole(s.rules.RoleInRuleOrg(ctx, ruleID, userID)); err != nil {
		return err
	}
	return s.rules.DeleteByIDForUser(ctx, ruleID, userID)
}

// validate posts the rule to the scanner's /rules/validate (semgrep --validate).
func (s *RuleService) validate(ctx context.Context, ruleYAML string) (bool, string, error) {
	body, _ := json.Marshal(map[string]string{"rule_yaml": ruleYAML})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.scannerURL+"/rules/validate", bytes.NewReader(body))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("rule validation service unavailable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return false, "", fmt.Errorf("rule validation returned %d", resp.StatusCode)
	}
	var out struct {
		Valid bool   `json:"valid"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, "", err
	}
	return out.Valid, out.Error, nil
}
