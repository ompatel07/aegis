package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/go-resty/resty/v2"

	"github.com/aegis-platform/orchestrator/internal/types"
)

// ScannerClient is an HTTP client for the Python scanner service. Each call has
// retry with exponential backoff for transient (5xx / network) failures.
type ScannerClient struct {
	client *resty.Client
}

// scanRequest is the body for sast/sca/secrets/quality endpoints.
type scanRequest struct {
	Path         string   `json:"path"`
	ScanID       string   `json:"scan_id"`
	Languages    []string `json:"languages,omitempty"`
	ProjectTypes []string `json:"project_types,omitempty"`
	CustomRules  []string `json:"custom_rules,omitempty"`
}

// deploymentRequest extends scanRequest with build controls.
type deploymentRequest struct {
	scanRequest
	SmokeTest           bool `json:"smoke_test"`
	StartTimeoutSeconds int  `json:"start_timeout_seconds"`
}

// deepRequest selects the deep-scan backend (joern default, codeql opt-in).
type deepRequest struct {
	scanRequest
	Engine string `json:"engine"`
}

func NewScannerClient(baseURL string, timeout time.Duration) *ScannerClient {
	c := resty.New().
		SetBaseURL(baseURL).
		SetTimeout(timeout).
		SetRetryCount(3).
		SetRetryWaitTime(2 * time.Second).
		SetRetryMaxWaitTime(15 * time.Second).
		// Retry on transient transport errors and 5xx responses only.
		AddRetryCondition(func(r *resty.Response, err error) bool {
			return err != nil || r.StatusCode() >= 500
		})
	return &ScannerClient{client: c}
}

func (s *ScannerClient) call(ctx context.Context, endpoint string, body any) (*types.EngineResult, error) {
	var result types.EngineResult
	resp, err := s.client.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetBody(body).
		SetResult(&result).
		Post(endpoint)
	if err != nil {
		return nil, fmt.Errorf("scanner %s: %w", endpoint, err)
	}
	if resp.IsError() {
		return nil, fmt.Errorf("scanner %s returned %d: %s", endpoint, resp.StatusCode(), resp.String())
	}
	return &result, nil
}

func (s *ScannerClient) base(path, scanID string, langs, ptypes []string) scanRequest {
	return scanRequest{Path: path, ScanID: scanID, Languages: langs, ProjectTypes: ptypes}
}

// SAST runs Semgrep, applying any per-project custom rules on top of the packs.
func (s *ScannerClient) SAST(ctx context.Context, path, scanID string, langs, ptypes, customRules []string) (*types.EngineResult, error) {
	body := s.base(path, scanID, langs, ptypes)
	body.CustomRules = customRules
	return s.call(ctx, "/scan/sast", body)
}

// SCA runs Trivy.
func (s *ScannerClient) SCA(ctx context.Context, path, scanID string, langs, ptypes []string) (*types.EngineResult, error) {
	return s.call(ctx, "/scan/sca", s.base(path, scanID, langs, ptypes))
}

// Secrets runs Gitleaks.
func (s *ScannerClient) Secrets(ctx context.Context, path, scanID string, langs, ptypes []string) (*types.EngineResult, error) {
	return s.call(ctx, "/scan/secrets", s.base(path, scanID, langs, ptypes))
}

// Quality runs the quality engine.
func (s *ScannerClient) Quality(ctx context.Context, path, scanID string, langs, ptypes []string) (*types.EngineResult, error) {
	return s.call(ctx, "/scan/quality", s.base(path, scanID, langs, ptypes))
}

// Deployment runs the build + smoke harness.
func (s *ScannerClient) Deployment(ctx context.Context, path, scanID string, langs, ptypes []string) (*types.EngineResult, error) {
	return s.call(ctx, "/scan/deployment", deploymentRequest{
		scanRequest:         s.base(path, scanID, langs, ptypes),
		SmokeTest:           true,
		StartTimeoutSeconds: 30,
	})
}

type sbomRequest struct {
	Path   string `json:"path"`
	ScanID string `json:"scan_id"`
	Format string `json:"format"`
}

type sbomResponse struct {
	Format     string `json:"format"`
	Content    string `json:"content"`
	Components int    `json:"components"`
	Error      string `json:"error"`
}

// SBOM generates a Software Bill of Materials (format = cyclonedx | spdx) from the
// checked-out repo. Returns the document text + component count.
func (s *ScannerClient) SBOM(ctx context.Context, path, scanID, format string) (string, int, error) {
	var out sbomResponse
	resp, err := s.client.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetBody(sbomRequest{Path: path, ScanID: scanID, Format: format}).
		SetResult(&out).
		Post("/sbom")
	if err != nil {
		return "", 0, fmt.Errorf("scanner /sbom: %w", err)
	}
	if resp.IsError() {
		return "", 0, fmt.Errorf("scanner /sbom returned %d: %s", resp.StatusCode(), resp.String())
	}
	if out.Error != "" {
		return "", 0, fmt.Errorf("sbom: %s", out.Error)
	}
	return out.Content, out.Components, nil
}

// Deep runs the opt-in interprocedural taint scan (Joern or CodeQL). When the
// selected backend's tool is absent the scanner returns status=skipped (200),
// which surfaces here as a normal EngineResult, not an error.
func (s *ScannerClient) Deep(ctx context.Context, path, scanID, engine string) (*types.EngineResult, error) {
	if engine == "" {
		engine = "joern"
	}
	return s.call(ctx, "/scan/deep", deepRequest{
		scanRequest: s.base(path, scanID, nil, nil),
		Engine:      engine,
	})
}
