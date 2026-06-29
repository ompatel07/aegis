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
}

// deploymentRequest extends scanRequest with build controls.
type deploymentRequest struct {
	scanRequest
	SmokeTest           bool `json:"smoke_test"`
	StartTimeoutSeconds int  `json:"start_timeout_seconds"`
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

// SAST runs Semgrep.
func (s *ScannerClient) SAST(ctx context.Context, path, scanID string, langs, ptypes []string) (*types.EngineResult, error) {
	return s.call(ctx, "/scan/sast", s.base(path, scanID, langs, ptypes))
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
