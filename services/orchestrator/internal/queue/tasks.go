// Package queue mirrors the API's job contract so the orchestrator can decode
// the exact payload the API publishes.
package queue

// TypeScanRun must match the API's queue.TypeScanRun constant.
const TypeScanRun = "scan:run"

// ScanPayload mirrors the API's queue.ScanPayload.
type ScanPayload struct {
	ScanID    string `json:"scan_id"`
	ProjectID string `json:"project_id"`
	RepoURL   string `json:"repo_url"`
	RepoType  string `json:"repo_type"`
	Branch    string `json:"branch"`
	CommitSHA string `json:"commit_sha"`
	Trigger   string `json:"trigger"`
	Language  string `json:"language"`

	// CloneToken authenticates the git clone for private repos (GitHub App
	// installation token, or a per-project encrypted PAT). Transient job data —
	// never persisted to the scan record, never logged.
	CloneToken string `json:"clone_token,omitempty"`

	// UploadPath, when set, is a code archive (.zip/.tar.gz) to extract into a
	// per-scan sandbox instead of cloning (Method B — direct upload).
	UploadPath string `json:"upload_path,omitempty"`

	// Deep scan (opt-in interprocedural taint analysis: joern | codeql).
	DeepScanEnabled bool   `json:"deep_scan_enabled,omitempty"`
	DeepScanEngine  string `json:"deep_scan_engine,omitempty"`

	// CIMode gates the deployment pillar. Web/API scans leave it false (two-pillar
	// product: Security + Code Quality). Only a CI integration — running after the
	// customer's own pipeline built the workspace — sets it true, and even then
	// Aegis inspects the pre-built artifacts and never builds the code itself.
	CIMode bool `json:"ci_mode,omitempty"`

	// Per-project custom Semgrep rules (YAML documents) for this scan.
	CustomRules []string `json:"custom_rules,omitempty"`
}
