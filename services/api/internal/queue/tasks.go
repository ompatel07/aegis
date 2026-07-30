// Package queue defines the job contract between the API (producer) and the
// orchestrator (consumer), plus the Asynq publisher.
package queue

// TypeScanRun is the Asynq task type for executing a scan pipeline. The
// orchestrator registers a handler for this exact string.
const TypeScanRun = "scan:run"

// ScanPayload is the JSON payload carried by a scan job. It is intentionally
// self-contained so the orchestrator never needs to re-read the API's request.
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
	// installation token or a per-project encrypted PAT). Transient job data —
	// never persisted to the scan record, never logged.
	CloneToken string `json:"clone_token,omitempty"`

	// UploadPath, when set, is a code archive (.zip/.tar.gz) to extract into a
	// per-scan sandbox instead of cloning (Method B — direct upload).
	UploadPath string `json:"upload_path,omitempty"`

	// Deep scan (opt-in interprocedural taint analysis: joern | codeql).
	DeepScanEnabled bool   `json:"deep_scan_enabled,omitempty"`
	DeepScanEngine  string `json:"deep_scan_engine,omitempty"`

	// Per-project custom Semgrep rules (YAML documents) to apply for this scan.
	CustomRules []string `json:"custom_rules,omitempty"`
}
