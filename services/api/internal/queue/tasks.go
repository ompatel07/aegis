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
}
