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
}
