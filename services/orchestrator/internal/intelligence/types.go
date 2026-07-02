// Package intelligence keeps Aegis's vulnerability database live by syncing from
// official feeds (NVD, OSV, GHSA, Semgrep registry) on a schedule, and
// retroactively flags past scans affected by newly-published CVEs.
package intelligence

import "time"

// CVE is a normalized vulnerability record from any source.
type CVE struct {
	CVEID       string
	Description string
	CVSSScore   *float64
	CVSSVector  string
	Affected    []AffectedPackage
	References  []string
	Published   *time.Time
	Modified    *time.Time
	Source      string // nvd | osv | ghsa
	Severity    string
}

// AffectedPackage identifies a vulnerable package + the version it is fixed in.
type AffectedPackage struct {
	Ecosystem  string `json:"ecosystem"`
	Name       string `json:"name"`
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// SyncResult summarizes one source sync.
type SyncResult struct {
	Source  string
	Added   int
	Updated int
	Skipped bool
	Note    string
}
