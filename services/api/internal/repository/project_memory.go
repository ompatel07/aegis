package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// ── Baseline view ─────────────────────────────────────────────────────────────

type BaselineRule struct {
	RuleID          string  `db:"rule_id" json:"rule_id"`
	Engine          *string `db:"engine" json:"engine,omitempty"`
	AvgCountPerScan float64 `db:"avg_count_per_scan" json:"avg_count_per_scan"`
	TypicalSeverity *string `db:"typical_severity" json:"typical_severity,omitempty"`
	TimesSeen       int     `db:"times_seen" json:"times_seen"`
	IsGrandfathered bool    `db:"is_grandfathered" json:"is_grandfathered"`
}

type RuleStat struct {
	RuleID         string  `db:"rule_id" json:"rule_id"`
	TotalFeedback  int     `db:"total_feedback" json:"total_feedback"`
	FPCount        int     `db:"fp_count" json:"fp_count"`
	ConfirmedCount int     `db:"confirmed_count" json:"confirmed_count"`
	FPRate         float64 `db:"fp_rate" json:"fp_rate"`
}

type BaselineData struct {
	Established     bool            `json:"established"`
	ScanCount       int             `json:"scan_count"`
	GrandfatherMode bool            `json:"grandfather_mode"`
	Profile         json.RawMessage `json:"profile,omitempty"`
	Rules           []BaselineRule  `json:"rules"`
	TeamLearning    []RuleStat      `json:"team_learning"`
}

// Baseline returns the project's baseline profile, per-rule baseline, and the
// team-learning feedback stats. Ownership must be checked by the caller.
func (r *ProjectRepository) Baseline(ctx context.Context, projectID string, grandfatherMode bool) (*BaselineData, error) {
	out := &BaselineData{GrandfatherMode: grandfatherMode, Rules: []BaselineRule{}, TeamLearning: []RuleStat{}}

	var profile json.RawMessage
	err := r.db.QueryRowxContext(ctx,
		`SELECT scan_count, baseline_json FROM project_baselines WHERE project_id = $1`, projectID).
		Scan(&out.ScanCount, &profile)
	if err == nil {
		out.Established = true
		out.Profile = profile
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	if err := r.db.SelectContext(ctx, &out.Rules, `
		SELECT rule_id, engine, avg_count_per_scan, typical_severity, times_seen, is_grandfathered
		  FROM project_baseline_findings WHERE project_id = $1
		 ORDER BY avg_count_per_scan DESC, times_seen DESC LIMIT 25`, projectID); err != nil {
		return nil, err
	}
	if err := r.db.SelectContext(ctx, &out.TeamLearning, `
		SELECT rule_id, total_feedback, fp_count, confirmed_count, fp_rate
		  FROM project_rule_stats WHERE project_id = $1
		 ORDER BY total_feedback DESC LIMIT 25`, projectID); err != nil {
		return nil, err
	}
	return out, nil
}

// ── Finding lifecycle view (P1a) ──────────────────────────────────────────────

// FindingState is one distinct finding (by fingerprint) tracked across a
// project's scan history, with its current lifecycle status.
type FindingState struct {
	Fingerprint     string  `db:"fingerprint" json:"fingerprint"`
	RuleID          *string `db:"rule_id" json:"rule_id,omitempty"`
	Engine          *string `db:"engine" json:"engine,omitempty"`
	Severity        *string `db:"severity" json:"severity,omitempty"`
	FilePath        *string `db:"file_path" json:"file_path,omitempty"`
	Title           *string `db:"title" json:"title,omitempty"`
	Status          string  `db:"status" json:"status"`
	FirstSeenScanID *string `db:"first_seen_scan_id" json:"first_seen_scan_id,omitempty"`
	LastSeenScanID  *string `db:"last_seen_scan_id" json:"last_seen_scan_id,omitempty"`
	ResolvedScanID  *string `db:"resolved_scan_id" json:"resolved_scan_id,omitempty"`
	TimesSeen       int     `db:"times_seen" json:"times_seen"`
}

// LifecycleData is the project-wide lifecycle summary: counts per status plus the
// currently-resolved findings (which are absent from any current scan's findings,
// so they can only be surfaced from here).
type LifecycleData struct {
	Counts   map[string]int  `json:"counts"`
	Resolved []FindingState  `json:"resolved"`
}

// Lifecycle returns the per-status counts and the resolved findings for a project.
func (r *ProjectRepository) Lifecycle(ctx context.Context, projectID string) (*LifecycleData, error) {
	out := &LifecycleData{Counts: map[string]int{}, Resolved: []FindingState{}}

	rows, err := r.db.QueryxContext(ctx,
		`SELECT status, count(*) FROM project_finding_states WHERE project_id = $1 GROUP BY status`, projectID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			_ = rows.Close()
			return nil, err
		}
		out.Counts[status] = n
	}
	_ = rows.Close()

	if err := r.db.SelectContext(ctx, &out.Resolved, `
		SELECT fingerprint, rule_id, engine, severity, file_path, title, status,
		       first_seen_scan_id, last_seen_scan_id, resolved_scan_id, times_seen
		  FROM project_finding_states
		 WHERE project_id = $1 AND status = 'resolved'
		 ORDER BY updated_at DESC LIMIT 200`, projectID); err != nil {
		return nil, err
	}
	return out, nil
}

// RemediationEvidence is one vulnerability that was found and later proven fixed:
// the shape an auditor actually consumes. Aegis holds every element already —
// what it lacked before J3 was any path from the lifecycle table into the
// compliance report.
type RemediationEvidence struct {
	Fingerprint   string  `db:"fingerprint" json:"fingerprint"`
	RuleID        *string `db:"rule_id" json:"rule_id,omitempty"`
	Engine        *string `db:"engine" json:"engine,omitempty"`
	Severity      *string `db:"severity" json:"severity,omitempty"`
	FilePath      *string `db:"file_path" json:"file_path,omitempty"`
	Title         *string `db:"title" json:"title,omitempty"`
	CWEID         *string `db:"cwe_id" json:"cwe_id,omitempty"`
	OWASPCategory *string `db:"owasp_category" json:"owasp_category,omitempty"`
	// Scan identity at each end of the finding's life, so the claim is auditable
	// back to a specific scan rather than only to a date.
	FirstSeenScanID *string    `db:"first_seen_scan_id" json:"first_seen_scan_id,omitempty"`
	ResolvedScanID  *string    `db:"resolved_scan_id" json:"resolved_scan_id,omitempty"`
	FirstSeenAt     time.Time  `db:"first_seen_at" json:"first_seen_at"`
	ResolvedAt      time.Time  `db:"resolved_at" json:"resolved_at"`
	TimesSeen       int        `db:"times_seen" json:"times_seen"`
}

// RemediationEvidenceFor returns the project's resolved findings with the CWE /
// OWASP category needed to attribute each to a control.
//
// project_finding_states does not carry cwe_id or owasp_category, so those are
// recovered by joining back to the finding row from the last scan that saw it —
// that row is the authoritative record of what the finding was. A resolved
// finding is by definition absent from the current scan, which is exactly why a
// point-in-time findings query can never produce this evidence.
func (r *ProjectRepository) RemediationEvidenceFor(ctx context.Context, projectID string) ([]RemediationEvidence, error) {
	out := []RemediationEvidence{}
	err := r.db.SelectContext(ctx, &out, `
		SELECT s.fingerprint, s.rule_id, s.engine, s.severity, s.file_path, s.title,
		       f.cwe_id, f.owasp_category,
		       s.first_seen_scan_id, s.resolved_scan_id,
		       s.first_seen_at, s.updated_at AS resolved_at, s.times_seen
		  FROM project_finding_states s
		  LEFT JOIN findings f
		         ON f.fingerprint = s.fingerprint
		        AND f.scan_id = s.last_seen_scan_id
		 WHERE s.project_id = $1 AND s.status = 'resolved'
		 ORDER BY s.updated_at DESC
		 LIMIT 500`, projectID)
	return out, err
}
