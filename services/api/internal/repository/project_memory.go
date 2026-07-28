package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
