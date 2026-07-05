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

// ── AI-code memory ────────────────────────────────────────────────────────────

type AICodePoint struct {
	Date   time.Time `json:"date"`
	Pct    float64   `json:"pct"`
	Safety int       `json:"safety"`
}

type AICodeMemory struct {
	ScansAnalyzed   int           `json:"scans_analyzed"`
	FirstSeen       *time.Time    `json:"first_seen,omitempty"`
	CurrentPct      float64       `json:"current_pct"`
	Trend           string        `json:"trend"` // growing | shrinking | stable | none
	AvgSafety       int           `json:"avg_safety"`
	Series          []AICodePoint `json:"series"`
	PersistentFiles []string      `json:"persistent_files"`
	Note            string        `json:"note"`
}

// AICodeMemory reconstructs how a project's AI-generated-code footprint has
// evolved across its completed scans (Phase 2C TASK 4c). Ownership checked by caller.
func (r *ProjectRepository) AICodeMemory(ctx context.Context, projectID string) (*AICodeMemory, error) {
	rows, err := r.db.QueryxContext(ctx, `
		SELECT created_at, COALESCE(ai_generated_pct, 0), COALESCE(ai_code_safety_score, 100), ai_code_report
		  FROM scans
		 WHERE project_id = $1 AND status = 'completed' AND ai_generated_pct IS NOT NULL
		 ORDER BY created_at ASC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := &AICodeMemory{Series: []AICodePoint{}, PersistentFiles: []string{}, Trend: "none"}
	var safetySum int
	fileHits := map[string]int{}
	for rows.Next() {
		var created time.Time
		var pct float64
		var safety int
		var report []byte
		if err := rows.Scan(&created, &pct, &safety, &report); err != nil {
			return nil, err
		}
		out.Series = append(out.Series, AICodePoint{Date: created, Pct: pct, Safety: safety})
		safetySum += safety
		if pct > 0 && out.FirstSeen == nil {
			c := created
			out.FirstSeen = &c
		}
		if len(report) > 0 {
			var rep struct {
				AIFiles []string `json:"ai_files"`
			}
			if json.Unmarshal(report, &rep) == nil {
				for _, f := range rep.AIFiles {
					fileHits[f]++
				}
			}
		}
	}

	n := len(out.Series)
	out.ScansAnalyzed = n
	if n == 0 {
		out.Note = "No scans with AI-code analysis yet."
		return out, nil
	}
	out.CurrentPct = out.Series[n-1].Pct
	out.AvgSafety = safetySum / n

	// Persistent AI files: present in 2+ scans.
	for f, hits := range fileHits {
		if hits >= 2 {
			out.PersistentFiles = append(out.PersistentFiles, f)
		}
	}

	// Trend: compare the latest scan to the mean of the earlier ones.
	if n >= 2 {
		var prevSum float64
		for _, p := range out.Series[:n-1] {
			prevSum += p.Pct
		}
		prevAvg := prevSum / float64(n-1)
		switch {
		case out.CurrentPct > prevAvg+3:
			out.Trend = "growing"
		case out.CurrentPct < prevAvg-3:
			out.Trend = "shrinking"
		default:
			out.Trend = "stable"
		}
	} else {
		out.Trend = "stable"
	}

	switch {
	case out.FirstSeen == nil:
		out.Note = "No AI-generated code detected across this project's scans."
	case out.Trend == "growing":
		out.Note = "AI-generated code is a growing share of this codebase — keep an eye on its review coverage."
	case out.Trend == "shrinking":
		out.Note = "AI-generated code's share is shrinking across recent scans."
	default:
		out.Note = "AI-generated code footprint is stable across recent scans."
	}
	return out, nil
}
