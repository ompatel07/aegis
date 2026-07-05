package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/jmoiron/sqlx"

	"github.com/aegis-platform/orchestrator/internal/types"
)

// applyBaseline tags findings that deviate from the project's baseline (is_new)
// and updates the baseline with this scan. The first completed scan establishes
// the baseline: everything in it is grandfathered (is_new = false). On later
// scans, a finding whose rule was never seen before is flagged new. Runs inside
// the SaveResults transaction so tagging + baseline update are atomic.
func applyBaseline(ctx context.Context, tx *sqlx.Tx, projectID, scanID string, findings []types.Finding) error {
	if projectID == "" {
		return nil // nothing to anchor a baseline to
	}

	var scanCount int
	err := tx.QueryRowxContext(ctx,
		`SELECT scan_count FROM project_baselines WHERE project_id = $1`, projectID).Scan(&scanCount)
	firstScan := errors.Is(err, sql.ErrNoRows)
	if err != nil && !firstScan {
		return err
	}

	// Rules already known for this project (established before this scan).
	known := map[string]bool{}
	rows, err := tx.QueryxContext(ctx,
		`SELECT rule_id FROM project_baseline_findings WHERE project_id = $1`, projectID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var rid string
		if err := rows.Scan(&rid); err != nil {
			_ = rows.Close()
			return err
		}
		known[rid] = true
	}
	_ = rows.Close()

	// Tag new findings + tally this scan's per-rule counts.
	type agg struct {
		count    int
		engine   string
		severity string
	}
	counts := map[string]*agg{}
	for i := range findings {
		f := &findings[i]
		if !firstScan && !known[f.RuleID] {
			f.IsNew = true
		}
		a := counts[f.RuleID]
		if a == nil {
			a = &agg{engine: f.Engine, severity: f.Severity}
			counts[f.RuleID] = a
		}
		a.count++
	}

	// Upsert per-rule baseline (running average count; grandfather rules first
	// seen in the establishing scan).
	const upsertRule = `
		INSERT INTO project_baseline_findings
			(project_id, rule_id, engine, avg_count_per_scan, typical_severity, times_seen, is_grandfathered, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, 1, $6, now())
		ON CONFLICT (project_id, rule_id) DO UPDATE SET
			avg_count_per_scan = (project_baseline_findings.avg_count_per_scan * project_baseline_findings.times_seen + $4)
			                     / (project_baseline_findings.times_seen + 1),
			times_seen = project_baseline_findings.times_seen + 1,
			typical_severity = $5,
			last_seen_at = now()`
	for rid, a := range counts {
		if _, err := tx.ExecContext(ctx, upsertRule,
			projectID, rid, a.engine, a.count, a.severity, firstScan); err != nil {
			return err
		}
	}

	// Upsert the project baseline row with an aggregate profile.
	profile, _ := json.Marshal(buildBaselineProfile(findings))
	const upsertBaseline = `
		INSERT INTO project_baselines (project_id, baseline_json, scan_count, first_scan_id, last_updated_at)
		VALUES ($1, $2, 1, $3, now())
		ON CONFLICT (project_id) DO UPDATE SET
			baseline_json = $2,
			scan_count = project_baselines.scan_count + 1,
			last_updated_at = now()`
	if _, err := tx.ExecContext(ctx, upsertBaseline, projectID, profile, scanID); err != nil {
		return err
	}
	return nil
}

// buildBaselineProfile summarizes "what's normal" for the project from a scan's
// findings (severity mix, distinct rules) — metadata only.
func buildBaselineProfile(findings []types.Finding) map[string]any {
	sev := map[string]int{}
	rules := map[string]bool{}
	for _, f := range findings {
		sev[f.Severity]++
		rules[f.RuleID] = true
	}
	return map[string]any{
		"total_findings":      len(findings),
		"distinct_rules":      len(rules),
		"severity_breakdown":  sev,
	}
}

// applyTeamPriors blends each project's per-rule feedback history into the
// finding's false-positive probability — the team-level personalization. A team
// that consistently dismisses a rule pushes that rule's FP probability up for
// their own findings. Metadata only (rule_id + feedback counts).
func applyTeamPriors(ctx context.Context, tx *sqlx.Tx, projectID string, findings []types.Finding) error {
	if projectID == "" {
		return nil
	}
	priors := map[string]float64{}
	rows, err := tx.QueryxContext(ctx,
		`SELECT rule_id, fp_rate FROM project_rule_stats WHERE project_id = $1 AND total_feedback >= 3`, projectID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var rid string
		var rate float64
		if err := rows.Scan(&rid, &rate); err != nil {
			_ = rows.Close()
			return err
		}
		priors[rid] = rate
	}
	_ = rows.Close()
	if len(priors) == 0 {
		return nil
	}

	for i := range findings {
		rate, ok := priors[findings[i].RuleID]
		if !ok {
			continue
		}
		base := 0.0
		if findings[i].FalsePositiveProbability != nil {
			base = *findings[i].FalsePositiveProbability
		}
		blended := 0.5*base + 0.5*rate
		findings[i].FalsePositiveProbability = &blended
	}
	return nil
}
