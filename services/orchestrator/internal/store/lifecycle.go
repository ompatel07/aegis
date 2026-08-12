package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"

	"github.com/jmoiron/sqlx"

	"github.com/aegis-platform/orchestrator/internal/types"
)

// applyLifecycle is the instance-level finding lifecycle pass (P1a). It compares
// this scan's findings — identified by their stable, line-shift-resilient
// fingerprint (scanner utils/snippet.py) — against the project's prior state and
// classifies each as new / existing / reopened, records which findings this scan
// resolved, and sets f.IsNew accordingly.
//
// Rules:
//   - fingerprint never seen for this project  -> NEW      (is_new = true)
//   - previously resolved, present again        -> REOPENED (is_new = true)
//   - present before and now                    -> EXISTING (is_new = false)
//   - present before, absent now                -> RESOLVED (recorded on its state row)
//
// The very first scan of a project establishes the baseline: everything is
// grandfathered as EXISTING (is_new = false) so the first PR isn't failed by the
// whole backlog. From the second scan on, a new instance of an already-seen rule
// correctly reads as NEW — the fix for the old rule-level gate weakness.
//
// Runs inside the SaveResults transaction so tagging + state update are atomic.
func applyLifecycle(ctx context.Context, tx *sqlx.Tx, projectID, scanID string, findings []types.Finding) error {
	if projectID == "" {
		return nil // nothing to anchor lifecycle to (e.g. ad-hoc scan)
	}

	// Prior state for this project: fingerprint -> status.
	prior := map[string]string{}
	rows, err := tx.QueryxContext(ctx,
		`SELECT fingerprint, status FROM project_finding_states WHERE project_id = $1`, projectID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var fp, st string
		if err := rows.Scan(&fp, &st); err != nil {
			_ = rows.Close()
			return err
		}
		prior[fp] = st
	}
	_ = rows.Close()

	firstScan := len(prior) == 0

	// Ensure every finding has a fingerprint (scanner supplies it; fall back to a
	// deterministic rule+file+line basis so a finding is never left unkeyed).
	for i := range findings {
		if findings[i].Fingerprint == "" {
			findings[i].Fingerprint = fallbackFingerprint(&findings[i])
		}
	}

	// De-duplicate the current scan's fingerprints (multiple identical findings
	// already get distinct fingerprints via the scanner's per-basis ordinal; this
	// guards against any residual collision so upserts don't double-count).
	present := make(map[string]*types.Finding, len(findings))
	for i := range findings {
		f := &findings[i]
		if _, ok := present[f.Fingerprint]; !ok {
			present[f.Fingerprint] = f
		}
	}

	const upsert = `
		INSERT INTO project_finding_states
			(project_id, fingerprint, rule_id, engine, severity, file_path, title,
			 status, first_seen_scan_id, last_seen_scan_id, times_seen, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, 1, now())
		ON CONFLICT (project_id, fingerprint) DO UPDATE SET
			status            = $8,
			last_seen_scan_id = $9,
			resolved_scan_id  = NULL,
			severity          = $5,
			times_seen        = project_finding_states.times_seen + 1,
			last_seen_at      = now(),
			updated_at        = now()`

	// Classify + upsert each present finding.
	for fp, f := range present {
		var status string
		switch {
		case firstScan:
			status = statusExisting // baseline scan: grandfather everything
		case prior[fp] == "":
			status = statusNew
		case prior[fp] == statusResolved:
			status = statusReopened
		default:
			status = statusExisting
		}

		isNew := status == statusNew || status == statusReopened
		// Apply to every finding sharing this fingerprint (the deduped set).
		for i := range findings {
			if findings[i].Fingerprint == fp {
				findings[i].IsNew = isNew
				findings[i].LifecycleStatus = status
			}
		}

		if _, err := tx.ExecContext(ctx, upsert,
			projectID, fp, f.RuleID, f.Engine, f.Severity, f.FilePath, f.Title,
			status, scanID,
		); err != nil {
			return err
		}
	}

	// Resolved detection: every present finding's state row was just stamped with
	// last_seen_scan_id = scanID above. So any row that is still active
	// (new/existing/reopened) but was NOT touched this scan (its last_seen predates
	// this scan) is a finding that has gone away — resolved by this scan. This
	// avoids binding a fingerprint array and is exact. (First scan: nothing prior.)
	if !firstScan {
		const markResolved = `
			UPDATE project_finding_states
			SET status = $3, resolved_scan_id = $2, updated_at = now()
			WHERE project_id = $1
			  AND status IN ('new', 'existing', 'reopened')
			  AND last_seen_scan_id IS DISTINCT FROM $2`
		if _, err := tx.ExecContext(ctx, markResolved, projectID, scanID, statusResolved); err != nil {
			return err
		}
	}

	return nil
}

const (
	statusNew      = "new"
	statusExisting = "existing"
	statusResolved = "resolved"
	statusReopened = "reopened"
)

// fallbackFingerprint keeps a finding keyed even if the scanner didn't supply a
// fingerprint. Deterministic (rule + file + line), though not line-shift
// resilient — the scanner's content-based fingerprint is preferred.
func fallbackFingerprint(f *types.Finding) string {
	line := 0
	if f.LineStart != nil {
		line = *f.LineStart
	}
	sum := sha256.Sum256([]byte(f.RuleID + "\x1f" + f.FilePath + "\x1f" + strconv.Itoa(line)))
	return hex.EncodeToString(sum[:])[:32]
}
