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
//     ...but ONLY when the detector that raised it ran on this scan (N1):
//     its engine completed and, for per-rule engines, its rule executed.
//   - absent, and its rule no longer ships       -> RETIRED (neither open nor fixed)
//   - absent, detector did not run               -> unchanged (absence proves nothing)
//   - previously retired, present again          -> EXISTING (never fixed, only unchecked)
//
// The very first scan of a project establishes the baseline: everything is
// grandfathered as EXISTING (is_new = false) so the first PR isn't failed by the
// whole backlog. From the second scan on, a new instance of an already-seen rule
// correctly reads as NEW — the fix for the old rule-level gate weakness.
//
// Runs inside the SaveResults transaction so tagging + state update are atomic.
func applyLifecycle(ctx context.Context, tx *sqlx.Tx, projectID, scanID string, findings []types.Finding,
	ev types.LifecycleEvidence) error {
	if projectID == "" {
		return nil // nothing to anchor lifecycle to (e.g. ad-hoc scan)
	}

	// Prior state for this project: fingerprint -> status, plus the content key
	// and rule needed to recognise a finding whose file moved (J4).
	prior := map[string]string{}
	type priorRow struct {
		fingerprint string
		status      string
		ruleID      string
		codeKey     string
	}
	priorByCodeKey := map[string][]priorRow{}
	rows, err := tx.QueryxContext(ctx,
		`SELECT fingerprint, status, COALESCE(rule_id,''), COALESCE(code_key,'')
		   FROM project_finding_states WHERE project_id = $1`, projectID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var pr priorRow
		if err := rows.Scan(&pr.fingerprint, &pr.status, &pr.ruleID, &pr.codeKey); err != nil {
			_ = rows.Close()
			return err
		}
		prior[pr.fingerprint] = pr.status
		// Only active rows are migration candidates: a finding that was already
		// resolved should stay resolved, not be revived by a coincidental match.
		if pr.codeKey != "" && pr.status != statusResolved && pr.status != statusRetired {
			priorByCodeKey[pr.codeKey] = append(priorByCodeKey[pr.codeKey], pr)
		}
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

	// ── Rename migration (J4) ────────────────────────────────────────────────
	//
	// file_path is part of the fingerprint, so moving a file resolves every
	// finding in it and opens an identical set as new — a wave of fake
	// regressions and fake fixes on the same day. In an artifact whose value is
	// open-vs-closed, that is the worst possible false story.
	//
	// Why not git's rename detection, which the obvious design would use: we
	// clone with GIT_CLONE_DEPTH=1, so the previous scan's commit is not in the
	// working copy and `git diff --find-renames` between the two revisions cannot
	// run without an extra network fetch that may fail (force-push, GC, a scan of
	// a different branch, or an uploaded archive with no git history at all).
	//
	// Matching on the finding's own content is also strictly more precise for
	// this purpose. Git answers "was this file renamed, at 50% similarity"; we
	// need "is this the same finding", and a file can be 60% similar while the
	// vulnerable line itself was deleted and a different one introduced.
	//
	// The rule, deliberately conservative: a prior finding and a current finding
	// are the same only when their content keys are equal, their rule ids are
	// equal, and the pairing is strictly 1:1 — exactly one unmatched prior and
	// exactly one unmatched current finding carry that key. Anything ambiguous
	// (a file copied, one file split into two, identical code duplicated
	// elsewhere) leaves both sides alone and falls back to today's behaviour.
	// Guessing here would fabricate remediation evidence, which is worse than
	// reporting a move as a resolve plus a new finding.
	migrated := map[string]string{} // old fingerprint -> new fingerprint
	if !firstScan {
		// Current findings that matched nothing by fingerprint, grouped by content.
		unmatchedByCodeKey := map[string][]*types.Finding{}
		for i := range findings {
			f := &findings[i]
			if f.CodeKey == "" {
				continue
			}
			if _, seen := prior[f.Fingerprint]; seen {
				continue // already identified by its exact fingerprint
			}
			unmatchedByCodeKey[f.CodeKey] = append(unmatchedByCodeKey[f.CodeKey], f)
		}

		for codeKey, currents := range unmatchedByCodeKey {
			candidates := priorByCodeKey[codeKey]
			if len(currents) != 1 || len(candidates) != 1 {
				continue // ambiguous — decline to guess
			}
			cur, old := currents[0], candidates[0]
			if old.ruleID != cur.RuleID {
				continue // same code, different rule: not the same finding
			}
			if _, stillPresent := present[old.fingerprint]; stillPresent {
				continue // the old identity is alive in this scan; not a move
			}
			migrated[old.fingerprint] = cur.Fingerprint
		}

		// Re-key the state rows so the upsert below updates the existing history
		// (first_seen_at, times_seen) rather than creating a second row.
		for oldFP, newFP := range migrated {
			if _, err := tx.ExecContext(ctx,
				`UPDATE project_finding_states
				    SET fingerprint = $3, updated_at = now()
				  WHERE project_id = $1 AND fingerprint = $2`,
				projectID, oldFP, newFP); err != nil {
				return err
			}
			prior[newFP] = prior[oldFP]
			delete(prior, oldFP)
		}
	}

	const upsert = `
		INSERT INTO project_finding_states
			(project_id, fingerprint, rule_id, engine, severity, file_path, title,
			 status, first_seen_scan_id, last_seen_scan_id, times_seen, updated_at, code_key)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, 1, now(), $10)
		ON CONFLICT (project_id, fingerprint) DO UPDATE SET
			status            = $8,
			last_seen_scan_id = $9,
			resolved_scan_id  = NULL,
			severity          = $5,
			-- J4: follow the file. After a rename migration the row keeps its
			-- history but must point at where the finding actually lives now,
			-- otherwise the audit trail cites a path that no longer exists.
			file_path         = $6,
			-- Backfills code_key on rows written before J4, so a finding becomes
			-- rename-aware from its next scan onward.
			code_key          = COALESCE(NULLIF($10, ''), project_finding_states.code_key),
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
		case prior[fp] == statusRetired:
			// Its rule stopped running and has come back. It was never fixed, only
			// unchecked, so it is neither new nor a regression.
			status = statusExisting
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
			status, scanID, f.CodeKey,
		); err != nil {
			return err
		}
	}

	// Absence detection: every present finding's state row was just stamped with
	// last_seen_scan_id = scanID above, so any row still active (new/existing/
	// reopened) but NOT touched this scan is a finding that did not appear.
	//
	// Not appearing is only evidence of a fix when the detector that raised it ran
	// (N1). Before N1 every absent row was marked resolved, so a semgrep timeout, or
	// removing a rule, turned "we stopped looking" into "proven closed" -- and the
	// compliance report lists resolved findings as remediation evidence (J3).
	if !firstScan {
		rows, err := tx.QueryxContext(ctx, `
			SELECT fingerprint, COALESCE(engine,''), COALESCE(rule_id,'')
			  FROM project_finding_states
			 WHERE project_id = $1
			   AND status IN ('new', 'existing', 'reopened')
			   AND last_seen_scan_id IS DISTINCT FROM $2`, projectID, scanID)
		if err != nil {
			return err
		}
		var resolve, retire []string
		for rows.Next() {
			var fp, engine, ruleID string
			if err := rows.Scan(&fp, &engine, &ruleID); err != nil {
				_ = rows.Close()
				return err
			}
			switch absenceVerdict(ev, engine, ruleID) {
			case statusResolved:
				resolve = append(resolve, fp)
			case statusRetired:
				retire = append(retire, fp)
			}
		}
		_ = rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		// A retired finding carries no resolved_scan_id: no scan resolved it.
		const mark = `
			UPDATE project_finding_states
			SET status = $2, resolved_scan_id = $3, updated_at = now()
			WHERE project_id = $1 AND fingerprint = ANY($4)`
		for _, batch := range []struct {
			status       string
			resolvedScan any
			fps          []string
		}{{statusResolved, scanID, resolve}, {statusRetired, nil, retire}} {
			if len(batch.fps) == 0 {
				continue
			}
			if _, err := tx.ExecContext(ctx, mark, projectID, batch.status, batch.resolvedScan, batch.fps); err != nil {
				return err
			}
		}
	}

	return nil
}

// absenceVerdict decides what a finding's absence from this scan proves:
// statusResolved, statusRetired, or "" (nothing -- leave the row as it is).
func absenceVerdict(ev types.LifecycleEvidence, engine, ruleID string) string {
	if ev.Completed == nil {
		return statusResolved // no evidence supplied: pre-N1 behaviour
	}
	if !ev.Completed[engine] {
		return "" // engine failed, was skipped, or did not run: absence proves nothing
	}
	executed, perRule := ev.RulesExecuted[engine]
	if !perRule {
		return statusResolved // engine completed and has no per-rule sets
	}
	if executed[ruleID] {
		return statusResolved // its rule ran and did not fire: evidence of a fix
	}
	if shipped := ev.RulesShipped[engine]; shipped != nil && !shipped[ruleID] {
		return statusRetired // its rule no longer exists (N1) or a custom rule was removed
	}
	return "" // shipped but not run this scan (pack failed, language not detected)
}

const (
	statusNew      = "new"
	statusExisting = "existing"
	statusResolved = "resolved"
	statusReopened = "reopened"
	// statusRetired: the rule that raised the finding no longer runs (N1). Neither
	// open nor fixed; excluded from both sides of every open-vs-closed count.
	statusRetired = "retired"
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
