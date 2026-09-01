package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"

	"github.com/aegis-platform/api/internal/models"
)

// FindingRepository handles persistence for findings.
type FindingRepository struct {
	db *sqlx.DB
}

func NewFindingRepository(db *sqlx.DB) *FindingRepository {
	return &FindingRepository{db: db}
}

// FindingFilter captures optional list filters.
type FindingFilter struct {
	Pillar            string
	Severity          string
	Engine            string
	IncludeSuppressed bool
}

// ListByScan returns a filtered, paginated page of findings plus the total
// count matching the same filters.
func (r *FindingRepository) ListByScan(
	ctx context.Context, scanID string, f FindingFilter, limit, offset int,
) ([]models.Finding, int, error) {
	where := []string{"scan_id = $1"}
	args := []any{scanID}
	idx := 2

	if f.Pillar != "" {
		where = append(where, fmt.Sprintf("pillar = $%d", idx))
		args = append(args, f.Pillar)
		idx++
	}
	if f.Severity != "" {
		where = append(where, fmt.Sprintf("severity = $%d", idx))
		args = append(args, f.Severity)
		idx++
	}
	if f.Engine != "" {
		where = append(where, fmt.Sprintf("engine = $%d", idx))
		args = append(args, f.Engine)
		idx++
	}
	if !f.IncludeSuppressed {
		where = append(where, "is_suppressed = FALSE")
	}
	clause := strings.Join(where, " AND ")

	var total int
	countQ := "SELECT COUNT(*) FROM findings WHERE " + clause
	if err := r.db.GetContext(ctx, &total, countQ, args...); err != nil {
		return nil, 0, err
	}

	// KEV (actively exploited) first, then severity band, then push likely false
	// positives down within each band, then file/line/fingerprint for stable,
	// deterministic ordering across identical scans.
	listQ := fmt.Sprintf(`
		SELECT * FROM findings
		WHERE %s
		ORDER BY `+orderByFindings+`
		LIMIT $%d OFFSET $%d`, clause, idx, idx+1)
	args = append(args, limit, offset)

	findings := []models.Finding{}
	if err := r.db.SelectContext(ctx, &findings, listQ, args...); err != nil {
		return nil, 0, err
	}
	return findings, total, nil
}

// AllByScan returns every finding for a scan, unpaginated — for exports (SARIF).
// Capped defensively so a pathological scan can't stream unbounded rows.
func (r *FindingRepository) AllByScan(ctx context.Context, scanID string) ([]models.Finding, error) {
	findings, _, err := r.AllByScanCapped(ctx, scanID)
	return findings, err
}

// AllByScanCapped is AllByScan plus an explicit TRUNCATED flag. It fetches one row
// past the cap so it can tell a complete result from a truncated one, then trims to
// the cap. A truncated export must be surfaced (e.g. a SARIF notification), never
// returned as a complete-looking list — the clones[:60] / silent-truncation defect.
func (r *FindingRepository) AllByScanCapped(ctx context.Context, scanID string) (findings []models.Finding, truncated bool, err error) {
	q := `SELECT * FROM findings WHERE scan_id = $1 ORDER BY ` + orderByFindings + ` LIMIT $2`
	findings = []models.Finding{}
	if err = r.db.SelectContext(ctx, &findings, q, scanID, findingExportCap+1); err != nil {
		return nil, false, err
	}
	if len(findings) > findingExportCap {
		findings = findings[:findingExportCap]
		truncated = true
	}
	return findings, truncated, nil
}

// ProjectContextForFinding resolves the owning project's id, AI-fix flag, and
// language for a finding the user owns (finding -> scan -> project).
func (r *FindingRepository) ProjectContextForFinding(ctx context.Context, findingID, userID string) (projectID string, aiEnabled bool, language *string, err error) {
	err = r.db.QueryRowxContext(ctx,
		`SELECT p.id, p.ai_fix_enabled, p.language
		   FROM findings f
		   JOIN scans s    ON s.id = f.scan_id
		   JOIN projects p ON p.id = s.project_id
		  WHERE f.id = $1 AND p.organization_id IN (SELECT org_id FROM organization_members WHERE user_id = $2)`,
		findingID, userID).Scan(&projectID, &aiEnabled, &language)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return
}

// InsertFeedback records a user's action on a finding (ownership-checked via
// finding -> scan -> project -> user). Feeds the local FP classifier's training.
func (r *FindingRepository) InsertFeedback(ctx context.Context, findingID, userID, action, reason string) error {
	res, err := r.db.ExecContext(ctx,
		`INSERT INTO finding_feedback (finding_id, user_id, action, reason)
		 SELECT f.id, $2, $3, $4
		   FROM findings f
		   JOIN scans s    ON s.id = f.scan_id
		   JOIN projects p ON p.id = s.project_id
		  WHERE f.id = $1 AND p.organization_id IN (SELECT org_id FROM organization_members WHERE user_id = $2)`,
		findingID, userID, action, reason)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpsertRuleStats updates the project's per-rule feedback stats (team pattern
// learning, Phase 2C TASK 4). Dismissals (marked_fp/ignored/suppressed) count as
// false positives; confirmed/fixed count as confirmed. The blended fp_rate feeds
// a per-team personalization of the FP classifier at the next scan. Metadata only.
func (r *FindingRepository) UpsertRuleStats(ctx context.Context, findingID, userID, action string) error {
	fp, confirmed := 0, 0
	switch action {
	case "marked_fp", "ignored", "suppressed":
		fp = 1
	case "confirmed", "fixed":
		confirmed = 1
	default:
		return nil
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO project_rule_stats
			(project_id, rule_id, engine, total_feedback, fp_count, confirmed_count, fp_rate, updated_at)
		SELECT p.id, f.rule_id, f.engine, 1, $2::int, $3::int, $2::numeric, now()
		  FROM findings f
		  JOIN scans s    ON s.id = f.scan_id
		  JOIN projects p ON p.id = s.project_id
		 WHERE f.id = $1 AND p.organization_id IN (SELECT org_id FROM organization_members WHERE user_id = $4)
		ON CONFLICT (project_id, rule_id) DO UPDATE SET
			total_feedback  = project_rule_stats.total_feedback + 1,
			fp_count        = project_rule_stats.fp_count + $2::int,
			confirmed_count = project_rule_stats.confirmed_count + $3::int,
			fp_rate         = ROUND((project_rule_stats.fp_count + $2::int)::numeric
			                        / (project_rule_stats.total_feedback + 1), 3),
			updated_at      = now()`,
		findingID, fp, confirmed, userID)
	return err
}

// severityRankSQL maps severities to an orderable rank (critical = 0).
const severityRankSQL = `
	CASE severity
		WHEN 'critical' THEN 0
		WHEN 'high'     THEN 1
		WHEN 'medium'   THEN 2
		WHEN 'low'      THEN 3
		ELSE 4
	END`

// kevFirstSQL floats CISA-KEV (actively-exploited) findings to the very top,
// above every non-KEV finding regardless of CVSS band — the strongest triage
// signal leads. Display ordering only; detection/severity are untouched.
const kevFirstSQL = `CASE WHEN COALESCE(metadata->>'kev', '') = 'true' THEN 0 ELSE 1 END`

// reachableFirstSQL: within a severity band, a reachable finding (user input can hit
// it) outranks an unreachable one — reachability is the SCA differentiator, so it is
// part of the sort, not just a badge. See docs/UI_DATA_AUDIT.md § ordering.
const reachableFirstSQL = `CASE WHEN COALESCE(metadata->>'reachable', '') = 'true' THEN 0 ELSE 1 END`

// newFirstSQL: a regression introduced since the last scan ranks above pre-existing
// debt of equal severity/reachability — it is the cheap fix still in this PR.
const newFirstSQL = `CASE WHEN is_new THEN 0 ELSE 1 END`

// orderByFindings is the ONE canonical finding order, used by both the paginated
// list and the export: KEV → severity → reachable → new → likely-FP down → stable
// file/line/fingerprint. The web comparator (web/lib/findingOrder.ts) must reproduce
// this exactly or pagination and the rendered order drift; both are parity-tested
// (finding_order_test.go, findingOrder.test.ts) against the same fixture.
const orderByFindings = kevFirstSQL + `, ` + severityRankSQL + `, ` + reachableFirstSQL + `, ` + newFirstSQL +
	`, COALESCE(false_positive_probability, 0) ASC, file_path, line_start NULLS LAST, COALESCE(fingerprint, '')`

// findingExportCap bounds an unpaginated export so a pathological scan cannot stream
// unbounded rows. Hitting it is a TRUNCATION and must be surfaced, never returned as
// a complete-looking list (the clones[:60] defect class).
const findingExportCap = 50000

// GetByIDForUser loads a finding, enforcing ownership via scan → project → user.
// RoleInFindingOrg returns the caller's role in the org that owns the finding
// (finding → scan → project → org), or ErrNotFound if the finding is not visible
// to the caller. Used to gate finding writes (triage/feedback) on a minimum role.
func (r *FindingRepository) RoleInFindingOrg(ctx context.Context, findingID, userID string) (string, error) {
	const q = `SELECT om.role
		FROM findings f
		JOIN scans s               ON s.id = f.scan_id
		JOIN projects p            ON p.id = s.project_id
		JOIN organization_members om ON om.org_id = p.organization_id
		WHERE f.id = $1 AND om.user_id = $2`
	var role string
	if err := r.db.GetContext(ctx, &role, q, findingID, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return role, nil
}

func (r *FindingRepository) GetByIDForUser(ctx context.Context, id, userID string) (*models.Finding, error) {
	const q = `
		SELECT f.* FROM findings f
		JOIN scans s    ON s.id = f.scan_id
		JOIN projects p ON p.id = s.project_id
		WHERE f.id = $1 AND p.organization_id IN (SELECT org_id FROM organization_members WHERE user_id = $2)`
	var f models.Finding
	if err := r.db.GetContext(ctx, &f, q, id, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &f, nil
}

// UpdateTriage flips the false-positive / suppressed flags for a finding the
// user owns. Ownership is enforced inside the UPDATE so a foreign id is a no-op.
func (r *FindingRepository) UpdateTriage(
	ctx context.Context, id, userID string, isFalsePositive, isSuppressed *bool,
) (*models.Finding, error) {
	const q = `
		UPDATE findings f
		SET is_false_positive = COALESCE($3, f.is_false_positive),
		    is_suppressed     = COALESCE($4, f.is_suppressed)
		FROM scans s, projects p
		WHERE f.id = $1
		  AND s.id = f.scan_id
		  AND p.id = s.project_id
		  AND p.organization_id IN (SELECT org_id FROM organization_members WHERE user_id = $2)
		RETURNING f.*`
	var f models.Finding
	if err := r.db.QueryRowxContext(ctx, q, id, userID, isFalsePositive, isSuppressed).StructScan(&f); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &f, nil
}

// SeverityCount is one row of the report aggregation.
type SeverityCount struct {
	Pillar   string `db:"pillar" json:"pillar"`
	Severity string `db:"severity" json:"severity"`
	Count    int    `db:"count" json:"count"`
}

// AggregateByPillarSeverity powers the report endpoint's summary breakdown.
func (r *FindingRepository) AggregateByPillarSeverity(ctx context.Context, scanID string) ([]SeverityCount, error) {
	const q = `
		SELECT pillar, severity, COUNT(*) AS count
		FROM findings
		WHERE scan_id = $1 AND is_suppressed = FALSE
		GROUP BY pillar, severity`
	rows := []SeverityCount{}
	if err := r.db.SelectContext(ctx, &rows, q, scanID); err != nil {
		return nil, err
	}
	return rows, nil
}
