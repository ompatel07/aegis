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

	// Order by severity, then push likely false positives down within each band
	// (FP-probability-adjusted priority), then file/line for stability.
	listQ := fmt.Sprintf(`
		SELECT * FROM findings
		WHERE %s
		ORDER BY %s, COALESCE(false_positive_probability, 0) ASC, file_path, line_start NULLS LAST
		LIMIT $%d OFFSET $%d`, clause, severityRankSQL, idx, idx+1)
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
	q := fmt.Sprintf(`
		SELECT * FROM findings
		WHERE scan_id = $1
		ORDER BY %s, COALESCE(false_positive_probability, 0) ASC, file_path, line_start NULLS LAST
		LIMIT 50000`, severityRankSQL)
	findings := []models.Finding{}
	if err := r.db.SelectContext(ctx, &findings, q, scanID); err != nil {
		return nil, err
	}
	return findings, nil
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
		  WHERE f.id = $1 AND p.user_id = $2`,
		findingID, userID, action, reason)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
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

// GetByIDForUser loads a finding, enforcing ownership via scan → project → user.
func (r *FindingRepository) GetByIDForUser(ctx context.Context, id, userID string) (*models.Finding, error) {
	const q = `
		SELECT f.* FROM findings f
		JOIN scans s    ON s.id = f.scan_id
		JOIN projects p ON p.id = s.project_id
		WHERE f.id = $1 AND p.user_id = $2`
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
		  AND p.user_id = $2
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
