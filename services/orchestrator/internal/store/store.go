// Package store is the orchestrator's data-access layer: it transitions scan
// state and persists findings + scores transactionally.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"

	// Register the pgx stdlib driver.
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/aegis-platform/orchestrator/internal/pipeline"
	"github.com/aegis-platform/orchestrator/internal/types"
)

// Store wraps the database connection pool.
type Store struct {
	db *sqlx.DB
}

// Connect opens and verifies a pooled connection.
func Connect(ctx context.Context, dsn string, maxOpen, maxIdle int, maxLife time.Duration) (*Store, error) {
	db, err := sqlx.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(maxLife)

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// MarkRunning transitions a scan to running and stamps started_at.
func (s *Store) MarkRunning(ctx context.Context, scanID string) error {
	const q = `UPDATE scans SET status = 'running', started_at = now() WHERE id = $1`
	_, err := s.db.ExecContext(ctx, q, scanID)
	return err
}

// MarkFailed transitions a scan to failed with an error message and timing.
func (s *Store) MarkFailed(ctx context.Context, scanID, msg string) error {
	const q = `
		UPDATE scans
		SET status = 'failed',
		    error_message = $2,
		    completed_at = now(),
		    duration_seconds = GREATEST(0, EXTRACT(EPOCH FROM (now() - COALESCE(started_at, queued_at)))::int)
		WHERE id = $1`
	_, err := s.db.ExecContext(ctx, q, scanID, msg)
	return err
}

// SaveResults persists findings and the completed scan in a single transaction:
// either all findings + the score update land, or nothing does.
func (s *Store) SaveResults(ctx context.Context, scanID string, agg pipeline.Aggregated) error {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	// Roll back on any path that doesn't reach Commit.
	defer func() { _ = tx.Rollback() }()

	if err := insertFindings(ctx, tx, scanID, agg.Findings); err != nil {
		return fmt.Errorf("insert findings: %w", err)
	}

	var errMsg any
	if len(agg.EngineErrors) > 0 {
		parts := make([]string, 0, len(agg.EngineErrors))
		for engine, e := range agg.EngineErrors {
			parts = append(parts, fmt.Sprintf("%s: %s", engine, e))
		}
		errMsg = "completed with degraded engines — " + strings.Join(parts, "; ")
	}

	const updateScan = `
		UPDATE scans SET
			status = 'completed',
			quality_score = $2, security_score = $3, deployment_score = $4,
			overall_score = $5, overall_grade = $6,
			quality_issues_total = $7, security_issues_total = $8,
			secrets_found = $9, vulnerabilities_found = $10,
			raw_semgrep_output = $11, raw_trivy_output = $12,
			raw_gitleaks_output = $13, raw_quality_output = $14,
			error_message = $15,
			completed_at = now(),
			duration_seconds = GREATEST(0, EXTRACT(EPOCH FROM (now() - COALESCE(started_at, queued_at)))::int)
		WHERE id = $1`
	if _, err := tx.ExecContext(ctx, updateScan,
		scanID,
		agg.QualityScore, agg.SecurityScore, agg.DeploymentScore,
		agg.OverallScore, agg.OverallGrade,
		agg.QualityIssuesTotal, agg.SecurityIssuesTotal,
		agg.SecretsFound, agg.VulnerabilitiesFound,
		[]byte(agg.RawSemgrep), []byte(agg.RawTrivy),
		[]byte(agg.RawGitleaks), []byte(agg.RawQuality),
		errMsg,
	); err != nil {
		return fmt.Errorf("update scan: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

const findingColumnCount = 18

// insertFindings bulk-inserts findings in chunks (bounded by Postgres' param limit).
func insertFindings(ctx context.Context, tx *sqlx.Tx, scanID string, findings []types.Finding) error {
	const chunkSize = 1000
	for start := 0; start < len(findings); start += chunkSize {
		end := start + chunkSize
		if end > len(findings) {
			end = len(findings)
		}
		query, args := buildInsert(scanID, findings[start:end])
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return err
		}
	}
	return nil
}

// buildInsert constructs a multi-row INSERT for a chunk of findings.
func buildInsert(scanID string, chunk []types.Finding) (string, []any) {
	var b strings.Builder
	b.WriteString(`INSERT INTO findings
		(scan_id, pillar, engine, rule_id, rule_name, severity, title, description,
		 file_path, line_start, line_end, column_start, column_end,
		 cwe_id, cve_id, owasp_category, fix_suggestion, metadata) VALUES `)

	args := make([]any, 0, len(chunk)*findingColumnCount)
	for i, f := range chunk {
		if i > 0 {
			b.WriteByte(',')
		}
		base := i * findingColumnCount
		b.WriteByte('(')
		for c := 0; c < findingColumnCount; c++ {
			if c > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, "$%d", base+c+1)
		}
		b.WriteByte(')')

		args = append(args,
			scanID, f.Pillar, f.Engine, f.RuleID, f.RuleName, f.Severity, f.Title,
			nullStr(f.Description), f.FilePath, f.LineStart, f.LineEnd, f.ColumnStart, f.ColumnEnd,
			nullStr(f.CWEID), nullStr(f.CVEID), nullStr(f.OWASPCategory),
			nullStr(f.FixSuggestion), metadataJSON(f.Metadata),
		)
	}
	return b.String(), args
}

// nullStr maps an empty string to SQL NULL.
func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// metadataJSON marshals the metadata map, returning NULL when empty.
func metadataJSON(m map[string]any) any {
	if len(m) == 0 {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return b
}
