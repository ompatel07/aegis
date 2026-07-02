package intelligence

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jmoiron/sqlx"
)

// Store is the intelligence DB layer (CVE mirror, sync log, notifications).
type Store struct {
	db *sqlx.DB
}

func NewStore(db *sqlx.DB) *Store { return &Store{db: db} }

// StartSync records a running sync and returns its id.
func (s *Store) StartSync(ctx context.Context, source string) (string, error) {
	var id string
	err := s.db.QueryRowxContext(ctx,
		`INSERT INTO intelligence_sync_log (source, status) VALUES ($1, 'running') RETURNING id`,
		source,
	).Scan(&id)
	return id, err
}

// FinishSync closes out a sync log row.
func (s *Store) FinishSync(ctx context.Context, id string, added, updated int, status, errMsg string) error {
	var errp *string
	if errMsg != "" {
		errp = &errMsg
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE intelligence_sync_log
		 SET sync_completed_at = now(), records_added = $2, records_updated = $3,
		     status = $4, error_message = $5
		 WHERE id = $1`,
		id, added, updated, status, errp,
	)
	return err
}

// UpsertCVE inserts or updates a CVE, returning whether the row was newly
// inserted (via the xmax=0 trick — 0 means this tuple was just inserted).
func (s *Store) UpsertCVE(ctx context.Context, c CVE) (bool, error) {
	affected, _ := json.Marshal(c.Affected)
	refs, _ := json.Marshal(c.References)
	var inserted bool
	err := s.db.QueryRowxContext(ctx,
		`INSERT INTO cve_database
		   (cve_id, description, cvss_v3_score, cvss_v3_vector, affected_packages,
		    published_date, modified_date, references_json, source, severity, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, now())
		 ON CONFLICT (cve_id) DO UPDATE SET
		    description = EXCLUDED.description,
		    cvss_v3_score = EXCLUDED.cvss_v3_score,
		    cvss_v3_vector = EXCLUDED.cvss_v3_vector,
		    affected_packages = EXCLUDED.affected_packages,
		    modified_date = EXCLUDED.modified_date,
		    references_json = EXCLUDED.references_json,
		    severity = EXCLUDED.severity,
		    updated_at = now()
		 RETURNING (xmax = 0) AS inserted`,
		c.CVEID, c.Description, c.CVSSScore, nullStr(c.CVSSVector), affected,
		c.Published, c.Modified, refs, c.Source, nullStr(c.Severity),
	).Scan(&inserted)
	return inserted, err
}

// FlagAffectedScans marks recent scans (<=90d) that flagged any of the affected
// package names as needing re-evaluation, and notifies the owning users once per
// (user, project). Returns the number of scans flagged.
func (s *Store) FlagAffectedScans(ctx context.Context, c CVE) (int, error) {
	names := packageNames(c)
	if len(names) == 0 {
		return 0, nil
	}
	reason := "New vulnerability " + c.CVEID + " affects a dependency in this scan."

	type row struct {
		ScanID    string `db:"id"`
		ProjectID string `db:"project_id"`
		UserID    string `db:"user_id"`
	}
	flagged := 0
	notified := map[string]bool{}

	for _, name := range names {
		var rows []row
		if err := s.db.SelectContext(ctx, &rows,
			`SELECT DISTINCT s.id, s.project_id, p.user_id
			   FROM scans s
			   JOIN projects p ON p.id = s.project_id
			   JOIN findings f ON f.scan_id = s.id
			  WHERE s.created_at > now() - interval '90 days'
			    AND f.metadata->>'package' = $1`,
			name,
		); err != nil {
			return flagged, err
		}
		for _, r := range rows {
			res, err := s.db.ExecContext(ctx,
				`UPDATE scans SET needs_reeval = TRUE, reeval_reason = $2
				  WHERE id = $1 AND needs_reeval = FALSE`,
				r.ScanID, reason,
			)
			if err != nil {
				return flagged, err
			}
			if n, _ := res.RowsAffected(); n > 0 {
				flagged++
			}
			key := r.UserID + "|" + r.ProjectID
			if !notified[key] {
				notified[key] = true
				if err := s.insertNotification(ctx, r.UserID, r.ProjectID, c); err != nil {
					return flagged, err
				}
			}
		}
	}
	return flagged, nil
}

func (s *Store) insertNotification(ctx context.Context, userID, projectID string, c CVE) error {
	// Collapse noise: at most one unread rescan notification per (user, project)
	// per day, so a sync that adds 100 CVEs doesn't create 100 alerts.
	var exists bool
	if err := s.db.GetContext(ctx, &exists,
		`SELECT EXISTS(SELECT 1 FROM notifications
		   WHERE user_id = $1 AND project_id = $2 AND kind = 'rescan_recommended'
		     AND is_read = FALSE AND created_at > now() - interval '24 hours')`,
		userID, projectID,
	); err == nil && exists {
		return nil
	}
	meta, _ := json.Marshal(map[string]any{"cve_id": c.CVEID, "cvss": c.CVSSScore})
	title := "New CVE affects a project — re-scan recommended"
	body := c.CVEID + " was published affecting a dependency in one of your scanned projects. Re-scan to reassess risk."
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO notifications (user_id, project_id, kind, title, body, metadata)
		 VALUES ($1, $2, 'rescan_recommended', $3, $4, $5)`,
		userID, projectID, title, body, meta,
	)
	return err
}

// SourceStatus is one row of the /intelligence/status response.
type SourceStatus struct {
	Source        string     `db:"source" json:"source"`
	LastStartedAt *time.Time `db:"last_started_at" json:"last_started_at"`
	LastStatus    *string    `db:"last_status" json:"last_status"`
	LastAdded     *int       `db:"last_added" json:"last_added"`
	LastUpdated   *int       `db:"last_updated" json:"last_updated"`
}

// Status returns the most recent sync per source.
func (s *Store) Status(ctx context.Context) ([]SourceStatus, error) {
	var out []SourceStatus
	err := s.db.SelectContext(ctx, &out,
		`SELECT DISTINCT ON (source)
		        source,
		        sync_started_at   AS last_started_at,
		        status            AS last_status,
		        records_added     AS last_added,
		        records_updated   AS last_updated
		   FROM intelligence_sync_log
		  ORDER BY source, sync_started_at DESC`,
	)
	return out, err
}

// Counts returns cve_database row counts per source.
func (s *Store) Counts(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryxContext(ctx, `SELECT source, COUNT(*) FROM cve_database GROUP BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var src string
		var n int
		if err := rows.Scan(&src, &n); err != nil {
			return nil, err
		}
		out[src] = n
	}
	return out, rows.Err()
}

// PkgRef is a distinct dependency seen in recent scans.
type PkgRef struct {
	Name      string `db:"name"`
	Ecosystem string `db:"eco"`
}

// RecentPackages returns distinct packages (with their detected ecosystem) that
// appeared in Trivy findings over the last 90 days — the set worth re-querying
// OSV for. Bounded so a source sync stays fast.
func (s *Store) RecentPackages(ctx context.Context, limit int) ([]PkgRef, error) {
	var out []PkgRef
	err := s.db.SelectContext(ctx, &out,
		`SELECT DISTINCT metadata->>'package' AS name,
		        COALESCE(metadata->>'reachability_ecosystem', '') AS eco
		   FROM findings f
		   JOIN scans s ON s.id = f.scan_id
		  WHERE s.created_at > now() - interval '90 days'
		    AND f.engine = 'trivy'
		    AND metadata->>'package' IS NOT NULL
		  LIMIT $1`,
		limit,
	)
	return out, err
}

func packageNames(c CVE) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range c.Affected {
		if a.Name != "" && !seen[a.Name] {
			seen[a.Name] = true
			out = append(out, a.Name)
		}
	}
	return out
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
