package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jmoiron/sqlx"

	"github.com/aegis-platform/api/internal/models"
)

// IntelligenceRepository reads the vulnerability-intelligence tables.
type IntelligenceRepository struct {
	db *sqlx.DB
}

func NewIntelligenceRepository(db *sqlx.DB) *IntelligenceRepository {
	return &IntelligenceRepository{db: db}
}

// SyncStatus returns the most recent sync per source.
func (r *IntelligenceRepository) SyncStatus(ctx context.Context) ([]models.SyncStatus, error) {
	var out []models.SyncStatus
	err := r.db.SelectContext(ctx, &out,
		`SELECT DISTINCT ON (source)
		        source,
		        sync_started_at   AS last_started_at,
		        sync_completed_at AS last_completed_at,
		        status            AS last_status,
		        records_added,
		        records_updated
		   FROM intelligence_sync_log
		  ORDER BY source, sync_started_at DESC`)
	return out, err
}

// CVECounts returns cve_database row counts per source, plus the total.
func (r *IntelligenceRepository) CVECounts(ctx context.Context) (map[string]int, int, error) {
	rows, err := r.db.QueryxContext(ctx, `SELECT source, COUNT(*) FROM cve_database GROUP BY source`)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	counts := map[string]int{}
	total := 0
	for rows.Next() {
		var src string
		var n int
		if err := rows.Scan(&src, &n); err != nil {
			return nil, 0, err
		}
		counts[src] = n
		total += n
	}
	return counts, total, rows.Err()
}

// ListNotifications returns a user's notifications, newest first.
func (r *IntelligenceRepository) ListNotifications(ctx context.Context, userID string, limit int) ([]models.Notification, error) {
	out := []models.Notification{}
	err := r.db.SelectContext(ctx, &out,
		`SELECT id, project_id, kind, title, body, is_read, created_at
		   FROM notifications WHERE user_id = $1
		  ORDER BY created_at DESC LIMIT $2`,
		userID, limit)
	return out, err
}

// UnreadCount returns the number of unread notifications for a user.
func (r *IntelligenceRepository) UnreadCount(ctx context.Context, userID string) (int, error) {
	var n int
	err := r.db.GetContext(ctx, &n,
		`SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND is_read = FALSE`, userID)
	return n, err
}

// MarkNotificationRead marks one of the user's notifications read.
func (r *IntelligenceRepository) MarkNotificationRead(ctx context.Context, id, userID string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE notifications SET is_read = TRUE WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
