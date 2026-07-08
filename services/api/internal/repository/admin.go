package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/aegis-platform/api/internal/models"
)

// AdminRepository backs the platform super-admin panel. Queries here are NOT
// scoped to an org/user — they are platform-wide and only reachable behind the
// super-admin middleware.
type AdminRepository struct {
	db *sqlx.DB
}

func NewAdminRepository(db *sqlx.DB) *AdminRepository { return &AdminRepository{db: db} }

// IsSuperAdmin reports whether a user holds the platform super-admin role (and
// is not suspended). Used by the RequireSuperAdmin middleware.
func (r *AdminRepository) IsSuperAdmin(ctx context.Context, userID string) (bool, error) {
	var ok bool
	err := r.db.GetContext(ctx, &ok,
		`SELECT COALESCE(is_super_admin AND suspended_at IS NULL, FALSE) FROM users WHERE id = $1`, userID)
	if err != nil {
		return false, nil
	}
	return ok, nil
}

// ── Overview ──────────────────────────────────────────────────────────────────

func (r *AdminRepository) Overview(ctx context.Context) (*models.AdminOverview, error) {
	o := &models.AdminOverview{FindingsBySev: map[string]int{}}
	err := r.db.QueryRowxContext(ctx, `
		SELECT
			(SELECT count(*) FROM organizations),
			(SELECT count(*) FROM users),
			(SELECT count(*) FROM projects),
			(SELECT count(*) FROM scans),
			(SELECT count(*) FROM scans WHERE created_at > now() - interval '7 days'),
			(SELECT count(*) FROM scans WHERE created_at > now() - interval '30 days'),
			(SELECT count(*) FROM scans WHERE status IN ('queued','running')),
			(SELECT count(*) FROM users WHERE created_at > now() - interval '7 days'),
			(SELECT count(*) FROM support_tickets WHERE status <> 'resolved')`,
	).Scan(&o.Organizations, &o.Users, &o.Projects, &o.ScansTotal, &o.Scans7d, &o.Scans30d,
		&o.ActiveScans, &o.Signups7d, &o.OpenTickets)
	if err != nil {
		return nil, err
	}

	rows, err := r.db.QueryxContext(ctx, `SELECT severity, count(*) FROM findings GROUP BY severity`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return nil, err
		}
		o.FindingsBySev[sev] = n
	}
	return o, nil
}

// ── Organizations ─────────────────────────────────────────────────────────────

func (r *AdminRepository) ListOrgs(ctx context.Context, search string, limit int) ([]models.AdminOrgRow, error) {
	out := []models.AdminOrgRow{}
	err := r.db.SelectContext(ctx, &out, `
		SELECT o.id, o.name, o.slug, o.plan, o.is_personal, o.suspended_at, o.created_at,
			(SELECT count(*) FROM organization_members m WHERE m.org_id = o.id) AS members,
			(SELECT count(*) FROM projects p WHERE p.organization_id = o.id) AS projects,
			(SELECT count(*) FROM scans s JOIN projects p ON p.id = s.project_id WHERE p.organization_id = o.id) AS scans,
			(SELECT max(s.created_at) FROM scans s JOIN projects p ON p.id = s.project_id WHERE p.organization_id = o.id) AS last_activity
		FROM organizations o
		WHERE ($1 = '' OR o.name ILIKE '%'||$1||'%' OR o.slug ILIKE '%'||$1||'%')
		ORDER BY o.created_at DESC
		LIMIT $2`, search, limit)
	return out, err
}

func (r *AdminRepository) SuspendOrg(ctx context.Context, orgID string, suspend bool) error {
	var q string
	if suspend {
		q = `UPDATE organizations SET suspended_at = now(), updated_at = now() WHERE id = $1`
	} else {
		q = `UPDATE organizations SET suspended_at = NULL, updated_at = now() WHERE id = $1`
	}
	_, err := r.db.ExecContext(ctx, q, orgID)
	return err
}

func (r *AdminRepository) SetOrgPlan(ctx context.Context, orgID, plan string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE organizations SET plan = $2, updated_at = now() WHERE id = $1`, orgID, plan)
	return err
}

// ── Users ─────────────────────────────────────────────────────────────────────

func (r *AdminRepository) ListUsers(ctx context.Context, search string, limit int) ([]models.AdminUserRow, error) {
	out := []models.AdminUserRow{}
	err := r.db.SelectContext(ctx, &out, `
		SELECT u.id, u.email, u.name, u.is_super_admin, u.suspended_at, u.created_at,
			(SELECT count(*) FROM organization_members m WHERE m.user_id = u.id) AS orgs
		FROM users u
		WHERE ($1 = '' OR u.email ILIKE '%'||$1||'%' OR u.name ILIKE '%'||$1||'%')
		ORDER BY u.created_at DESC
		LIMIT $2`, search, limit)
	return out, err
}

func (r *AdminRepository) SetSuperAdmin(ctx context.Context, userID string, grant bool) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET is_super_admin = $2, updated_at = now() WHERE id = $1`, userID, grant)
	return err
}

func (r *AdminRepository) SuspendUser(ctx context.Context, userID string, suspend bool) error {
	var q string
	if suspend {
		q = `UPDATE users SET suspended_at = now(), updated_at = now() WHERE id = $1`
	} else {
		q = `UPDATE users SET suspended_at = NULL, updated_at = now() WHERE id = $1`
	}
	_, err := r.db.ExecContext(ctx, q, userID)
	return err
}

// ── Scans ─────────────────────────────────────────────────────────────────────

func (r *AdminRepository) ListScans(ctx context.Context, status string, limit int) ([]models.AdminScanRow, error) {
	out := []models.AdminScanRow{}
	err := r.db.SelectContext(ctx, &out, `
		SELECT s.id, s.project_id, p.name AS project_name, s.status, s.overall_grade,
			s.duration_seconds, s.error_message, s.created_at
		FROM scans s JOIN projects p ON p.id = s.project_id
		WHERE ($1 = '' OR s.status = $1)
		ORDER BY s.created_at DESC
		LIMIT $2`, status, limit)
	return out, err
}

// ── Audit ─────────────────────────────────────────────────────────────────────

func (r *AdminRepository) InsertAudit(ctx context.Context, adminID, action string, targetType, targetID *string, details map[string]any, ip string) error {
	var d []byte
	if len(details) > 0 {
		d, _ = json.Marshal(details)
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO admin_audit_log (admin_user_id, action, target_type, target_id, details, ip)
		VALUES (NULLIF($1,'')::uuid, $2, $3, $4, $5, NULLIF($6,''))`,
		adminID, action, targetType, targetID, d, ip)
	return err
}

func (r *AdminRepository) ListAudit(ctx context.Context, action string, limit int) ([]models.AdminAuditEntry, error) {
	out := []models.AdminAuditEntry{}
	err := r.db.SelectContext(ctx, &out, `
		SELECT a.id, a.admin_user_id, u.email AS admin_email, a.action, a.target_type, a.target_id,
			a.details, a.ip, a.created_at
		FROM admin_audit_log a
		LEFT JOIN users u ON u.id = a.admin_user_id
		WHERE ($1 = '' OR a.action = $1)
		ORDER BY a.created_at DESC
		LIMIT $2`, action, limit)
	return out, err
}

// ── Feature flags ─────────────────────────────────────────────────────────────

func (r *AdminRepository) ListFlags(ctx context.Context) ([]models.FeatureFlag, error) {
	out := []models.FeatureFlag{}
	return out, r.db.SelectContext(ctx, &out, `SELECT * FROM feature_flags ORDER BY key`)
}

func (r *AdminRepository) CreateFlag(ctx context.Context, key string, description *string) (*models.FeatureFlag, error) {
	var f models.FeatureFlag
	err := r.db.GetContext(ctx, &f, `
		INSERT INTO feature_flags (key, description) VALUES ($1, $2) RETURNING *`, key, description)
	return &f, err
}

func (r *AdminRepository) UpdateFlag(ctx context.Context, id string, enabled bool, rolloutPct int, enabledOrgs []string) error {
	orgs, _ := json.Marshal(enabledOrgs)
	if enabledOrgs == nil {
		orgs = []byte("[]")
	}
	_, err := r.db.ExecContext(ctx, `
		UPDATE feature_flags SET enabled = $2, rollout_pct = $3, enabled_orgs = $4, updated_at = now()
		WHERE id = $1`, id, enabled, rolloutPct, orgs)
	return err
}

func (r *AdminRepository) DeleteFlag(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM feature_flags WHERE id = $1`, id)
	return err
}

// ── Beta invitations ──────────────────────────────────────────────────────────

func (r *AdminRepository) ListBeta(ctx context.Context, limit int) ([]models.BetaInvitation, error) {
	out := []models.BetaInvitation{}
	return out, r.db.SelectContext(ctx, &out,
		`SELECT * FROM beta_invitations ORDER BY created_at DESC LIMIT $1`, limit)
}

func (r *AdminRepository) CreateBeta(ctx context.Context, email, welcome, token, invitedBy string, expires time.Time) (*models.BetaInvitation, error) {
	var b models.BetaInvitation
	err := r.db.GetContext(ctx, &b, `
		INSERT INTO beta_invitations (email, welcome_message, token, invited_by, expires_at)
		VALUES (lower($1), NULLIF($2,''), $3, NULLIF($4,'')::uuid, $5) RETURNING *`,
		email, welcome, token, invitedBy, expires)
	return &b, err
}

func (r *AdminRepository) SetBetaStatus(ctx context.Context, id, status string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE beta_invitations SET status = $2 WHERE id = $1`, id, status)
	return err
}

func (r *AdminRepository) BetaConversions(ctx context.Context) (sent, accepted int, err error) {
	err = r.db.QueryRowxContext(ctx,
		`SELECT count(*), count(*) FILTER (WHERE status = 'accepted') FROM beta_invitations`).Scan(&sent, &accepted)
	return
}

// ── Support tickets ───────────────────────────────────────────────────────────

func (r *AdminRepository) CreateTicket(ctx context.Context, userID, email, subject, message string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO support_tickets (user_id, email, subject, message)
		VALUES (NULLIF($1,'')::uuid, NULLIF($2,''), $3, $4)`, userID, email, subject, message)
	return err
}

func (r *AdminRepository) ListTickets(ctx context.Context, status string, limit int) ([]models.SupportTicket, error) {
	out := []models.SupportTicket{}
	return out, r.db.SelectContext(ctx, &out, `
		SELECT * FROM support_tickets
		WHERE ($1 = '' OR status = $1)
		ORDER BY created_at DESC LIMIT $2`, status, limit)
}

func (r *AdminRepository) ReplyTicket(ctx context.Context, id, reply, status string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE support_tickets SET admin_reply = $2, status = $3, updated_at = now() WHERE id = $1`,
		id, reply, status)
	return err
}

// ── Scan ratings (feedback widget) ────────────────────────────────────────────

// CreateScanRating stores a thumbs-up/down for a scan, but only for a scan the
// user can access (finding-style ownership via org membership).
func (r *AdminRepository) CreateScanRating(ctx context.Context, scanID, userID, rating, comment string) error {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO scan_ratings (scan_id, user_id, rating, comment)
		SELECT s.id, $2, $3, NULLIF($4,'')
		  FROM scans s JOIN projects p ON p.id = s.project_id
		 WHERE s.id = $1
		   AND p.organization_id IN (SELECT org_id FROM organization_members WHERE user_id = $2)`,
		scanID, userID, rating, comment)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Health ────────────────────────────────────────────────────────────────────

// Health returns platform liveness signals for the admin health page.
func (r *AdminRepository) Health(ctx context.Context) map[string]any {
	h := map[string]any{"db": "ok"}
	var queued, running, failed24h int
	err := r.db.QueryRowxContext(ctx, `
		SELECT
			(SELECT count(*) FROM scans WHERE status = 'queued'),
			(SELECT count(*) FROM scans WHERE status = 'running'),
			(SELECT count(*) FROM scans WHERE status = 'failed' AND created_at > now() - interval '24 hours')`,
	).Scan(&queued, &running, &failed24h)
	if err != nil {
		h["db"] = "error"
	}
	h["scans_queued"] = queued
	h["scans_running"] = running
	h["scans_failed_24h"] = failed24h
	return h
}
