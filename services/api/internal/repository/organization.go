package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/jmoiron/sqlx"

	"github.com/aegis-platform/api/internal/models"
)

// OrganizationRepository handles orgs, membership, and invitations.
type OrganizationRepository struct {
	db *sqlx.DB
}

func NewOrganizationRepository(db *sqlx.DB) *OrganizationRepository {
	return &OrganizationRepository{db: db}
}

// Create inserts an organization and makes the creator its owner, atomically.
func (r *OrganizationRepository) Create(ctx context.Context, o *models.Organization, ownerID string) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	err = tx.QueryRowxContext(ctx, `
		INSERT INTO organizations (name, slug, billing_email, plan, is_personal)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, updated_at`,
		o.Name, o.Slug, o.BillingEmail, o.Plan, o.IsPersonal,
	).Scan(&o.ID, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate key") {
			return ErrConflict
		}
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO organization_members (org_id, user_id, role) VALUES ($1, $2, 'owner')`,
		o.ID, ownerID); err != nil {
		return err
	}
	return tx.Commit()
}

// ListForUser returns the orgs a user belongs to, with their role.
func (r *OrganizationRepository) ListForUser(ctx context.Context, userID string) ([]models.OrgMembership, error) {
	const q = `
		SELECT o.*, m.role
		  FROM organizations o
		  JOIN organization_members m ON m.org_id = o.id
		 WHERE m.user_id = $1
		 ORDER BY o.is_personal DESC, o.created_at ASC`
	out := []models.OrgMembership{}
	if err := r.db.SelectContext(ctx, &out, q, userID); err != nil {
		return nil, err
	}
	return out, nil
}

// PersonalOrgID returns the user's personal org id (created at registration).
func (r *OrganizationRepository) PersonalOrgID(ctx context.Context, userID string) (string, error) {
	var id string
	err := r.db.GetContext(ctx, &id, `
		SELECT o.id FROM organizations o
		  JOIN organization_members m ON m.org_id = o.id
		 WHERE m.user_id = $1 AND o.is_personal = TRUE
		 ORDER BY o.created_at ASC LIMIT 1`, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return id, err
}

// RoleOf returns the user's role in an org, or ErrNotFound if not a member.
func (r *OrganizationRepository) RoleOf(ctx context.Context, orgID, userID string) (string, error) {
	var role string
	err := r.db.GetContext(ctx, &role,
		`SELECT role FROM organization_members WHERE org_id = $1 AND user_id = $2`, orgID, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return role, err
}

// GetForUser loads an org the user is a member of.
func (r *OrganizationRepository) GetForUser(ctx context.Context, orgID, userID string) (*models.Organization, error) {
	const q = `
		SELECT o.* FROM organizations o
		  JOIN organization_members m ON m.org_id = o.id
		 WHERE o.id = $1 AND m.user_id = $2`
	var o models.Organization
	if err := r.db.GetContext(ctx, &o, q, orgID, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &o, nil
}

// UpdateSettings updates name + billing email (caller must be admin+).
func (r *OrganizationRepository) UpdateSettings(ctx context.Context, orgID, name string, billingEmail *string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE organizations SET name = $2, billing_email = $3, updated_at = now() WHERE id = $1`,
		orgID, name, billingEmail)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Members lists an org's members with identity.
func (r *OrganizationRepository) Members(ctx context.Context, orgID string) ([]models.OrgMember, error) {
	const q = `
		SELECT m.user_id, u.email, u.name, m.role, m.joined_at
		  FROM organization_members m
		  JOIN users u ON u.id = m.user_id
		 WHERE m.org_id = $1
		 ORDER BY m.joined_at ASC`
	out := []models.OrgMember{}
	if err := r.db.SelectContext(ctx, &out, q, orgID); err != nil {
		return nil, err
	}
	return out, nil
}

// AddMember inserts (or updates the role of) a member.
func (r *OrganizationRepository) AddMember(ctx context.Context, orgID, userID, role, invitedBy string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO organization_members (org_id, user_id, role, invited_by)
		VALUES ($1, $2, $3, NULLIF($4,'')::uuid)
		ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role`,
		orgID, userID, role, invitedBy)
	return err
}

// SetRole changes a member's role.
func (r *OrganizationRepository) SetRole(ctx context.Context, orgID, userID, role string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE organization_members SET role = $3 WHERE org_id = $1 AND user_id = $2`, orgID, userID, role)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RemoveMember deletes a membership.
func (r *OrganizationRepository) RemoveMember(ctx context.Context, orgID, userID string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM organization_members WHERE org_id = $1 AND user_id = $2`, orgID, userID)
	return err
}

// CountOwners returns how many owners an org has (to prevent orphaning it).
func (r *OrganizationRepository) CountOwners(ctx context.Context, orgID string) (int, error) {
	var n int
	err := r.db.GetContext(ctx, &n,
		`SELECT COUNT(*) FROM organization_members WHERE org_id = $1 AND role = 'owner'`, orgID)
	return n, err
}

// ── Invitations ───────────────────────────────────────────────────────────────

func (r *OrganizationRepository) CreateInvitation(ctx context.Context, inv *models.OrgInvitation, invitedBy string) error {
	return r.db.QueryRowxContext(ctx, `
		INSERT INTO organization_invitations (org_id, email, role, token, invited_by, expires_at)
		VALUES ($1, lower($2), $3, $4, $5, $6)
		RETURNING id, created_at`,
		inv.OrgID, inv.Email, inv.Role, inv.Token, invitedBy, inv.ExpiresAt,
	).Scan(&inv.ID, &inv.CreatedAt)
}

func (r *OrganizationRepository) ListInvitations(ctx context.Context, orgID string) ([]models.OrgInvitation, error) {
	const q = `SELECT * FROM organization_invitations
		WHERE org_id = $1 AND accepted_at IS NULL ORDER BY created_at DESC`
	out := []models.OrgInvitation{}
	if err := r.db.SelectContext(ctx, &out, q, orgID); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *OrganizationRepository) InvitationByToken(ctx context.Context, token string) (*models.OrgInvitation, error) {
	var inv models.OrgInvitation
	err := r.db.GetContext(ctx, &inv,
		`SELECT * FROM organization_invitations WHERE token = $1`, token)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &inv, err
}

func (r *OrganizationRepository) MarkInvitationAccepted(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE organization_invitations SET accepted_at = now() WHERE id = $1`, id)
	return err
}

func (r *OrganizationRepository) DeleteInvitation(ctx context.Context, orgID, id string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM organization_invitations WHERE id = $1 AND org_id = $2`, id, orgID)
	return err
}
