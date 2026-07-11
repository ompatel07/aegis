package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/aegis-platform/api/internal/models"
)

// SSORepository persists SSO connections, SCIM tokens, and identity links.
type SSORepository struct {
	db *sqlx.DB
}

func NewSSORepository(db *sqlx.DB) *SSORepository { return &SSORepository{db: db} }

// ── Connections ──────────────────────────────────────────────────────────────

func (r *SSORepository) CreateConnection(ctx context.Context, c *models.SSOConnection) error {
	const q = `
		INSERT INTO sso_connections (organization_id, protocol, display_name, enabled, email_domain,
			oidc_issuer, oidc_client_id, oidc_client_secret_enc, oidc_scopes,
			saml_idp_entity_id, saml_idp_sso_url, saml_idp_certificate,
			attr_email, attr_name, default_role, jit_provisioning)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,COALESCE(NULLIF($9,''),'openid email profile'),
			$10,$11,$12,COALESCE(NULLIF($13,''),'email'),COALESCE(NULLIF($14,''),'name'),
			COALESCE(NULLIF($15,''),'member'),$16)
		RETURNING id, created_at, updated_at`
	return r.db.QueryRowxContext(ctx, q,
		c.OrganizationID, c.Protocol, c.DisplayName, c.Enabled, c.EmailDomain,
		c.OIDCIssuer, c.OIDCClientID, c.OIDCClientSecretEnc, c.OIDCScopes,
		c.SAMLIdPEntityID, c.SAMLIdPSSOURL, c.SAMLIdPCertificate,
		c.AttrEmail, c.AttrName, c.DefaultRole, c.JITProvisioning,
	).Scan(&c.ID, &c.CreatedAt, &c.UpdatedAt)
}

func (r *SSORepository) UpdateConnection(ctx context.Context, c *models.SSOConnection) error {
	const q = `
		UPDATE sso_connections SET
			display_name=$2, enabled=$3, email_domain=$4,
			oidc_issuer=$5, oidc_client_id=$6,
			oidc_client_secret_enc=COALESCE($7, oidc_client_secret_enc),
			oidc_scopes=$8, saml_idp_entity_id=$9, saml_idp_sso_url=$10,
			saml_idp_certificate=$11, attr_email=$12, attr_name=$13,
			default_role=$14, jit_provisioning=$15, updated_at=now()
		WHERE id=$1 AND organization_id=$16`
	res, err := r.db.ExecContext(ctx, q, c.ID, c.DisplayName, c.Enabled, c.EmailDomain,
		c.OIDCIssuer, c.OIDCClientID, c.OIDCClientSecretEnc, c.OIDCScopes,
		c.SAMLIdPEntityID, c.SAMLIdPSSOURL, c.SAMLIdPCertificate,
		c.AttrEmail, c.AttrName, c.DefaultRole, c.JITProvisioning, c.OrganizationID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *SSORepository) GetConnection(ctx context.Context, id string) (*models.SSOConnection, error) {
	var c models.SSOConnection
	if err := r.db.GetContext(ctx, &c, `SELECT * FROM sso_connections WHERE id=$1`, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &c, nil
}

// GetEnabledByDomain resolves the enabled connection that owns an email domain.
func (r *SSORepository) GetEnabledByDomain(ctx context.Context, domain string) (*models.SSOConnection, error) {
	var c models.SSOConnection
	err := r.db.GetContext(ctx, &c,
		`SELECT * FROM sso_connections WHERE enabled AND lower(email_domain)=lower($1) LIMIT 1`, domain)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &c, nil
}

func (r *SSORepository) ListConnections(ctx context.Context, orgID string) ([]models.SSOConnection, error) {
	var cs []models.SSOConnection
	err := r.db.SelectContext(ctx, &cs, `SELECT * FROM sso_connections WHERE organization_id=$1 ORDER BY created_at`, orgID)
	return cs, err
}

func (r *SSORepository) DeleteConnection(ctx context.Context, id, orgID string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM sso_connections WHERE id=$1 AND organization_id=$2`, id, orgID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ── SCIM tokens ──────────────────────────────────────────────────────────────

func (r *SSORepository) CreateSCIMToken(ctx context.Context, t *models.SCIMToken) error {
	return r.db.QueryRowxContext(ctx,
		`INSERT INTO scim_tokens (organization_id, token_hash, token_prefix, display_name, enabled)
		 VALUES ($1,$2,$3,$4,TRUE) RETURNING id, created_at`,
		t.OrganizationID, t.TokenHash, t.TokenPrefix, t.DisplayName).Scan(&t.ID, &t.CreatedAt)
}

// GetSCIMTokenByHash returns the enabled token matching a presented secret's hash.
func (r *SSORepository) GetSCIMTokenByHash(ctx context.Context, hash string) (*models.SCIMToken, error) {
	var t models.SCIMToken
	err := r.db.GetContext(ctx, &t, `SELECT * FROM scim_tokens WHERE token_hash=$1 AND enabled`, hash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &t, nil
}

func (r *SSORepository) TouchSCIMToken(ctx context.Context, id string) {
	_, _ = r.db.ExecContext(ctx, `UPDATE scim_tokens SET last_used_at=now() WHERE id=$1`, id)
}

func (r *SSORepository) ListSCIMTokens(ctx context.Context, orgID string) ([]models.SCIMToken, error) {
	var ts []models.SCIMToken
	err := r.db.SelectContext(ctx, &ts, `SELECT * FROM scim_tokens WHERE organization_id=$1 ORDER BY created_at`, orgID)
	return ts, err
}

func (r *SSORepository) RevokeSCIMToken(ctx context.Context, id, orgID string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE scim_tokens SET enabled=FALSE WHERE id=$1 AND organization_id=$2`, id, orgID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Identity links ───────────────────────────────────────────────────────────

// UpsertIdentity records (or reactivates) the external→user link for a connection.
func (r *SSORepository) UpsertIdentity(ctx context.Context, connID, userID, externalID string) (*models.SSOIdentity, error) {
	var id models.SSOIdentity
	err := r.db.QueryRowxContext(ctx, `
		INSERT INTO sso_identities (connection_id, user_id, external_id, active)
		VALUES ($1,$2,$3,TRUE)
		ON CONFLICT (connection_id, external_id)
		DO UPDATE SET user_id=EXCLUDED.user_id, active=TRUE, updated_at=now()
		RETURNING id, connection_id, user_id, external_id, active, created_at, updated_at`,
		connID, userID, externalID).StructScan(&id)
	if err != nil {
		return nil, fmt.Errorf("upsert identity: %w", err)
	}
	return &id, nil
}

func (r *SSORepository) GetIdentityByExternalID(ctx context.Context, connID, externalID string) (*models.SSOIdentity, error) {
	var id models.SSOIdentity
	err := r.db.GetContext(ctx, &id, `SELECT * FROM sso_identities WHERE connection_id=$1 AND external_id=$2`, connID, externalID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &id, nil
}

func (r *SSORepository) ListIdentities(ctx context.Context, connID string) ([]models.SSOIdentity, error) {
	var ids []models.SSOIdentity
	err := r.db.SelectContext(ctx, &ids, `SELECT * FROM sso_identities WHERE connection_id=$1 ORDER BY created_at`, connID)
	return ids, err
}

// SetIdentityActive toggles a link (SCIM deprovision/reprovision) and returns the user id.
func (r *SSORepository) SetIdentityActive(ctx context.Context, id string, active bool) error {
	_, err := r.db.ExecContext(ctx, `UPDATE sso_identities SET active=$2, updated_at=now() WHERE id=$1`, id, active)
	return err
}
