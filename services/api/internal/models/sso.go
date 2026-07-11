package models

import "time"

// SSOConnection is an org's SAML or OIDC identity-provider configuration.
type SSOConnection struct {
	ID             string `db:"id" json:"id"`
	OrganizationID string `db:"organization_id" json:"organization_id"`
	Protocol       string `db:"protocol" json:"protocol"` // oidc | saml
	DisplayName    string `db:"display_name" json:"display_name"`
	Enabled        bool   `db:"enabled" json:"enabled"`
	EmailDomain    *string `db:"email_domain" json:"email_domain"`

	// OIDC. The client secret is never serialized to JSON.
	OIDCIssuer          *string `db:"oidc_issuer" json:"oidc_issuer"`
	OIDCClientID        *string `db:"oidc_client_id" json:"oidc_client_id"`
	OIDCClientSecretEnc *string `db:"oidc_client_secret_enc" json:"-"`
	OIDCScopes          string  `db:"oidc_scopes" json:"oidc_scopes"`

	// SAML.
	SAMLIdPEntityID    *string `db:"saml_idp_entity_id" json:"saml_idp_entity_id"`
	SAMLIdPSSOURL      *string `db:"saml_idp_sso_url" json:"saml_idp_sso_url"`
	SAMLIdPCertificate *string `db:"saml_idp_certificate" json:"saml_idp_certificate"`

	AttrEmail       string `db:"attr_email" json:"attr_email"`
	AttrName        string `db:"attr_name" json:"attr_name"`
	DefaultRole     string `db:"default_role" json:"default_role"`
	JITProvisioning bool   `db:"jit_provisioning" json:"jit_provisioning"`

	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

// SCIMToken is a bearer credential an IdP uses to provision users via SCIM 2.0.
type SCIMToken struct {
	ID             string     `db:"id" json:"id"`
	OrganizationID string     `db:"organization_id" json:"organization_id"`
	TokenHash      string     `db:"token_hash" json:"-"`
	TokenPrefix    string     `db:"token_prefix" json:"token_prefix"`
	DisplayName    string     `db:"display_name" json:"display_name"`
	Enabled        bool       `db:"enabled" json:"enabled"`
	CreatedAt      time.Time  `db:"created_at" json:"created_at"`
	LastUsedAt     *time.Time `db:"last_used_at" json:"last_used_at"`
}

// SSOIdentity links an external IdP subject to an Aegis user under a connection.
type SSOIdentity struct {
	ID           string    `db:"id" json:"id"`
	ConnectionID string    `db:"connection_id" json:"connection_id"`
	UserID       string    `db:"user_id" json:"user_id"`
	ExternalID   string    `db:"external_id" json:"external_id"`
	Active       bool      `db:"active" json:"active"`
	CreatedAt    time.Time `db:"created_at" json:"created_at"`
	UpdatedAt    time.Time `db:"updated_at" json:"updated_at"`
}
