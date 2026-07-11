-- ─────────────────────────────────────────────────────────────────────────────
-- Enterprise SSO: SAML 2.0 + OIDC connections, SCIM 2.0 provisioning, and the
-- identity links that tie an external IdP subject to an Aegis user.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE sso_connections (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    protocol               TEXT NOT NULL CHECK (protocol IN ('oidc', 'saml')),
    display_name           TEXT NOT NULL DEFAULT '',
    enabled                BOOLEAN NOT NULL DEFAULT FALSE,

    -- Auto-routing: users with this verified email domain are sent to this IdP.
    email_domain           TEXT,

    -- OIDC (Okta / Auth0 / Azure AD / Google Workspace all speak this).
    oidc_issuer            TEXT,
    oidc_client_id         TEXT,
    oidc_client_secret_enc TEXT,                         -- AES-256-GCM at rest
    oidc_scopes            TEXT NOT NULL DEFAULT 'openid email profile',

    -- SAML 2.0 IdP descriptor.
    saml_idp_entity_id     TEXT,
    saml_idp_sso_url       TEXT,
    saml_idp_certificate   TEXT,                         -- PEM x509 signing cert

    -- Assertion → account attribute mapping + JIT policy.
    attr_email             TEXT NOT NULL DEFAULT 'email',
    attr_name              TEXT NOT NULL DEFAULT 'name',
    default_role           TEXT NOT NULL DEFAULT 'member',
    jit_provisioning       BOOLEAN NOT NULL DEFAULT TRUE,

    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One enabled connection may own a given email domain (routing must be unambiguous).
CREATE UNIQUE INDEX sso_connections_domain_uniq
    ON sso_connections (lower(email_domain))
    WHERE enabled AND email_domain IS NOT NULL;
CREATE INDEX sso_connections_org_idx ON sso_connections (organization_id);

-- SCIM 2.0 bearer tokens (one or more per org) used by the IdP to provision users.
CREATE TABLE scim_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,                -- sha256(token), hex
    token_prefix    TEXT NOT NULL DEFAULT '',            -- first chars, for display
    display_name    TEXT NOT NULL DEFAULT '',
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ
);
CREATE INDEX scim_tokens_org_idx ON scim_tokens (organization_id);

-- Links an external IdP subject (OIDC sub / SAML NameID / SCIM externalId) to an
-- Aegis user within a connection, enabling idempotent JIT login + SCIM lifecycle.
CREATE TABLE sso_identities (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id  UUID NOT NULL REFERENCES sso_connections(id) ON DELETE CASCADE,
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    external_id    TEXT NOT NULL,
    active         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (connection_id, external_id)
);
CREATE INDEX sso_identities_user_idx ON sso_identities (user_id);
