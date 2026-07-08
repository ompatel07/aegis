-- 000020_admin.up.sql
-- Platform super-admin panel: a platform-level role, an append-only admin audit
-- log, feature flags, beta invitations, and a support inbox.

BEGIN;

ALTER TABLE users ADD COLUMN is_super_admin BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN suspended_at TIMESTAMPTZ;
ALTER TABLE organizations ADD COLUMN suspended_at TIMESTAMPTZ;

-- Append-only audit of every admin action (incl. impersonation + role grants).
CREATE TABLE admin_audit_log (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_user_id UUID        REFERENCES users (id) ON DELETE SET NULL,
    action        VARCHAR(64) NOT NULL,
    target_type   VARCHAR(32),
    target_id     VARCHAR(128),
    details       JSONB,
    ip            VARCHAR(64),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_admin_audit_created ON admin_audit_log (created_at DESC);
CREATE INDEX idx_admin_audit_admin ON admin_audit_log (admin_user_id, created_at DESC);

CREATE TABLE feature_flags (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    key          VARCHAR(64) NOT NULL UNIQUE,
    description  TEXT,
    enabled      BOOLEAN     NOT NULL DEFAULT FALSE,
    rollout_pct  INTEGER     NOT NULL DEFAULT 0 CHECK (rollout_pct BETWEEN 0 AND 100),
    enabled_orgs JSONB       NOT NULL DEFAULT '[]'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE beta_invitations (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    email           VARCHAR(320) NOT NULL,
    welcome_message TEXT,
    token           VARCHAR(64)  NOT NULL UNIQUE,
    status          VARCHAR(16)  NOT NULL DEFAULT 'sent'
                                 CHECK (status IN ('sent', 'accepted', 'expired', 'revoked')),
    invited_by      UUID         REFERENCES users (id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    accepted_at     TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ  NOT NULL
);
CREATE INDEX idx_beta_email ON beta_invitations (lower(email));

CREATE TABLE support_tickets (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID         REFERENCES users (id) ON DELETE SET NULL,
    email       VARCHAR(320),
    subject     VARCHAR(255) NOT NULL,
    message     TEXT         NOT NULL,
    status      VARCHAR(16)  NOT NULL DEFAULT 'new'
                             CHECK (status IN ('new', 'in_progress', 'resolved')),
    admin_reply TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX idx_support_status ON support_tickets (status, created_at DESC);

-- Per-scan thumbs-up/down feedback from the scan page widget (product signal).
CREATE TABLE scan_ratings (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id    UUID        NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    user_id    UUID        REFERENCES users (id) ON DELETE SET NULL,
    rating     VARCHAR(8)  NOT NULL CHECK (rating IN ('up', 'down')),
    comment    TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_scan_ratings_scan ON scan_ratings (scan_id);

-- Bootstrap: the first-registered user becomes the platform super admin.
UPDATE users SET is_super_admin = TRUE
 WHERE id = (SELECT id FROM users ORDER BY created_at ASC LIMIT 1);

COMMIT;
