-- 000014_organizations.up.sql
-- Organizations, team membership, roles, and invitations (Phase 2C TASK 5).
-- Projects move from single-user ownership to org ownership; existing projects
-- are migrated into a personal org per user so nothing breaks.

BEGIN;

CREATE TABLE organizations (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name          VARCHAR(255) NOT NULL,
    slug          VARCHAR(96)  NOT NULL UNIQUE,
    billing_email VARCHAR(320),
    plan          VARCHAR(32)  NOT NULL DEFAULT 'free',
    is_personal   BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE organization_members (
    org_id     UUID        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id    UUID        NOT NULL REFERENCES users (id)         ON DELETE CASCADE,
    role       VARCHAR(16) NOT NULL DEFAULT 'member'
                           CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    invited_by UUID        REFERENCES users (id) ON DELETE SET NULL,
    joined_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
);
CREATE INDEX idx_org_members_user ON organization_members (user_id);

CREATE TABLE organization_invitations (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    email       VARCHAR(320) NOT NULL,
    role        VARCHAR(16) NOT NULL DEFAULT 'member'
                            CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    token       VARCHAR(64) NOT NULL UNIQUE,
    invited_by  UUID        REFERENCES users (id) ON DELETE SET NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_org_invitations_email ON organization_invitations (lower(email));
CREATE INDEX idx_org_invitations_org   ON organization_invitations (org_id);

-- Projects now belong to an organization (nullable during backfill; the app
-- always sets it going forward).
ALTER TABLE projects ADD COLUMN organization_id UUID REFERENCES organizations (id) ON DELETE CASCADE;
CREATE INDEX idx_projects_org ON projects (organization_id);

-- Backfill: a personal org per existing user (they become owner) and migrate
-- their projects into it.
DO $$
DECLARE u RECORD;
        new_org UUID;
BEGIN
    FOR u IN SELECT id, email, name FROM users LOOP
        INSERT INTO organizations (name, slug, billing_email, plan, is_personal)
        VALUES (
            COALESCE(NULLIF(u.name, ''), 'Personal') || '''s workspace',
            'ws-' || replace(u.id::text, '-', ''),
            u.email, 'free', TRUE
        )
        RETURNING id INTO new_org;

        INSERT INTO organization_members (org_id, user_id, role) VALUES (new_org, u.id, 'owner');
        UPDATE projects SET organization_id = new_org WHERE user_id = u.id;
    END LOOP;
END $$;

COMMIT;
