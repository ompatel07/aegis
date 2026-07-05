-- 000015_policies.up.sql
-- Scan policies & quality gates (Phase 2C TASK 8). Configurable, per-project
-- policies that gate PR merges, plus a record of each scan's evaluation.

BEGIN;

CREATE TABLE project_policies (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    name        VARCHAR(96) NOT NULL,
    template    VARCHAR(32),                       -- startup | growing | enterprise | compliance | custom
    config_json JSONB       NOT NULL DEFAULT '{}'::jsonb,
    is_active   BOOLEAN     NOT NULL DEFAULT TRUE,  -- the policy evaluated for PR checks
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_project_policies_project ON project_policies (project_id);
-- At most one active policy per project.
CREATE UNIQUE INDEX idx_project_policies_active ON project_policies (project_id) WHERE is_active;

CREATE TABLE policy_evaluations (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id      UUID        NOT NULL REFERENCES scans (id)            ON DELETE CASCADE,
    policy_id    UUID        REFERENCES project_policies (id)          ON DELETE SET NULL,
    passed       BOOLEAN     NOT NULL,
    reasons_json JSONB       NOT NULL DEFAULT '[]'::jsonb,  -- per-check results
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scan_id)
);

COMMIT;
