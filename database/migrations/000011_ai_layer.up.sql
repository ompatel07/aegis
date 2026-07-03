-- 000011_ai_layer.up.sql
-- Opt-in AI fix suggestions: per-project enablement + a full audit trail of
-- every AI call (enterprise requirement). AI is OFF by default.

BEGIN;

ALTER TABLE projects ADD COLUMN ai_fix_enabled BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE ai_audit_log (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID        REFERENCES users (id)    ON DELETE SET NULL,
    project_id   UUID        REFERENCES projects (id) ON DELETE SET NULL,
    finding_id   UUID,
    feature      VARCHAR(32) NOT NULL,   -- fix_suggestion | exec_report
    provider     VARCHAR(32) NOT NULL,
    model        VARCHAR(128),
    prompt_hash  VARCHAR(64) NOT NULL,   -- sha256 of the exact prompt sent
    prompt_chars INTEGER     NOT NULL DEFAULT 0,
    success      BOOLEAN     NOT NULL DEFAULT TRUE,
    error        TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_ai_audit_created ON ai_audit_log (created_at DESC);
CREATE INDEX idx_ai_audit_project ON ai_audit_log (project_id, created_at DESC);

COMMIT;
