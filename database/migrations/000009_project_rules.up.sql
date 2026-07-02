-- 000009_project_rules.up.sql
-- Customer-supplied per-project Semgrep rules, plus the rule-pack version a scan
-- ran with (for reproducibility / surfacing rule changes on re-scan).

BEGIN;

CREATE TABLE project_rules (
    id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID         NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    name       VARCHAR(255) NOT NULL,
    rule_yaml  TEXT         NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX idx_project_rules_project ON project_rules (project_id);

ALTER TABLE scans ADD COLUMN rule_pack_version VARCHAR(64);

COMMIT;
