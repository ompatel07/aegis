-- 000007_context_rich_findings.down.sql

BEGIN;

ALTER TABLE findings
    DROP COLUMN IF EXISTS title_human,
    DROP COLUMN IF EXISTS impact,
    DROP COLUMN IF EXISTS risk_level,
    DROP COLUMN IF EXISTS remediation_action,
    DROP COLUMN IF EXISTS remediation_details,
    DROP COLUMN IF EXISTS estimated_effort,
    DROP COLUMN IF EXISTS context_metadata;

COMMIT;
