-- 000025_finding_lifecycle.down.sql
BEGIN;

DROP TABLE IF EXISTS project_finding_states;
DROP INDEX IF EXISTS idx_findings_fingerprint;
ALTER TABLE findings DROP COLUMN IF EXISTS fingerprint;
ALTER TABLE findings DROP COLUMN IF EXISTS lifecycle_status;

COMMIT;
