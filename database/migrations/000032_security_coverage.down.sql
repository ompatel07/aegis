-- 000032_security_coverage.down.sql
BEGIN;

ALTER TABLE scans DROP COLUMN IF EXISTS security_coverage;

COMMIT;
