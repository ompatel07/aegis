-- 000016_scan_stage.down.sql

BEGIN;

ALTER TABLE scans DROP COLUMN IF EXISTS stage;

COMMIT;
