-- 000011_ai_layer.down.sql

BEGIN;

DROP TABLE IF EXISTS ai_audit_log;
ALTER TABLE projects DROP COLUMN IF EXISTS ai_fix_enabled;

COMMIT;
