-- 000009_project_rules.down.sql

BEGIN;

ALTER TABLE scans DROP COLUMN IF EXISTS rule_pack_version;
DROP TABLE IF EXISTS project_rules;

COMMIT;
