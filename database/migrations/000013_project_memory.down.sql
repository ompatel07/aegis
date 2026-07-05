-- 000013_project_memory.down.sql

BEGIN;

ALTER TABLE projects DROP COLUMN IF EXISTS grandfather_mode;
ALTER TABLE findings DROP COLUMN IF EXISTS is_new;
DROP TABLE IF EXISTS project_rule_stats;
DROP TABLE IF EXISTS project_baseline_findings;
DROP TABLE IF EXISTS project_baselines;

COMMIT;
