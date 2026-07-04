-- 000012_ai_code_detection.down.sql

BEGIN;

DROP INDEX IF EXISTS idx_findings_ai_generated;
ALTER TABLE findings DROP COLUMN IF EXISTS in_ai_generated_code;
ALTER TABLE findings DROP COLUMN IF EXISTS ai_generated_probability;

ALTER TABLE scans DROP COLUMN IF EXISTS ai_generated_pct;
ALTER TABLE scans DROP COLUMN IF EXISTS ai_code_safety_score;
ALTER TABLE scans DROP COLUMN IF EXISTS ai_code_report;

COMMIT;
