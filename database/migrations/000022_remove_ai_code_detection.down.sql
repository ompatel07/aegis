-- 000022_remove_ai_code_detection.down.sql
-- Restore the AI-code detection columns (unpopulated) if rolling back.

BEGIN;

ALTER TABLE findings ADD COLUMN IF NOT EXISTS in_ai_generated_code BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_generated_probability DOUBLE PRECISION;
CREATE INDEX IF NOT EXISTS idx_findings_ai_generated ON findings (scan_id) WHERE in_ai_generated_code;

ALTER TABLE scans ADD COLUMN IF NOT EXISTS ai_generated_pct     DOUBLE PRECISION;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS ai_code_safety_score INTEGER;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS ai_code_report       JSONB;

COMMIT;
