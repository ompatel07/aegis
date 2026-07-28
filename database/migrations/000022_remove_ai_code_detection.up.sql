-- 000022_remove_ai_code_detection.up.sql
-- Remove the AI-generated-code DETECTION feature (Phase 2D). The classifier was
-- unproven on real data (ROC-AUC ~0.54; see AI_CODE_DETECTION_VALIDATION.md), so
-- its columns are dropped. The AI-failure-mode Semgrep RULES are unaffected —
-- their findings are ordinary security findings in the findings table.
-- Reversible: the down migration restores the columns (they'd just be unpopulated).

BEGIN;

DROP INDEX IF EXISTS idx_findings_ai_generated;
ALTER TABLE findings DROP COLUMN IF EXISTS in_ai_generated_code;
ALTER TABLE findings DROP COLUMN IF EXISTS ai_generated_probability;

ALTER TABLE scans DROP COLUMN IF EXISTS ai_generated_pct;
ALTER TABLE scans DROP COLUMN IF EXISTS ai_code_safety_score;
ALTER TABLE scans DROP COLUMN IF EXISTS ai_code_report;

COMMIT;
