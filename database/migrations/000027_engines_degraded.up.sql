-- 000027_engines_degraded.up.sql
-- D1: scan-level degradation. A scan can complete while an engine ran without full
-- coverage (broken custom rule pack) or failed outright. engines_degraded records
-- [{engine, reason, coverage_lost}], surfaced so a partial scan is never read clean.
BEGIN;
ALTER TABLE scans ADD COLUMN engines_degraded JSONB NOT NULL DEFAULT '[]'::jsonb;
COMMIT;
