-- 000012_ai_code_detection.up.sql
-- AI-generated-code detection (Phase 2C TASK 3). Per-finding tagging of whether
-- a finding sits in AI-generated code, plus a per-scan AI-code report. All
-- derived locally from file metadata — no source code is stored.

BEGIN;

-- Per-finding: is this finding in a file the AI-code classifier flagged, and the
-- file's AI-generated probability (0..1) for context.
ALTER TABLE findings ADD COLUMN in_ai_generated_code BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE findings ADD COLUMN ai_generated_probability DOUBLE PRECISION;

CREATE INDEX idx_findings_ai_generated ON findings (scan_id) WHERE in_ai_generated_code;

-- Per-scan AI-code report: estimated % of the codebase that looks AI-generated,
-- an AI-code safety score (0..100), and the full breakdown as JSON (files scored,
-- findings in AI vs human code, top AI issues, why files were flagged).
ALTER TABLE scans ADD COLUMN ai_generated_pct     DOUBLE PRECISION;
ALTER TABLE scans ADD COLUMN ai_code_safety_score INTEGER;
ALTER TABLE scans ADD COLUMN ai_code_report       JSONB;

COMMIT;
