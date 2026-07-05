-- 000016_scan_stage.up.sql
-- Live scan progress (Phase 2C TASK 6): the current pipeline stage, updated as
-- the scan runs and pushed to the dashboard in real time (SSE) for onboarding.

BEGIN;

ALTER TABLE scans ADD COLUMN stage VARCHAR(24);

COMMIT;
