-- 000008_intelligence.down.sql

BEGIN;

DROP TABLE IF EXISTS notifications;
ALTER TABLE scans DROP COLUMN IF EXISTS needs_reeval, DROP COLUMN IF EXISTS reeval_reason;
DROP TABLE IF EXISTS intelligence_sync_log;
DROP TABLE IF EXISTS rule_registry;
DROP TABLE IF EXISTS cve_database;

COMMIT;
