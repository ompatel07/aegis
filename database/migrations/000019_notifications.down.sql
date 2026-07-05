-- 000019_notifications.down.sql

BEGIN;

ALTER TABLE scans DROP COLUMN IF EXISTS notified_at;
DROP TABLE IF EXISTS project_slack;
DROP TABLE IF EXISTS notification_settings;

COMMIT;
