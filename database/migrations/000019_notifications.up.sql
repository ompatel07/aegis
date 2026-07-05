-- 000019_notifications.up.sql
-- Email + Slack notifications (Phase 2C TASK 7): per-user email preferences,
-- per-project Slack routing, and a per-scan dispatch marker.

BEGIN;

CREATE TABLE notification_settings (
    user_id            UUID        PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    email_enabled      BOOLEAN     NOT NULL DEFAULT TRUE,
    email_scan_complete BOOLEAN    NOT NULL DEFAULT FALSE,  -- every scan is noisy → opt-in
    email_new_critical BOOLEAN     NOT NULL DEFAULT TRUE,   -- new criticals are worth an email
    digest_frequency   VARCHAR(16) NOT NULL DEFAULT 'weekly' CHECK (digest_frequency IN ('daily','weekly','never')),
    severity_threshold VARCHAR(16) NOT NULL DEFAULT 'high'  CHECK (severity_threshold IN ('critical','high','medium','all')),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE project_slack (
    project_id  UUID        PRIMARY KEY REFERENCES projects (id) ON DELETE CASCADE,
    webhook_url TEXT        NOT NULL,                         -- Slack incoming webhook
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    min_severity VARCHAR(16) NOT NULL DEFAULT 'high' CHECK (min_severity IN ('critical','high','medium','all')),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-scan dispatch marker so the notifier sends each scan's alerts exactly once.
ALTER TABLE scans ADD COLUMN notified_at TIMESTAMPTZ;

COMMIT;
