-- 000008_intelligence.up.sql
-- Live vulnerability intelligence: a local CVE mirror, a rule registry, sync
-- audit log, retroactive re-evaluation flags, and in-app notifications.

BEGIN;

CREATE TABLE cve_database (
    cve_id            VARCHAR(64)  PRIMARY KEY,
    description       TEXT,
    cvss_v3_score     NUMERIC(3, 1),
    cvss_v3_vector    VARCHAR(128),
    affected_packages JSONB,        -- [{ecosystem, name, introduced, fixed}]
    published_date    TIMESTAMPTZ,
    modified_date     TIMESTAMPTZ,
    references_json   JSONB,
    source            VARCHAR(16) NOT NULL,   -- nvd | osv | ghsa
    severity          VARCHAR(16),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_cve_modified  ON cve_database (modified_date DESC);
CREATE INDEX idx_cve_source    ON cve_database (source);
CREATE INDEX idx_cve_affected  ON cve_database USING GIN (affected_packages);

CREATE TABLE rule_registry (
    engine               VARCHAR(32)  NOT NULL,
    rule_id              VARCHAR(512) NOT NULL,
    rule_definition_yaml TEXT,
    source_registry      VARCHAR(64),
    category             VARCHAR(64),
    severity             VARCHAR(16),
    added_date           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_date         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (engine, rule_id)
);

CREATE TABLE intelligence_sync_log (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    source            VARCHAR(32) NOT NULL,
    sync_started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    sync_completed_at TIMESTAMPTZ,
    records_added     INTEGER     NOT NULL DEFAULT 0,
    records_updated   INTEGER     NOT NULL DEFAULT 0,
    status            VARCHAR(16) NOT NULL,   -- running | success | failed
    error_message     TEXT
);
CREATE INDEX idx_sync_log_source_started ON intelligence_sync_log (source, sync_started_at DESC);

-- Retroactive re-evaluation: a newly-published CVE can invalidate an old scan.
ALTER TABLE scans
    ADD COLUMN needs_reeval  BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN reeval_reason TEXT;

CREATE TABLE notifications (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users (id)    ON DELETE CASCADE,
    project_id UUID        REFERENCES projects (id)          ON DELETE CASCADE,
    kind       VARCHAR(32) NOT NULL,   -- new_cve | rescan_recommended
    title      VARCHAR(255) NOT NULL,
    body       TEXT,
    metadata   JSONB,
    is_read    BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_notifications_user ON notifications (user_id, is_read, created_at DESC);

COMMIT;
