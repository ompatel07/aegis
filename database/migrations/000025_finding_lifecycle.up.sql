-- 000025_finding_lifecycle.up.sql
-- Instance-level finding lifecycle (P1a): track New / Existing / Resolved /
-- Reopened per finding across a project's scan history, keyed by a stable,
-- line-shift-resilient fingerprint (scanner utils/snippet.py). This replaces the
-- old rule-level "is_new" (a new instance of an already-seen rule now correctly
-- reads as new) and lets the PR gate block genuinely new findings.

BEGIN;

-- Per-finding identity + lifecycle status, carried on each scan's findings.
ALTER TABLE findings ADD COLUMN fingerprint      VARCHAR(64);
ALTER TABLE findings ADD COLUMN lifecycle_status VARCHAR(16)   -- new | existing | reopened
    CHECK (lifecycle_status IN ('new', 'existing', 'reopened'));
CREATE INDEX idx_findings_fingerprint ON findings (fingerprint);

-- One row per distinct finding (fingerprint) ever seen in a project: its current
-- lifecycle status and the scans that bound its life. Resolved findings live only
-- here (they are absent from the current scan's findings), so "what did this scan
-- fix?" is answerable.
CREATE TABLE project_finding_states (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id         UUID        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    fingerprint        VARCHAR(64) NOT NULL,
    rule_id            VARCHAR(512),
    engine             VARCHAR(32),
    severity           VARCHAR(16),
    file_path          VARCHAR(2048),
    title              VARCHAR(1024),
    status             VARCHAR(16) NOT NULL          -- new | existing | resolved | reopened
                       CHECK (status IN ('new', 'existing', 'resolved', 'reopened')),
    first_seen_scan_id UUID,
    last_seen_scan_id  UUID,
    resolved_scan_id   UUID,                         -- the scan that first found it gone
    times_seen         INTEGER     NOT NULL DEFAULT 1,
    first_seen_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, fingerprint)
);
CREATE INDEX idx_finding_states_project ON project_finding_states (project_id);
CREATE INDEX idx_finding_states_status  ON project_finding_states (project_id, status);

COMMIT;
