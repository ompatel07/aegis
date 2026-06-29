-- 000003_create_scans.up.sql
-- A scan is one run of the 3-pillar pipeline against a project.

BEGIN;

CREATE TABLE scans (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id   UUID        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    trigger      VARCHAR(32) NOT NULL
                             CHECK (trigger IN ('manual', 'webhook', 'scheduled')),
    status       VARCHAR(32) NOT NULL DEFAULT 'queued'
                             CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    branch       VARCHAR(255),
    commit_sha   VARCHAR(64),

    -- Pillar scores (0-100). NULL until the scan completes.
    quality_score    INTEGER CHECK (quality_score    BETWEEN 0 AND 100),
    security_score   INTEGER CHECK (security_score   BETWEEN 0 AND 100),
    deployment_score INTEGER CHECK (deployment_score BETWEEN 0 AND 100),
    overall_score    INTEGER CHECK (overall_score    BETWEEN 0 AND 100),
    overall_grade    VARCHAR(1) CHECK (overall_grade IN ('A', 'B', 'C', 'D', 'F')),

    -- Pillar summary counts.
    quality_issues_total  INTEGER NOT NULL DEFAULT 0,
    security_issues_total INTEGER NOT NULL DEFAULT 0,
    secrets_found         INTEGER NOT NULL DEFAULT 0,
    vulnerabilities_found INTEGER NOT NULL DEFAULT 0,

    -- Timing.
    queued_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at       TIMESTAMPTZ,
    completed_at     TIMESTAMPTZ,
    duration_seconds INTEGER,

    -- Raw engine output retained as JSONB for drill-down / reprocessing.
    raw_semgrep_output  JSONB,
    raw_trivy_output    JSONB,
    raw_gitleaks_output JSONB,
    raw_quality_output  JSONB,

    error_message TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- List scans for a project (history view), newest first.
CREATE INDEX idx_scans_project_id ON scans (project_id);
CREATE INDEX idx_scans_status     ON scans (status);
CREATE INDEX idx_scans_created_at ON scans (created_at DESC);
-- Composite for the common "latest scans for a project" query.
CREATE INDEX idx_scans_project_created ON scans (project_id, created_at DESC);

COMMIT;
