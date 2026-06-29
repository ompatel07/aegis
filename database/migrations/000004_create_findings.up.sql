-- 000004_create_findings.up.sql
-- Normalized findings produced by every engine, across all three pillars.

BEGIN;

CREATE TABLE findings (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id     UUID         NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    pillar      VARCHAR(32)  NOT NULL
                             CHECK (pillar IN ('quality', 'security', 'deployment')),
    engine      VARCHAR(32)  NOT NULL
                             CHECK (engine IN ('semgrep', 'trivy', 'gitleaks', 'quality', 'deployment')),
    rule_id     VARCHAR(512) NOT NULL,
    rule_name   VARCHAR(512) NOT NULL,
    severity    VARCHAR(16)  NOT NULL
                             CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    title       VARCHAR(1024) NOT NULL,
    description TEXT,

    -- Location within the codebase.
    file_path    VARCHAR(2048) NOT NULL,
    line_start   INTEGER,
    line_end     INTEGER,
    column_start INTEGER,
    column_end   INTEGER,

    -- Classification references.
    cwe_id         VARCHAR(32),
    cve_id         VARCHAR(64),
    owasp_category VARCHAR(128),

    -- Triage state.
    is_false_positive BOOLEAN NOT NULL DEFAULT FALSE,
    is_suppressed     BOOLEAN NOT NULL DEFAULT FALSE,
    fix_suggestion    TEXT,
    metadata          JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Findings are always queried within a scan, often filtered by pillar/severity.
CREATE INDEX idx_findings_scan_id  ON findings (scan_id);
CREATE INDEX idx_findings_severity ON findings (severity);
CREATE INDEX idx_findings_pillar   ON findings (pillar);
-- Composite to back the default findings list: a scan's active findings by pillar.
CREATE INDEX idx_findings_scan_pillar_severity
    ON findings (scan_id, pillar, severity)
    WHERE is_suppressed = FALSE;

COMMIT;
