-- 000007_context_rich_findings.up.sql
-- Context-rich finding fields: human-readable title, concrete impact, business
-- risk level, actionable remediation, effort estimate, and engine-specific
-- enrichment (CVSS breakdown, image size, complexity numbers, ...).

BEGIN;

ALTER TABLE findings
    ADD COLUMN title_human         VARCHAR(512),
    ADD COLUMN impact              VARCHAR(1024),
    ADD COLUMN risk_level          VARCHAR(16)
        CHECK (risk_level IN ('informational', 'low', 'medium', 'high', 'critical')),
    ADD COLUMN remediation_action  VARCHAR(1024),
    ADD COLUMN remediation_details TEXT,
    ADD COLUMN estimated_effort    VARCHAR(16)
        CHECK (estimated_effort IN ('trivial', 'quick', 'moderate', 'significant')),
    ADD COLUMN context_metadata    JSONB;

COMMIT;
