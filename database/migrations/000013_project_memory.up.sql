-- 000013_project_memory.up.sql
-- Per-project memory (Phase 2C TASK 4): baselines ("what's normal for this
-- codebase"), grandfathering (new vs existing findings), and team pattern
-- learning (per-project per-rule feedback priors). All metadata only.

BEGIN;

-- One baseline fingerprint per project: aggregate profile + bookkeeping.
CREATE TABLE project_baselines (
    project_id      UUID        PRIMARY KEY REFERENCES projects (id) ON DELETE CASCADE,
    baseline_json   JSONB       NOT NULL DEFAULT '{}'::jsonb,  -- complexity/dependency/overall profile
    scan_count      INTEGER     NOT NULL DEFAULT 0,
    first_scan_id   UUID,
    last_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-rule baseline: how often this rule fires for this project, and whether it
-- was present when the baseline was first established (grandfathered).
CREATE TABLE project_baseline_findings (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id          UUID        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    rule_id             VARCHAR(512) NOT NULL,
    engine              VARCHAR(32),
    avg_count_per_scan  NUMERIC(10,2) NOT NULL DEFAULT 0,
    typical_severity    VARCHAR(16),
    times_seen          INTEGER     NOT NULL DEFAULT 0,
    is_grandfathered    BOOLEAN     NOT NULL DEFAULT FALSE,
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, rule_id)
);
CREATE INDEX idx_baseline_findings_project ON project_baseline_findings (project_id);

-- Team pattern learning: per-project per-rule feedback stats feed a personalized
-- false-positive prior blended into each finding's score.
CREATE TABLE project_rule_stats (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    rule_id         VARCHAR(512) NOT NULL,
    engine          VARCHAR(32),
    total_feedback  INTEGER     NOT NULL DEFAULT 0,
    fp_count        INTEGER     NOT NULL DEFAULT 0,   -- marked_fp | ignored
    confirmed_count INTEGER     NOT NULL DEFAULT 0,   -- confirmed | fixed
    fp_rate         NUMERIC(4,3) NOT NULL DEFAULT 0,  -- fp_count / total_feedback
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, rule_id)
);
CREATE INDEX idx_project_rule_stats_project ON project_rule_stats (project_id);

-- Per-finding: does this finding deviate from the project baseline? (new vs
-- existing). "New" findings display first and can gate PRs (grandfathering).
ALTER TABLE findings ADD COLUMN is_new BOOLEAN NOT NULL DEFAULT FALSE;

-- Grandfathering mode: when on, only NEW findings (deviating from baseline) gate
-- PRs; pre-existing findings are informational.
ALTER TABLE projects ADD COLUMN grandfather_mode BOOLEAN NOT NULL DEFAULT TRUE;

COMMIT;
