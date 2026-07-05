-- 000018_vcs_tracking.up.sql
-- Generic PR/MR tracking for GitLab & Bitbucket (Phase 2C TASK 2), enabling the
-- single-updateable comment + status update once a scan completes. GitHub keeps
-- its richer pr_check_runs table (check-run ids etc.).

BEGIN;

CREATE TABLE vcs_pr_tracking (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    provider    VARCHAR(16) NOT NULL,                 -- gitlab | bitbucket
    scan_id     UUID        NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    project_ref VARCHAR(255) NOT NULL,                -- provider project id/slug
    repo_full_name VARCHAR(512) NOT NULL,
    pr_number   INTEGER     NOT NULL,
    head_sha    VARCHAR(64) NOT NULL,
    comment_id  BIGINT,                               -- the single updateable comment/note
    finalized   BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scan_id)
);
CREATE INDEX idx_vcs_pr_tracking_finalized ON vcs_pr_tracking (finalized) WHERE NOT finalized;

COMMIT;
