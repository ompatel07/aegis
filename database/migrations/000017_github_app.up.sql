-- 000017_github_app.up.sql
-- Full GitHub App (Phase 2C TASK 1): installations, per-repo enablement, and PR
-- check-run/comment tracking (for single-updateable comments + check statuses).

BEGIN;

CREATE TABLE github_app_installations (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    installation_id  BIGINT      NOT NULL UNIQUE,          -- GitHub's installation id
    account_login    VARCHAR(255) NOT NULL,                -- org/user the app is installed on
    account_type     VARCHAR(32),                          -- Organization | User
    organization_id  UUID        REFERENCES organizations (id) ON DELETE SET NULL,
    permissions_json JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at       TIMESTAMPTZ
);
CREATE INDEX idx_gh_installations_org ON github_app_installations (organization_id);

CREATE TABLE github_repositories (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    installation_id BIGINT      NOT NULL REFERENCES github_app_installations (installation_id) ON DELETE CASCADE,
    repo_id         BIGINT      NOT NULL,                  -- GitHub repo id
    name            VARCHAR(255) NOT NULL,
    full_name       VARCHAR(512) NOT NULL,
    default_branch  VARCHAR(255),
    project_id      UUID        REFERENCES projects (id) ON DELETE SET NULL,
    enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (installation_id, repo_id)
);
CREATE INDEX idx_gh_repos_installation ON github_repositories (installation_id);

CREATE TABLE pr_check_runs (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id       UUID        NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    installation_id BIGINT    NOT NULL,
    repo_full_name VARCHAR(512) NOT NULL,
    pr_number     INTEGER     NOT NULL,
    head_sha      VARCHAR(64) NOT NULL,
    check_run_id  BIGINT,                                  -- GitHub check-run id (nullable until created)
    comment_id    BIGINT,                                  -- the single updateable PR comment id
    finalized     BOOLEAN     NOT NULL DEFAULT FALSE,      -- check/comment updated after scan completion
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scan_id)
);
CREATE INDEX idx_pr_check_runs_finalized ON pr_check_runs (finalized) WHERE NOT finalized;

COMMIT;
