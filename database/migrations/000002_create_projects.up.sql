-- 000002_create_projects.up.sql
-- Projects belong to a user and describe a codebase to analyze.

BEGIN;

CREATE TABLE projects (
    id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name           VARCHAR(255) NOT NULL,
    slug           VARCHAR(255) NOT NULL UNIQUE,
    description    TEXT,
    repo_url       VARCHAR(1024),
    repo_type      VARCHAR(32)
                                CHECK (repo_type IN ('github', 'gitlab', 'bitbucket', 'upload')),
    default_branch VARCHAR(255) NOT NULL DEFAULT 'main',
    language       VARCHAR(64),
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Primary access pattern: list a user's projects, newest first.
CREATE INDEX idx_projects_user_id    ON projects (user_id);
CREATE INDEX idx_projects_created_at ON projects (created_at DESC);

CREATE TRIGGER trg_projects_updated_at
    BEFORE UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMIT;
