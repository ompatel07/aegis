-- 000005_create_github_integrations.up.sql
-- GitHub App / webhook integration per project. Tokens stored encrypted.

BEGIN;

CREATE TABLE github_integrations (
    id                     UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                UUID         NOT NULL REFERENCES users (id)    ON DELETE CASCADE,
    project_id             UUID         NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    installation_id        VARCHAR(64),
    -- HMAC secret used to verify X-Hub-Signature-256 on incoming webhooks.
    webhook_secret         VARCHAR(255) NOT NULL,
    -- AES-256 encrypted access token (never stored in plaintext).
    access_token_encrypted VARCHAR(1024),
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),

    -- One integration per project.
    CONSTRAINT uq_github_integrations_project UNIQUE (project_id)
);

CREATE INDEX idx_github_integrations_user_id         ON github_integrations (user_id);
CREATE INDEX idx_github_integrations_installation_id ON github_integrations (installation_id);

COMMIT;
