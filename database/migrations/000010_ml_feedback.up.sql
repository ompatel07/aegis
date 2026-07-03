-- 000010_ml_feedback.up.sql
-- Local learning: user feedback on findings + the metadata-only training set the
-- false-positive classifier learns from. NO SOURCE CODE is ever stored here.

BEGIN;

CREATE TABLE finding_feedback (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID        NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    user_id    UUID        NOT NULL REFERENCES users (id)    ON DELETE CASCADE,
    action     VARCHAR(16) NOT NULL
                           CHECK (action IN ('marked_fp', 'fixed', 'suppressed', 'ignored', 'confirmed')),
    reason     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_finding_feedback_created ON finding_feedback (created_at DESC);

-- ml_training_data: metadata-only features + the user's action as the label.
-- Materialized from finding_feedback + finding metadata (never the code itself).
CREATE TABLE ml_training_data (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    source               VARCHAR(16) NOT NULL DEFAULT 'feedback',  -- feedback | seed
    rule_id              VARCHAR(512),
    engine               VARCHAR(32),
    severity             VARCHAR(16),
    file_extension       VARCHAR(32),
    file_path_depth      INTEGER,
    project_language     VARCHAR(32),
    project_size_bucket  VARCHAR(16),
    lines_of_code        INTEGER,
    cwe                  VARCHAR(32),
    owasp_category       VARCHAR(128),
    is_in_test_file      BOOLEAN,
    is_in_generated_file BOOLEAN,
    is_direct_dependency BOOLEAN,
    label                VARCHAR(16) NOT NULL,   -- the user_action
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Inference output: the classifier's P(false positive) for each finding.
ALTER TABLE findings ADD COLUMN false_positive_probability REAL;

COMMIT;
