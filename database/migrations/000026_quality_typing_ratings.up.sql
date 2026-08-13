-- 000026_quality_typing_ratings.up.sql
-- SonarQube-style quality classification (P2c):
--   * per-finding issue_type: bug | vulnerability | code_smell
--   * per-scan A-E ratings: reliability, security, maintainability
-- Both derived from data Aegis already computes (finding pillar/severity + the
-- pillar sub-scores). Ratings map A (best) .. E (worst).

BEGIN;

ALTER TABLE findings ADD COLUMN issue_type VARCHAR(16)
    CHECK (issue_type IN ('bug', 'vulnerability', 'code_smell'));

ALTER TABLE scans ADD COLUMN reliability_rating    CHAR(1) CHECK (reliability_rating    IN ('A','B','C','D','E'));
ALTER TABLE scans ADD COLUMN security_rating       CHAR(1) CHECK (security_rating       IN ('A','B','C','D','E'));
ALTER TABLE scans ADD COLUMN maintainability_rating CHAR(1) CHECK (maintainability_rating IN ('A','B','C','D','E'));

COMMIT;
