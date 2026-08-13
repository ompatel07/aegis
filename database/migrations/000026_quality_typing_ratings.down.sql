-- 000026_quality_typing_ratings.down.sql
BEGIN;

ALTER TABLE findings DROP COLUMN IF EXISTS issue_type;
ALTER TABLE scans DROP COLUMN IF EXISTS reliability_rating;
ALTER TABLE scans DROP COLUMN IF EXISTS security_rating;
ALTER TABLE scans DROP COLUMN IF EXISTS maintainability_rating;

COMMIT;
