-- 000010_ml_feedback.down.sql

BEGIN;

ALTER TABLE findings DROP COLUMN IF EXISTS false_positive_probability;
DROP TABLE IF EXISTS ml_training_data;
DROP TABLE IF EXISTS finding_feedback;

COMMIT;
