-- 000015_policies.down.sql

BEGIN;

DROP TABLE IF EXISTS policy_evaluations;
DROP TABLE IF EXISTS project_policies;

COMMIT;
