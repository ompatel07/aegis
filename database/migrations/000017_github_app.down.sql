-- 000017_github_app.down.sql

BEGIN;

DROP TABLE IF EXISTS pr_check_runs;
DROP TABLE IF EXISTS github_repositories;
DROP TABLE IF EXISTS github_app_installations;

COMMIT;
