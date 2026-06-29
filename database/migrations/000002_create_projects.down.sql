-- 000002_create_projects.down.sql

BEGIN;

DROP TRIGGER IF EXISTS trg_projects_updated_at ON projects;
DROP TABLE IF EXISTS projects;

COMMIT;
