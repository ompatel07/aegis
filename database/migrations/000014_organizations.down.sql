-- 000014_organizations.down.sql

BEGIN;

DROP INDEX IF EXISTS idx_projects_org;
ALTER TABLE projects DROP COLUMN IF EXISTS organization_id;
DROP TABLE IF EXISTS organization_invitations;
DROP TABLE IF EXISTS organization_members;
DROP TABLE IF EXISTS organizations;

COMMIT;
