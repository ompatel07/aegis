-- 000020_admin.down.sql

BEGIN;

DROP TABLE IF EXISTS scan_ratings;
DROP TABLE IF EXISTS support_tickets;
DROP TABLE IF EXISTS beta_invitations;
DROP TABLE IF EXISTS feature_flags;
DROP TABLE IF EXISTS admin_audit_log;
ALTER TABLE organizations DROP COLUMN IF EXISTS suspended_at;
ALTER TABLE users DROP COLUMN IF EXISTS suspended_at;
ALTER TABLE users DROP COLUMN IF EXISTS is_super_admin;

COMMIT;
