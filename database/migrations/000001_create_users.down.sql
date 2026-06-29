-- 000001_create_users.down.sql

BEGIN;

DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
DROP TABLE IF EXISTS users;

-- set_updated_at() is shared; only drop it here because this is the base migration.
DROP FUNCTION IF EXISTS set_updated_at();

-- Leave pgcrypto/citext installed — other databases on the cluster may use them.

COMMIT;
