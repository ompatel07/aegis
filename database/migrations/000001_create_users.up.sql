-- 000001_create_users.up.sql
-- Base extensions, shared helpers, and the users table.

BEGIN;

-- gen_random_uuid() is core in PG13+, but pgcrypto also provides crypt()/digest()
-- helpers we may use elsewhere. Safe to require.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- Case-insensitive text for emails so 'A@x.com' == 'a@x.com'.
CREATE EXTENSION IF NOT EXISTS citext;

-- Shared trigger function: keep updated_at fresh on every UPDATE.
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE users (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email         CITEXT      NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    name          VARCHAR(255) NOT NULL,
    role          VARCHAR(32)  NOT NULL DEFAULT 'user'
                               CHECK (role IN ('user', 'admin')),
    plan          VARCHAR(32)  NOT NULL DEFAULT 'free'
                               CHECK (plan IN ('free', 'pro', 'enterprise')),
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- UNIQUE on email already creates an index used for login lookups.
CREATE INDEX idx_users_created_at ON users (created_at DESC);

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMIT;
