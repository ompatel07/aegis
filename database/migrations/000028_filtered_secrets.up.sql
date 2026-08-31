-- Scan-level count of secret matches SUPPRESSED as definitively-not-a-secret (P1):
-- {"placeholder": n, "expired_jwt": n}. Surfaced in the UI as "N filtered" so the
-- filtering is auditable, never silent.
ALTER TABLE scans ADD COLUMN filtered_secrets JSONB NOT NULL DEFAULT '{}'::jsonb;
