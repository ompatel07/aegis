-- 000024_finding_snippet.down.sql
BEGIN;

ALTER TABLE findings DROP COLUMN IF EXISTS code_snippet;
ALTER TABLE findings DROP COLUMN IF EXISTS snippet_start_line;

COMMIT;
