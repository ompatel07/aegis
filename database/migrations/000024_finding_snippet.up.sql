-- 000024_finding_snippet.up.sql
-- Inline code snippet on EVERY finding (P1c): the flagged line(s) plus a little
-- surrounding context, so SCA / secrets / quality / IaC findings show the
-- offending code inline, not just a file:line reference (matching Snyk / SonarQube
-- / Checkmarx). Populated by the scanner's snippet pass (utils/snippet.py).

BEGIN;

ALTER TABLE findings ADD COLUMN code_snippet       TEXT;
ALTER TABLE findings ADD COLUMN snippet_start_line INTEGER;  -- 1-based first line of the snippet

COMMIT;
