-- 000032_security_coverage.up.sql
-- N2: per-language SAST coverage, recorded per scan.
--
-- After N1 removed the Semgrep-licensed packs, a repository written in a language we
-- barely cover produces few findings -- and few findings read as "clean". A Java-only
-- repository could score Security 100 / grade A on seven Java rules. This column
-- carries what our shipped rules can actually see (fractions of the repo's LOC by
-- coverage tier, and whether the security score may be presented as confident), so
-- the gap is shown on every report instead of being invisible.
--
-- NULL means not measured: a scan from before N2, or one where SAST never ran.
--
-- `scans` is read with an explicit column list (repository/scan.go), so this column
-- is invisible to a binary that does not know it -- additive in both directions, no
-- three-step release needed (docs/DEPLOY_ORDERING.md).

BEGIN;

ALTER TABLE scans ADD COLUMN security_coverage JSONB;

COMMIT;
