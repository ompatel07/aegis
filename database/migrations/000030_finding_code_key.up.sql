-- J4: path-independent finding identity, so a moved file does not read as a wave
-- of fake regressions and fake fixes.
--
-- The fingerprint is sha256(rule + file_path + normalized code + ordinal).
-- file_path has to stay in it -- identical code in two files is two findings --
-- but that means renaming or moving a file resolves every finding in it and
-- opens an identical set as new. In a compliance artifact whose whole value is
-- open-vs-closed, that is the worst possible false story.
--
-- code_key is the same identity with file_path omitted. The lifecycle uses it
-- ONLY as a fallback, and only for a strictly 1:1 pairing between a finding that
-- disappeared and one that appeared, so two copies of identical code can never
-- be matched to each other by guess.
--
-- Existing rows are left NULL on purpose: the key cannot be recomputed without
-- the source line the finding was on, and that is not stored. Findings first
-- seen before this migration therefore keep today's behaviour across a rename
-- until their next scan re-establishes them. Stated rather than backfilled with
-- a guess.
ALTER TABLE findings              ADD COLUMN IF NOT EXISTS code_key varchar(64);
ALTER TABLE project_finding_states ADD COLUMN IF NOT EXISTS code_key varchar(64);

-- Supports the fallback lookup: unmatched prior rows for a project, by content.
CREATE INDEX IF NOT EXISTS idx_finding_states_code_key
    ON project_finding_states (project_id, code_key)
    WHERE code_key IS NOT NULL;
