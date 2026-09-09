DROP INDEX IF EXISTS idx_finding_states_code_key;
ALTER TABLE project_finding_states DROP COLUMN IF EXISTS code_key;
ALTER TABLE findings               DROP COLUMN IF EXISTS code_key;
