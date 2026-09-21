-- 000031_finding_state_retired.down.sql
-- Rolling back cannot keep 'retired' rows. They return to 'existing' -- open, which
-- is the honest pre-N1 reading of a finding nobody has shown to be fixed. They must
-- NOT become 'resolved': that would manufacture the remediation evidence 000031
-- exists to prevent.

BEGIN;

UPDATE project_finding_states SET status = 'existing', updated_at = now() WHERE status = 'retired';

ALTER TABLE project_finding_states DROP CONSTRAINT IF EXISTS project_finding_states_status_check;
ALTER TABLE project_finding_states ADD CONSTRAINT project_finding_states_status_check
    CHECK (status IN ('new', 'existing', 'resolved', 'reopened'));

COMMIT;
