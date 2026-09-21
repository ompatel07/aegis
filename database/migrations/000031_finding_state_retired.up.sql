-- 000031_finding_state_retired.up.sql
-- N1: a finding whose rule no longer ships is RETIRED, not RESOLVED.
--
-- Before this, lifecycle marked every finding absent from a scan as resolved. When
-- N1 removed the Semgrep-registry rules, each existing project's next scan would
-- have "resolved" every finding those rules raised -- and the compliance report
-- lists resolved findings as remediation evidence ("vulnerabilities proven
-- closed"). Retired is neither open nor fixed: excluded from both sides.
--
-- Additive to the CHECK only; no column changes, so no SELECT * exposure
-- (docs/DEPLOY_ORDERING.md). Old binaries never write 'retired'.

BEGIN;

ALTER TABLE project_finding_states DROP CONSTRAINT IF EXISTS project_finding_states_status_check;
ALTER TABLE project_finding_states ADD CONSTRAINT project_finding_states_status_check
    CHECK (status IN ('new', 'existing', 'resolved', 'reopened', 'retired'));

COMMIT;
