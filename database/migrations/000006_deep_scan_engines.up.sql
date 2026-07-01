-- 000006_deep_scan_engines.up.sql
-- Allow deep-scan engines (Joern, CodeQL) as sources of findings.

BEGIN;

ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_engine_check;
ALTER TABLE findings ADD CONSTRAINT findings_engine_check
    CHECK (engine IN ('semgrep', 'trivy', 'gitleaks', 'quality', 'deployment', 'codeql', 'joern'));

COMMIT;
