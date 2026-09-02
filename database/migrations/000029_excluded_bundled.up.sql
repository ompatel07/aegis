-- Scan-level summary of bundled/minified third-party JS/TS files EXCLUDED from SAST
-- (T2): {"files": n, "bytes": n, "reasons": {...}, "sample": [...]}. Surfaced in the
-- UI as "N bundled files excluded from SAST (M MB)" so the exclusion is auditable,
-- never silent. NULL when nothing was excluded (distinct from an empty exclusion).
ALTER TABLE scans ADD COLUMN excluded_bundled JSONB;
