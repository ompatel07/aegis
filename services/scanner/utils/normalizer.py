"""Cross-engine normalization helpers.

Each tool expresses severity differently. These helpers map every dialect onto
the single `Severity` enum so findings are directly comparable and scoreable.
"""
from __future__ import annotations

import os

from models.scan_result import Severity

# Semgrep emits ERROR / WARNING / INFO. Its metadata may carry a finer
# "impact"/"confidence". We map conservatively, then upgrade ERROR findings
# tagged as high-impact to critical.
_SEMGREP_BASE = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def normalize_semgrep_severity(raw_severity: str, metadata: dict | None) -> Severity:
    """Map a Semgrep result to our severity scale.

    ERROR → high, escalated to critical when metadata marks impact=HIGH and the
    rule is security-relevant. WARNING → medium, INFO → low.
    """
    base = _SEMGREP_BASE.get((raw_severity or "").upper(), Severity.LOW)
    metadata = metadata or {}

    if base is Severity.HIGH:
        impact = str(metadata.get("impact", "")).upper()
        likelihood = str(metadata.get("likelihood", "")).upper()
        if impact == "HIGH" and likelihood in ("HIGH", "MEDIUM"):
            return Severity.CRITICAL
    return base


def cvss_to_severity(score: float | None, fallback_label: str | None = None) -> Severity:
    """Map a CVSS base score to our scale (Trivy convention).

    >= 9.0 critical, >= 7.0 high, >= 4.0 medium, else low. When no numeric score
    is present, fall back to the textual severity label the tool provided.
    """
    if score is not None:
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW
    return label_to_severity(fallback_label)


def label_to_severity(label: str | None) -> Severity:
    """Map a free-text severity label (CRITICAL/HIGH/...) onto our scale."""
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "MODERATE": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "UNKNOWN": Severity.LOW,
        "INFO": Severity.INFO,
        "INFORMATIONAL": Severity.INFO,
    }
    return mapping.get((label or "").upper(), Severity.LOW)


def extract_owasp(metadata: dict | None) -> str | None:
    """Pull a single OWASP category string out of Semgrep-style metadata."""
    if not metadata:
        return None
    owasp = metadata.get("owasp")
    if isinstance(owasp, list) and owasp:
        return str(owasp[0])
    if isinstance(owasp, str):
        return owasp
    return None


def extract_cwe(metadata: dict | None) -> str | None:
    """Pull a single CWE id out of Semgrep-style metadata."""
    if not metadata:
        return None
    cwe = metadata.get("cwe")
    if isinstance(cwe, list) and cwe:
        return _first_cwe_id(str(cwe[0]))
    if isinstance(cwe, str):
        return _first_cwe_id(cwe)
    return None


def _first_cwe_id(value: str) -> str:
    """'CWE-89: SQL Injection' → 'CWE-89'."""
    token = value.strip().split(":", 1)[0].strip()
    return token or value


def relative_path(absolute: str, root: str) -> str:
    """Return a clean repo-relative path, falling back to the original."""
    try:
        rel = os.path.relpath(absolute, root)
        return rel.replace(os.sep, "/")
    except ValueError:
        return absolute


def truncate(text: str | None, limit: int) -> str | None:
    """Truncate overly long strings so they fit DB columns / stay readable."""
    if text is None:
        return None
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"
