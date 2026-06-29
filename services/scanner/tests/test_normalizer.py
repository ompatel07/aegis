"""Unit tests for severity normalization — the shared scoring foundation."""
from __future__ import annotations

from models.scan_result import Severity
from utils import normalizer


def test_cvss_to_severity_thresholds():
    assert normalizer.cvss_to_severity(9.8) is Severity.CRITICAL
    assert normalizer.cvss_to_severity(7.5) is Severity.HIGH
    assert normalizer.cvss_to_severity(5.0) is Severity.MEDIUM
    assert normalizer.cvss_to_severity(2.1) is Severity.LOW


def test_cvss_falls_back_to_label():
    assert normalizer.cvss_to_severity(None, "CRITICAL") is Severity.CRITICAL
    assert normalizer.cvss_to_severity(None, "moderate") is Severity.MEDIUM
    assert normalizer.cvss_to_severity(None, None) is Severity.LOW


def test_semgrep_severity_escalation():
    # ERROR + high impact/likelihood escalates to critical.
    sev = normalizer.normalize_semgrep_severity(
        "ERROR", {"impact": "HIGH", "likelihood": "HIGH"}
    )
    assert sev is Severity.CRITICAL
    # Plain ERROR stays high.
    assert normalizer.normalize_semgrep_severity("ERROR", {}) is Severity.HIGH
    assert normalizer.normalize_semgrep_severity("WARNING", {}) is Severity.MEDIUM
    assert normalizer.normalize_semgrep_severity("INFO", {}) is Severity.LOW


def test_extract_cwe_first_id():
    assert normalizer.extract_cwe({"cwe": ["CWE-89: SQL Injection"]}) == "CWE-89"
    assert normalizer.extract_cwe({"cwe": "CWE-79"}) == "CWE-79"
    assert normalizer.extract_cwe({}) is None


def test_truncate():
    assert normalizer.truncate("hello", 10) == "hello"
    assert normalizer.truncate("x" * 20, 10).endswith("…")
    assert normalizer.truncate(None, 10) is None
