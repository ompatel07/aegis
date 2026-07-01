"""Tests for the deep-scan engines (Joern + CodeQL slot).

The heavy tools (CodeQL CLI, Joern) are not present in the test image, so we
unit-test the parsers against canned tool output and assert the graceful
"unavailable -> skipped" behaviour of the live run().
"""
from __future__ import annotations

from config import get_settings
from engines import codeql_engine, joern_engine
from models.scan_request import DeepScanRequest
from models.scan_result import EngineStatus, Severity

settings = get_settings()

# ── CodeQL SARIF parsing ──────────────────────────────────────────────────────
_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "CodeQL", "rules": [
                {
                    "id": "js/sql-injection",
                    "name": "Database query built from user-controlled sources",
                    "properties": {
                        "tags": ["security", "external/cwe/cwe-089"],
                        "security-severity": "8.8",
                    },
                    "shortDescription": {"text": "SQL injection"},
                }
            ]}},
            "results": [
                {
                    "ruleId": "js/sql-injection",
                    "level": "error",
                    "message": {"text": "This query depends on a user-provided value."},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "app/routes/x.js"},
                        "region": {"startLine": 42, "startColumn": 5, "endLine": 42, "endColumn": 40},
                    }}],
                    "codeFlows": [{"threadFlows": [{"locations": [
                        {"location": {
                            "physicalLocation": {"artifactLocation": {"uri": "app/routes/x.js"},
                                                 "region": {"startLine": 10}},
                            "message": {"text": "req.query.id"}}},
                        {"location": {
                            "physicalLocation": {"artifactLocation": {"uri": "app/data/dao.js"},
                                                 "region": {"startLine": 30}},
                            "message": {"text": "db.query(sql)"}}},
                    ]}]}],
                }
            ],
        }
    ],
}


def test_codeql_sarif_parsing():
    findings = codeql_engine._parse_sarif(_SARIF, "/scan")
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "js/sql-injection"
    assert f.severity == Severity.HIGH  # security-severity 8.8 -> high
    assert f.cwe_id == "CWE-89"
    assert f.file_path == "app/routes/x.js"
    assert f.line_start == 42
    assert f.metadata["deep_scan"] is True
    assert f.metadata["dataflow_steps"] == 2
    assert f.metadata["dataflow"][0]["file"] == "app/routes/x.js"
    assert f.metadata["dataflow"][-1]["file"] == "app/data/dao.js"


async def test_codeql_unavailable_is_skipped_not_failed():
    req = DeepScanRequest(path="/tmp", scan_id="s", engine="codeql", languages=["javascript"])
    result = await codeql_engine.run(req, settings)
    assert result.status == EngineStatus.SKIPPED
    assert "license" in (result.error or "").lower()
    assert result.findings == []


# ── Joern output parsing ──────────────────────────────────────────────────────
_JOERN = {
    "findings": [
        {
            "vulnClass": "sql-injection",
            "cwe": "CWE-89",
            "severity": "critical",
            "file": "/scan/app/routes/x.js",
            "lineStart": 42,
            "lineEnd": 42,
            "method": "handler",
            "message": "Untrusted request data reaches a sql-injection sink",
            "flow": [
                {"file": "/scan/app/routes/x.js", "line": 10, "code": "req.query.id"},
                {"file": "/scan/app/data/dao.js", "line": 30, "code": "db.query(sql)"},
            ],
        }
    ]
}


def test_joern_output_parsing():
    findings = joern_engine._parse_output(_JOERN, "/scan")
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "joern/sql-injection"
    assert f.severity == Severity.CRITICAL
    assert f.cwe_id == "CWE-89"
    assert f.owasp_category == "A03:2021 - Injection"
    assert f.file_path == "app/routes/x.js"  # absolute path relativized against root
    assert f.line_start == 42
    assert f.metadata["deep_scan"] is True
    assert f.metadata["vuln_class"] == "sql-injection"
    assert f.metadata["dataflow_steps"] == 2
    assert f.metadata["dataflow"][0]["file"] == "app/routes/x.js"


def test_joern_backfills_owasp_and_severity_from_vuln_class():
    data = {"findings": [{"vulnClass": "ssrf", "file": "/scan/a.py", "lineStart": 1, "flow": []}]}
    f = joern_engine._parse_output(data, "/scan")[0]
    assert f.cwe_id == "CWE-918"
    assert f.owasp_category.startswith("A10")
    assert f.severity == Severity.HIGH


async def test_joern_unavailable_is_skipped_not_failed():
    req = DeepScanRequest(path="/tmp", scan_id="s", engine="joern")
    result = await joern_engine.run(req, settings)
    assert result.status == EngineStatus.SKIPPED
    assert result.findings == []


def test_exceeds_size_guard(tmp_path):
    (tmp_path / "small.txt").write_text("hello", encoding="utf-8")
    assert joern_engine._exceeds_size(str(tmp_path), limit_mb=100) is False
    assert joern_engine._exceeds_size(str(tmp_path), limit_mb=0) is True  # any content exceeds 0MB
