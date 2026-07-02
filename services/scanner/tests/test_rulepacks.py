"""Tests for rule-pack versioning + custom-rule validation."""
from __future__ import annotations

import os

import pytest

from config import get_settings
from engines import semgrep_engine
from utils.sandbox import binary_available

settings = get_settings()


def test_rule_pack_version_is_deterministic_and_sensitive():
    v1 = semgrep_engine._rule_pack_version(["p/a", "p/b"], None)
    v2 = semgrep_engine._rule_pack_version(["p/b", "p/a"], None)  # order-independent
    assert v1 == v2
    assert v1.startswith("rp-")
    # A different config set or custom rules changes the version.
    assert semgrep_engine._rule_pack_version(["p/a"], None) != v1
    assert semgrep_engine._rule_pack_version(["p/a", "p/b"], ["rules: []"]) != v1


def test_write_project_rules_roundtrip(tmp_path):
    d = semgrep_engine._write_project_rules(["rules: [] # one", "rules: [] # two"])
    try:
        assert d and os.path.isdir(d)
        files = sorted(os.listdir(d))
        assert files == ["rule_0.yaml", "rule_1.yaml"]
    finally:
        import shutil

        if d:
            shutil.rmtree(d, ignore_errors=True)
    assert semgrep_engine._write_project_rules(None) is None


_GOOD_RULE = """\
rules:
  - id: no-hardcoded-token
    pattern: token = "..."
    message: Hard-coded token
    languages: [python]
    severity: WARNING
"""

_BAD_RULE = "rules:\n  - id: broken\n    message: missing pattern and languages\n"


@pytest.mark.skipif(
    not binary_available(settings.semgrep_bin),
    reason="semgrep not available (run via make smoke)",
)
def test_validate_endpoint_accepts_good_rejects_bad():
    from fastapi.testclient import TestClient

    from main import app

    client = TestClient(app)
    ok = client.post("/rules/validate", json={"rule_yaml": _GOOD_RULE}).json()
    assert ok["valid"] is True and ok["rule_count"] >= 1

    bad = client.post("/rules/validate", json={"rule_yaml": _BAD_RULE}).json()
    assert bad["valid"] is False and bad["error"]
