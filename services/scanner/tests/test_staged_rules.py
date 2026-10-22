"""N3: staged rules stay correct, and stay out of scans and coverage.

rules_staging/ holds Aegis-authored rules that pass their fixtures but have not been
proven on real code at 0 false positives (benchmark-only, or never fired). They must
not run in a customer scan and must not be counted as coverage -- otherwise the
"real-code-gated" promise of N3 is just a directory name. See rules_staging/README.md.
"""
from __future__ import annotations

import os
import subprocess

import pytest
import yaml

from config import get_settings
from engines import semgrep_engine
from utils import rule_coverage
from utils.sandbox import binary_available

settings = get_settings()
SCANNER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STAGING = os.path.join(SCANNER, "rules_staging")


def _staged_ids() -> set[str]:
    ids: set[str] = set()
    for name in os.listdir(STAGING):
        if name.endswith(".yaml"):
            with open(os.path.join(STAGING, name), encoding="utf-8") as fh:
                ids |= {r["id"] for r in (yaml.safe_load(fh) or {}).get("rules") or []}
    return ids


def test_staging_holds_rules():
    assert len(_staged_ids()) >= 1


@pytest.mark.skipif(not binary_available(settings.semgrep_bin),
                    reason="semgrep binary not available (run via `make smoke`)")
def test_staged_rules_pass_their_fixtures():
    proc = subprocess.run([settings.semgrep_bin, "--test", "--config", STAGING, STAGING],
                          capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0 and "All tests passed" in proc.stdout, proc.stdout[-3000:]


def test_engine_never_loads_staging():
    """The bundled config dirs the engine passes to semgrep do not include staging."""
    dirs = [semgrep_engine._custom_rules_dir(),
            semgrep_engine._bundled_rules_dir(semgrep_engine._IAC_RULES_DIR),
            semgrep_engine._bundled_rules_dir(semgrep_engine._CICD_RULES_DIR),
            semgrep_engine._bundled_rules_dir(semgrep_engine._QUALITY_RULES_DIR)]
    for d in dirs:
        assert d is None or "rules_staging" not in os.path.abspath(d), d
    shipped = set().union(*(semgrep_engine._rule_ids_in(d) for d in dirs if d))
    leaked = {i for i in _staged_ids() if any(s.endswith(i) for s in shipped)}
    assert not leaked, f"staged rules would run in a scan: {sorted(leaked)}"


def test_staged_rules_are_not_counted_as_coverage():
    counted = set(rule_coverage.shipped_rule_languages())
    leaked = _staged_ids() & counted
    assert not leaked, f"staged rules counted as coverage: {sorted(leaked)}"


def test_a_rule_is_shipped_or_staged_never_both():
    counted = set(rule_coverage.shipped_rule_languages())
    assert not (_staged_ids() & counted)
