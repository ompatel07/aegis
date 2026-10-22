"""N4: the three-tier staging policy.

  PROVEN        fired on real code, 0 FP after triage -> ships, counts as coverage
  SILENT-CLEAN  API-shaped, fixtures pass, 0 FP on the measured corpus, never fired
                -> ships, findings labelled "recall unvalidated", NOT coverage
  STAGED        any known FP, or matches on naming habits -> rules_staging/, never runs

The test that matters: a silent-clean rule can never inflate a language's coverage,
CWE breadth or STRONG evidence. If it did, "recall unvalidated" would be a label on a
number that had already been counted.
"""
from __future__ import annotations

import os

import yaml

from engines import semgrep_engine
from utils import rule_coverage as rc

TAINT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "taint")


def _taint_rules():
    for name in sorted(os.listdir(TAINT)):
        if name.endswith(".yaml"):
            with open(os.path.join(TAINT, name), encoding="utf-8") as fh:
                yield from (yaml.safe_load(fh) or {}).get("rules") or []


def test_validation_values_are_known():
    for r in _taint_rules():
        assert rc.validation_of(r) in ("proven", rc.SILENT_CLEAN), r["id"]


def test_silent_clean_rules_ship():
    """Silent-clean rules RUN: they are in the bundled taint dir the engine loads."""
    sc = rc.silent_clean_rule_ids()
    assert sc, "N4 shipped seven silent-clean rules"
    loaded = semgrep_engine._rule_ids_in(semgrep_engine._custom_rules_dir())
    for rid in sc:
        assert any(x.endswith(rid) for x in loaded), f"{rid} is silent-clean but not loaded"


def test_silent_clean_rules_are_not_coverage():
    sc = rc.silent_clean_rule_ids()
    counted = set(rc.shipped_rule_languages())
    assert not (sc & counted), f"silent-clean rules counted as coverage: {sorted(sc & counted)}"
    # ...and the per-language index agrees: rebuild it by hand, excluding them.
    for r in _taint_rules():
        if r["id"] in sc:
            assert not rc.counts_as_coverage(r)


def test_silent_clean_rules_cannot_be_strong_evidence():
    """A documented vulnerability caught only by a silent-clean rule is not evidence
    for the bar: such a rule must be promoted first, on its own triaged findings."""
    from utils import tier_bar as tb

    sc = sorted(rc.silent_clean_rule_ids())
    assert sc, "expected at least one silent-clean rule"
    shipped = rc.shipped_rule_languages()
    assert all(rid not in shipped for rid in sc)
    gt = {"c": {"language": "java", "role": tb.HELD_OUT,
                "items": [{"id": "x", "scope": "IN", "status": "DET", "rules": [sc[0]]}]}}
    ev = tb.evaluate(gt, [], shipped, {"java"})["java"]
    assert ev.held_out_detected == 0 and ev.detection_corpora == []


def test_silent_clean_findings_are_labelled():
    raw = {"results": [
        {"check_id": "rules.taint.aegis-java-weak-cipher", "path": "/r/A.java",
         "start": {"line": 3, "col": 1}, "end": {"line": 3, "col": 9},
         "extra": {"message": "DES", "severity": "ERROR",
                   "metadata": {"cwe": ["CWE-327"], "aegis-validation": "silent-clean"}}},
        {"check_id": "rules.taint.aegis-java-weak-random-secret", "path": "/r/B.java",
         "start": {"line": 5, "col": 1}, "end": {"line": 5, "col": 9},
         "extra": {"message": "weak random", "severity": "WARNING",
                   "metadata": {"cwe": ["CWE-330"]}}},
    ]}
    by_rule = {f.rule_id: f for f in semgrep_engine._parse(raw, "/r")}
    sc = by_rule["aegis-java-weak-cipher"].metadata
    assert sc["recall_unvalidated"] is True and sc["validation"] == "silent-clean"
    proven = by_rule["aegis-java-weak-random-secret"].metadata
    assert "recall_unvalidated" not in proven and "validation" not in proven


def test_staged_rules_are_not_silent_clean():
    """A rule is in exactly one tier."""
    staging = os.path.join(os.path.dirname(TAINT), "..", "rules_staging")
    for name in os.listdir(staging):
        if name.endswith(".yaml"):
            with open(os.path.join(staging, name), encoding="utf-8") as fh:
                for r in (yaml.safe_load(fh) or {}).get("rules") or []:
                    assert r["id"] not in rc.silent_clean_rule_ids()
                    assert rc.validation_of(r) == "proven", (
                        f"{r['id']} is staged; it must not carry a shipping label")
