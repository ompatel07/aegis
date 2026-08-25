"""Reliability-bug rule pack tests (Q1).

The bug pack (rules/quality/bugs.yaml) makes the highest-trust-cost claim we
ship — "your code is wrong" — so it is gated to zero false positives. These
tests prove two things:

1. Every `ruleid:`/`ok:` annotation in the fixtures behaves — each planted bug
   fires, and each correct-code line stays silent. `semgrep --test` cannot pair
   one multi-language config with several fixtures (it crashes), so we run
   semgrep directly and check annotations against the JSON, the same way the
   pack was validated. Skips when semgrep is unavailable.
2. The pillar/issue_type wiring: the pack loads into
   enricher._QUALITY_BUG_RULES, bug findings are tagged issue_type=bug, quality
   smells stay code_smell, and security findings stay vulnerabilities. This runs
   without semgrep so it always guards the routing.
"""
from __future__ import annotations

import json
import os
import re
import subprocess

import pytest

from config import get_settings
from utils.sandbox import binary_available

settings = get_settings()
QUALITY_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules", "quality")
_ANN = re.compile(r"(?://|#)\s*(ruleid|ok):\s*([A-Za-z0-9_-]+)")


@pytest.mark.skipif(
    not binary_available(settings.semgrep_bin),
    reason="semgrep binary not available (run via `make smoke`)",
)
def test_bug_rules_match_fixture_annotations():
    fixtures = [
        f for f in os.listdir(QUALITY_DIR)
        if f.startswith("bugs.") and not f.endswith((".yaml", ".yml"))
    ]
    assert fixtures, "no bug-rule fixtures found"
    proc = subprocess.run(
        [settings.semgrep_bin, "--quiet", "--config", os.path.join(QUALITY_DIR, "bugs.yaml"),
         "--json", *[os.path.join(QUALITY_DIR, f) for f in fixtures]],
        capture_output=True, text=True, timeout=600,
    )
    data = json.loads(proc.stdout)
    assert not data.get("errors"), f"semgrep rule errors: {data.get('errors')}"

    hits: dict[tuple[str, int], set[str]] = {}
    for r in data["results"]:
        rid = r["check_id"].split(".")[-1]
        hits.setdefault((os.path.basename(r["path"]), r["start"]["line"]), set()).add(rid)

    expected: dict[tuple[str, int], set[str]] = {}
    problems: list[str] = []
    for f in fixtures:
        lines = open(os.path.join(QUALITY_DIR, f), encoding="utf-8").read().splitlines()
        for i, line in enumerate(lines):
            m = _ANN.search(line)
            if not m:
                continue
            kind, rid = m.group(1), m.group(2)
            tgt = i + 2  # annotation sits on the line above the code
            got = hits.get((f, tgt), set())
            if kind == "ruleid":
                expected.setdefault((f, tgt), set()).add(rid)
                if rid not in got:
                    problems.append(f"MISS {f}:{tgt} expected {rid}, got {sorted(got) or 'none'}")
            elif rid in got:
                problems.append(f"FALSE POSITIVE {f}:{tgt} {rid} fired on correct code")
    # No finding may land on a line we didn't mark as a positive.
    for (bn, ln), rules in hits.items():
        for rid in rules:
            if rid not in expected.get((bn, ln), set()):
                problems.append(f"UNEXPECTED {bn}:{ln} {rid}")
    assert not problems, "bug-rule fixture mismatches:\n  " + "\n  ".join(problems)


def test_bug_pack_loads_into_quality_bug_rules():
    from enrichment import enricher

    rules = enricher._QUALITY_BUG_RULES
    for rid in (
        "aegis-bug-identical-if-else-branches",
        "aegis-bug-identical-if-else-branches-go",
        "aegis-bug-identical-if-else-branches-py",
        "aegis-bug-return-in-finally",
        "aegis-bug-return-in-finally-java",
        "aegis-bug-mutable-default-arg",
        "aegis-bug-java-string-literal-equality",
    ):
        assert rid in rules, f"{rid} not loaded from bugs.yaml"
    # Dropped rule must NOT be present.
    assert "aegis-bug-self-assignment" not in rules


def test_bug_findings_are_typed_bug_smells_stay_smell_security_stays_vuln():
    from enrichment import enricher
    from models.scan_result import Engine, Finding, Pillar, Severity

    def mk(rid, pillar):
        return Finding(rule_id=rid, rule_name=rid, engine=Engine.SEMGREP, pillar=pillar,
                       severity=Severity.MEDIUM, title=rid, file_path="f", metadata={})

    bug = mk("aegis-bug-identical-if-else-branches", Pillar.QUALITY)
    smell = mk("quality/magic-numbers", Pillar.QUALITY)
    vuln = mk("aegis-php-xss", Pillar.SECURITY)
    enricher.enrich_all([bug, smell, vuln], "")
    assert bug.issue_type == "bug"
    assert smell.issue_type == "code_smell"
    assert vuln.issue_type == "vulnerability"


def test_no_bug_rule_emits_critical_severity():
    """Severity cap: no aegis-bug-* rule may declare ERROR (which our normalizer
    can escalate to critical). Worst allowed is WARNING (-> medium)."""
    import yaml

    with open(os.path.join(QUALITY_DIR, "bugs.yaml"), encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    for rule in doc["rules"]:
        assert rule["severity"] in ("INFO", "WARNING"), (
            f"{rule['id']} declares {rule['severity']}; bug rules cap at WARNING"
        )
