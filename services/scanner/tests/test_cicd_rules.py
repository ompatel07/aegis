"""Custom CI/CD (GitHub Actions) rule tests — prove every aegis-cicd-* rule fires
on a vulnerable workflow step and stays silent on the fixed one.

Two things make this pack different from the others and both are load-bearing:

1. Every rule is path-scoped to `**/.github/workflows/*.yml`, so the fixture must
   itself sit at such a path. A fixture parked anywhere else matches nothing and
   the test passes vacuously — which is worse than no test.
2. `semgrep --test` only pairs a rule with a fixture reliably when BOTH arguments
   are files; handing it a directory sends it down a relative-path branch that
   raises IndexError. So the pairing is made explicitly here.

Skips locally when semgrep isn't installed; runs for real inside the scanner
image (`make smoke`).
"""
from __future__ import annotations

import os
import subprocess

import pytest
import yaml

from config import get_settings
from utils.sandbox import binary_available

settings = get_settings()
_SCANNER_ROOT = os.path.dirname(os.path.dirname(__file__))
RULES_DIR = os.path.join(_SCANNER_ROOT, "rules", "cicd")
RULE_FILE = os.path.join(RULES_DIR, "github_actions.yaml")
FIXTURE = os.path.join(
    _SCANNER_ROOT, "tests", "fixtures", "cicd", ".github", "workflows",
    "github_actions.yml",
)


@pytest.mark.skipif(
    not binary_available(settings.semgrep_bin),
    reason="semgrep binary not available (run via `make smoke`)",
)
def test_cicd_rules_pass_semgrep_test():
    proc = subprocess.run(
        [settings.semgrep_bin, "--test", "--config", RULE_FILE, FIXTURE],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, (
        f"semgrep --test failed (rc={proc.returncode}). An aegis-cicd-* rule either "
        f"stopped firing on a vulnerable workflow step or now fires on the fixed "
        f"one.\nstdout tail:\n{proc.stdout[-3000:]}\nstderr tail:\n{proc.stderr[-2000:]}"
    )
    assert "All tests passed" in proc.stdout, proc.stdout[-3000:]


def test_fixture_sits_at_a_workflow_path():
    """The rules only apply under .github/workflows. If the fixture is ever moved
    out of such a path the semgrep test above would pass while matching nothing,
    so assert the location the scoping depends on."""
    assert os.path.isfile(FIXTURE), FIXTURE
    assert FIXTURE.replace(os.sep, "/").endswith(".github/workflows/github_actions.yml")


def test_cicd_rules_are_scoped_and_routed():
    """Each rule must be path-scoped (otherwise it fires on every YAML file in a
    repo) and must not claim the quality pillar (these are security findings)."""
    with open(RULE_FILE, encoding="utf-8") as fh:
        rules = yaml.safe_load(fh)["rules"]
    assert rules, "no rules loaded"
    for rule in rules:
        rid = rule["id"]
        assert rid.startswith("aegis-cicd-"), rid
        includes = rule.get("paths", {}).get("include", [])
        assert includes, f"{rid} is not path-scoped; it would fire on all YAML"
        assert all(".github/" in inc for inc in includes), f"{rid} scoping too broad: {includes}"
        assert rule.get("metadata", {}).get("pillar") != "quality", rid


def test_cicd_rules_directory_holds_only_rule_files():
    """The scanner loads rules/cicd as a directory config; a stray non-rule YAML
    (e.g. a test target) placed here would be parsed as a rule and could disable
    CI/CD scanning entirely."""
    for name in os.listdir(RULES_DIR):
        if not name.endswith((".yaml", ".yml")):
            continue
        with open(os.path.join(RULES_DIR, name), encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        assert isinstance(doc, dict) and "rules" in doc, (
            f"rules/cicd/{name} is not a semgrep rule file. Everything in this "
            f"directory is loaded as a --config; move test targets to tests/fixtures/."
        )
