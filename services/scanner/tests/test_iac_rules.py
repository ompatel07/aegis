"""Custom IaC (docker-compose) rule tests — prove every Aegis compose rule fires
on a misconfigured service and stays silent on the hardened one.

The compose rules live in rules/iac/docker_compose.yaml, but the scanner passes
the whole rules/iac directory as a semgrep --config, so the test *target* cannot
live there (semgrep would load it as a broken rule and disable compose scanning).
The fixture therefore lives under tests/fixtures/iac/ and is paired with the rule
explicitly here, mirroring test_taint_rules.py.

Skips locally when semgrep isn't installed; runs for real inside the scanner
image (`make smoke`).
"""
from __future__ import annotations

import os
import subprocess

import pytest

from config import get_settings
from utils.sandbox import binary_available

settings = get_settings()
_SCANNER_ROOT = os.path.dirname(os.path.dirname(__file__))
RULE_FILE = os.path.join(_SCANNER_ROOT, "rules", "iac", "docker_compose.yaml")
FIXTURE = os.path.join(_SCANNER_ROOT, "tests", "fixtures", "iac", "docker_compose.yml")


@pytest.mark.skipif(
    not binary_available(settings.semgrep_bin),
    reason="semgrep binary not available (run via `make smoke`)",
)
def test_compose_rules_pass_semgrep_test():
    proc = subprocess.run(
        [settings.semgrep_bin, "--test", "--config", RULE_FILE, FIXTURE],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, (
        f"semgrep --test failed (rc={proc.returncode}). An Aegis docker-compose rule "
        f"either stopped firing on a misconfigured service or now fires on the "
        f"hardened one.\nstdout tail:\n{proc.stdout[-3000:]}\nstderr tail:\n{proc.stderr[-2000:]}"
    )
    assert "All tests passed" in proc.stdout, proc.stdout[-3000:]


def test_iac_rules_directory_holds_only_rule_files():
    """The scanner loads rules/iac as a directory config; a stray non-rule YAML
    (e.g. a test target) placed here would be parsed as a rule and disable
    compose scanning. Guard against that packaging mistake."""
    rules_dir = os.path.join(_SCANNER_ROOT, "rules", "iac")
    assert os.path.isdir(rules_dir), f"IaC rules dir missing: {rules_dir}"
    yamls = [f for f in os.listdir(rules_dir) if f.endswith((".yaml", ".yml"))]
    assert yamls, "expected at least the docker_compose.yaml rule file"
    for f in yamls:
        assert f == "docker_compose.yaml", (
            f"unexpected YAML in rules/iac: {f} — only rule files belong here "
            f"(test targets go under tests/fixtures/iac/)."
        )
