"""Custom taint-rule tests — prove every rule fires on a vuln and stays silent
on the sanitized version.

Runs `semgrep --test` over rules/taint/, which pairs each rule file with its
same-named fixture and asserts that every `# ruleid:` line produces a finding
and every `# ok:` (sanitized) line does not. This is the guard against false
positives — the metric that kills developer trust in a SAST tool — so a
regression that makes a rule fire on sanitized code fails the build.

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
RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules", "taint")


@pytest.mark.skipif(
    not binary_available(settings.semgrep_bin),
    reason="semgrep binary not available (run via `make smoke`)",
)
def test_custom_taint_rules_pass_semgrep_test():
    proc = subprocess.run(
        [settings.semgrep_bin, "--test", "--config", RULES_DIR, RULES_DIR],
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert proc.returncode == 0, (
        f"semgrep --test failed (rc={proc.returncode}). A custom taint rule either "
        f"stopped detecting a planted vuln or now fires on sanitized code.\n"
        f"stdout tail:\n{proc.stdout[-3000:]}\nstderr tail:\n{proc.stderr[-2000:]}"
    )
    assert "All tests passed" in proc.stdout, proc.stdout[-3000:]


def test_rules_directory_is_present_and_populated():
    """The rules ship in the image; a packaging regression that dropped them
    would silently disable all custom detection."""
    assert os.path.isdir(RULES_DIR), f"custom rules dir missing: {RULES_DIR}"
    yamls = [f for f in os.listdir(RULES_DIR) if f.endswith((".yaml", ".yml"))]
    assert len(yamls) >= 4, f"expected >= 4 rule files (one per language), found {yamls}"
