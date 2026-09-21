"""N1: no rule with a non-permitted licence can reach a scan, and nothing can
fetch rules from the Semgrep registry.

The static half (licences per rule, manifest integrity, logic fingerprints of
removed rules, fetch constructs in source) is tools/check_rule_licences.py, run
here and in self-scan.yml. This file adds the behavioural half: whatever an
operator puts in settings, whatever a pack map says, the semgrep command line
only ever carries local rule files.
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys

from config import Settings
from engines import semgrep_engine

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "tools", "check_rule_licences.py")


def test_rule_licence_guard_passes_on_the_shipped_tree():
    out = subprocess.run([sys.executable, TOOL], capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr


def test_registry_shortcuts_in_settings_are_refused_not_fetched():
    s = Settings(semgrep_base_configs="p/default,p/owasp-top-ten,r/some.rule,auto,https://semgrep.dev/c/p/x")
    cfgs = semgrep_engine._select_configs(s, ["python", "javascript", "php", "java"], ["docker", "terraform"])
    assert cfgs, "JS should still select the pinned njsscan pack"
    for c in cfgs:
        assert os.path.isfile(c) or os.path.isdir(c), f"non-local config reached semgrep: {c}"


def test_no_language_or_project_type_maps_to_a_registry_pack():
    for lang, packs in semgrep_engine._LANGUAGE_RULESETS.items():
        for p in packs:
            assert semgrep_engine._vendored(p), f"{lang} maps to {p}, which is not a shipped pack"
    assert not hasattr(semgrep_engine, "_IAC_RULESETS"), "N1 removed the p/dockerfile + p/terraform map"
    cfgs = semgrep_engine._select_configs(Settings(), [], ["docker", "terraform"])
    assert cfgs == []


def test_missing_pack_is_dropped_never_a_registry_shortcut():
    assert semgrep_engine._vendored("p/default") is None
    assert semgrep_engine._vendored("nonexistent-pack") is None


def test_command_line_carries_only_local_configs(monkeypatch, tmp_path):
    """Drive the real entrypoint and inspect the argv semgrep would receive."""
    from models.scan_request import ScanRequest
    from utils.sandbox import CommandResult

    seen: list[list[str]] = []

    async def fake_run_command(args, **kwargs):
        seen.append(list(args))
        return CommandResult(args=args, returncode=0, stdout='{"results": [], "errors": []}',
                             stderr="", duration_seconds=0.01, timed_out=False)

    monkeypatch.setattr(semgrep_engine, "run_command", fake_run_command)
    (tmp_path / "a.js").write_text("var x = 1;\n", encoding="utf-8")
    s = Settings(semgrep_base_configs="p/default,auto")
    req = ScanRequest(path=str(tmp_path), scan_id="n1-argv", languages=["javascript", "python"],
                      project_types=["docker"])
    asyncio.run(semgrep_engine.run(req, s))

    assert len(seen) == 1
    argv = seen[0]
    cfgs = [argv[i + 1] for i, a in enumerate(argv) if a == "--config"]
    assert cfgs, "semgrep must never run without an explicit --config (its default is `auto`)"
    for c in cfgs:
        assert os.path.isfile(c) or os.path.isdir(c), f"non-local --config {c}"
    assert "--validate" not in argv


def test_result_reports_which_rules_ran_and_which_ship(monkeypatch, tmp_path):
    """Lifecycle evidence (N1): the orchestrator may only resolve a finding whose rule
    ran. The ids must be the canonical ids findings carry, or nothing would ever match."""
    from models.scan_request import ScanRequest
    from utils.sandbox import CommandResult

    async def fake_run_command(args, **kwargs):
        return CommandResult(args=args, returncode=0, stdout='{"results": [], "errors": []}',
                             stderr="", duration_seconds=0.01, timed_out=False)

    monkeypatch.setattr(semgrep_engine, "run_command", fake_run_command)
    (tmp_path / "a.js").write_text("var x = 1;\n", encoding="utf-8")

    js = asyncio.run(semgrep_engine.run(
        ScanRequest(path=str(tmp_path), scan_id="n1-ev-js", languages=["javascript"], project_types=[]),
        Settings()))
    py = asyncio.run(semgrep_engine.run(
        ScanRequest(path=str(tmp_path), scan_id="n1-ev-py", languages=["python"], project_types=[]),
        Settings()))

    shipped = set(js.rules_shipped or [])
    assert len(shipped) == len(semgrep_engine._shipped_rule_ids()) and "aegis-php-sql-injection" in shipped
    assert any(r.startswith("ajinabraham.njsscan.") for r in shipped)
    # JS ran njsscan and our packs; Python ran our packs only -- njsscan shipped but did not run.
    assert "aegis-php-sql-injection" in js.rules_executed and "aegis-php-sql-injection" in py.rules_executed
    assert any(r.startswith("ajinabraham.njsscan.") for r in js.rules_executed)
    assert not any(r.startswith("ajinabraham.njsscan.") for r in py.rules_executed)
    assert set(py.rules_executed) <= shipped
