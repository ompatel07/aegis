"""CI-mode deployment engine (Pass P3, Part B2).

Aegis is a two-pillar product; the deployment engine is offered ONLY in CI mode,
where it inspects a PRE-BUILT workspace and NEVER builds. These tests prove:
  - no build artifacts -> NOT MEASURED (skipped), and no build subprocess runs;
  - pre-built artifacts present -> measured (a passing `build` step);
  - CI mode never invokes a build/install command, even when a build command exists.
"""
from __future__ import annotations

import asyncio
import os

import pytest

from config import get_settings
from engines import deployment_engine
from models.scan_request import DeploymentRequest
from models.scan_result import EngineStatus

settings = get_settings()


def _run(path: str):
    return asyncio.run(
        deployment_engine.run(DeploymentRequest(path=path, scan_id="ci", ci_mode=True), settings)
    )


def test_ci_mode_no_artifacts_is_not_measured(tmp_path, monkeypatch):
    # Any build subprocess must blow up — CI mode must never build.
    async def _boom(*a, **k):
        raise AssertionError(f"build subprocess invoked in CI mode: {a[:1]}")

    monkeypatch.setattr(deployment_engine, "run_command", _boom)

    res = _run(str(tmp_path))
    assert res.status == EngineStatus.SKIPPED  # NOT MEASURED
    names = [s.name for s in res.deployment_report.steps]
    assert "ci-artifacts-missing" in names
    # no scored build step -> the orchestrator's DeploymentScore reads nil
    assert "build" not in names


def test_ci_mode_with_artifacts_is_measured(tmp_path, monkeypatch):
    async def _boom(*a, **k):
        raise AssertionError(f"build subprocess invoked in CI mode: {a[:1]}")

    monkeypatch.setattr(deployment_engine, "run_command", _boom)

    os.makedirs(tmp_path / "node_modules")
    res = _run(str(tmp_path))
    assert res.status == EngineStatus.COMPLETED
    steps = {s.name: s.success for s in res.deployment_report.steps}
    assert steps.get("build") is True  # pre-built artifacts => build-verified


def test_ci_mode_never_builds_even_with_build_system(tmp_path, monkeypatch):
    # A real build system (package.json) present but NO artifacts: still NOT MEASURED,
    # still no subprocess — CI mode never falls back to building.
    async def _boom(*a, **k):
        raise AssertionError(f"build subprocess invoked in CI mode: {a[:1]}")

    monkeypatch.setattr(deployment_engine, "run_command", _boom)

    (tmp_path / "package.json").write_text('{"name":"x","scripts":{"build":"tsc"}}', encoding="utf-8")
    res = _run(str(tmp_path))
    assert res.status == EngineStatus.SKIPPED
