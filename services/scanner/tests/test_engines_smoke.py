"""Engine smoke tests — prove each scanning engine actually finds issues.

These run against tests/fixtures/vulnerable_app/, which contains planted
vulnerabilities for every engine. They guard against *silent engine death*
(e.g. the semgrep pkg_resources crash that returned 0 findings while looking
healthy).

Each test skips locally when its underlying tool isn't installed, and runs for
real inside the scanner image (`make smoke`), where it asserts findings > 0 and
that the engine did not fail.
"""
from __future__ import annotations

import os

import pytest

from config import get_settings
from models.scan_request import ScanRequest
from models.scan_result import EngineStatus
from utils.sandbox import binary_available

from engines import (  # noqa: E402
    gitleaks_engine,
    quality_engine,
    semgrep_engine,
    trivy_engine,
)

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "vulnerable_app")
settings = get_settings()


def _req() -> ScanRequest:
    return ScanRequest(path=FIXTURE, scan_id="smoke")


def _lizard_available() -> bool:
    try:
        import lizard  # noqa: F401

        return True
    except ImportError:
        return False


def _assert_alive(result, engine: str):
    # The engine must not have failed (this is what catches a crashed tool that
    # was swallowed as a non-fatal exit code), and must produce findings.
    assert result.status != EngineStatus.FAILED, f"{engine} failed: {result.error}"
    assert (
        len(result.findings) > 0
    ), f"{engine} produced 0 findings on the vulnerable fixture (engine likely broken)"


@pytest.mark.skipif(
    not binary_available(settings.semgrep_bin),
    reason="semgrep binary not available (run via `make smoke`)",
)
async def test_semgrep_finds_issues():
    _assert_alive(await semgrep_engine.run(_req(), settings), "semgrep")


@pytest.mark.skipif(
    not binary_available(settings.trivy_bin),
    reason="trivy binary not available (run via `make smoke`)",
)
async def test_trivy_finds_issues():
    _assert_alive(await trivy_engine.run(_req(), settings), "trivy")


@pytest.mark.skipif(
    not binary_available(settings.gitleaks_bin),
    reason="gitleaks binary not available (run via `make smoke`)",
)
async def test_gitleaks_finds_issues():
    _assert_alive(await gitleaks_engine.run(_req(), settings), "gitleaks")


@pytest.mark.skipif(not _lizard_available(), reason="lizard not installed")
async def test_quality_finds_issues():
    _assert_alive(await quality_engine.run(_req(), settings), "quality")


def test_placeholder_secret_filter_drops_masks_keeps_real():
    # Masked / placeholder values a hardcoded-secret rule over-matches → dropped.
    for line in (
        '  dummyPassword: string = "***********************";',
        '  const pw = "changeme";',
        '  apiKey = "your_api_key_here";',
        "  token = ''",
    ):
        assert semgrep_engine._is_placeholder_secret(line) is True, line
    # A genuine literal secret must be kept.
    for line in (
        '  password = "Sup3rS3cretPw!99";',
        '  const token = "n8fH2kLpQ7rT3wYxZ0bV";',
    ):
        assert semgrep_engine._is_placeholder_secret(line) is False, line
