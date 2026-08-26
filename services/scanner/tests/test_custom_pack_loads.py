"""Guard: the Aegis custom Semgrep packs actually LOAD in a real scan.

Validation Run V1 found that a non-rule YAML (`ruff_map.yaml`) sitting inside a
semgrep-loaded directory made `semgrep --config rules/quality` exit 2, after
which the engine silently retried with registry packs ONLY — dropping the custom
taint engine and the reliability bug pack on every scan. 85 unit tests and the
36/36 taint suite were green throughout, because none of them exercised the real
combined-config scan path.

This test closes that gap: it runs the FULL semgrep entrypoint
(`semgrep_engine.run`, exactly what POST /scan/sast calls) against a fixture with
a planted violation of an Aegis-authored rule, and asserts that specific
`aegis-*` rule id comes back. If the custom pack ever degrades to registry-only,
this test fails instead of the failure being invisible.
"""
from __future__ import annotations

import asyncio

import pytest

from config import get_settings
from engines import semgrep_engine
from models.scan_request import ScanRequest
from utils.sandbox import binary_available

settings = get_settings()

# An Aegis-authored quality/bug rule (rules/quality/bugs.yaml). `.length < 0` is
# always false — the rule fires on this line and nowhere in the registry packs.
_SENTINEL_RULE = "aegis-bug-js-length-lt-zero"


@pytest.mark.skipif(
    not binary_available(settings.semgrep_bin),
    reason="semgrep binary not available (run via `make smoke`)",
)
def test_custom_pack_loads_in_real_scan(tmp_path):
    (tmp_path / "g.js").write_text(
        "function g(x) {\n  if (x.length < 0) {\n    return 1;\n  }\n}\n",
        encoding="utf-8",
    )
    req = ScanRequest(path=str(tmp_path), scan_id="custom-pack-load")
    result = asyncio.run(semgrep_engine.run(req, settings))

    assert result.status.value in ("completed", "success"), (
        f"semgrep scan did not complete: status={result.status}, error={result.error}"
    )
    rule_ids = {f.rule_id for f in result.findings}
    assert _SENTINEL_RULE in rule_ids, (
        f"custom Aegis pack did NOT load — sentinel rule {_SENTINEL_RULE!r} absent. "
        f"The scan likely degraded to registry packs only (a non-rule YAML in a "
        f"semgrep-loaded dir makes --config exit 2 and the engine retries without "
        f"custom rules). Got {len(rule_ids)} distinct rule ids, "
        f"{sum(1 for r in rule_ids if str(r).startswith('aegis'))} of them aegis-*."
    )
