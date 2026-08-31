"""Seam tests (Pass D1, Part C) — end-to-end through the REAL scanner entrypoints,
not the internals. Each per-engine unit test can be green while the SEAMS between
them are broken (a non-rule YAML silently drops the custom pack; an emptied bug set
mislabels every reliability bug as a smell; a redaction chokepoint that's bypassed
on one path). These tests exercise the joints.

Five seams:
  1. Custom rule packs actually load (an aegis-* rule fires in a real scan).
  2. No plaintext secret survives egress (the serialization chokepoint holds).
  3. The reliability SOURCE moves across repos — bug findings are tagged
     issue_type=bug, so a buggy repo differs from a clean one. This is the
     scanner half of "no rating is constant across different repos"; the rating
     half is orchestrator-side (pipeline/seams_test.go,
     TestSeamRatingsNeverConstantAcrossRepos). Emptying _QUALITY_BUG_RULES makes
     this seam collapse (buggy repo == clean repo) and the test FAILS.
  4. A degraded engine produces a DEGRADED result, never a clean one.
  5. Determinism — the same repo scanned twice yields identical findings.
"""
from __future__ import annotations

import asyncio

import pytest

from config import get_settings
from utils.sandbox import binary_available

settings = get_settings()

_SEMGREP = pytest.mark.skipif(
    not binary_available(settings.semgrep_bin),
    reason="semgrep binary not available (run via `make smoke`)",
)


# ── Seam 1: custom packs load in a real scan ─────────────────────────────────
@_SEMGREP
def test_seam_custom_pack_fires_aegis_rule(tmp_path):
    from engines import semgrep_engine
    from models.scan_request import ScanRequest

    (tmp_path / "g.js").write_text(
        "function g(x) {\n  if (x.length < 0) {\n    return 1;\n  }\n}\n", encoding="utf-8"
    )
    req = ScanRequest(path=str(tmp_path), scan_id="seam-custom-pack")
    result = asyncio.run(semgrep_engine.run(req, settings))
    assert result.status.value in ("completed", "success")
    rule_ids = {f.rule_id for f in result.findings}
    assert any(str(r).startswith("aegis-") for r in rule_ids), (
        f"no aegis-* rule fired — custom pack degraded to registry-only. Got {rule_ids}"
    )


# ── Seam 2: no plaintext secret leaves via egress ────────────────────────────
def test_seam_no_plaintext_secret_in_egress():
    from enrichment import secret_registry
    from models.scan_result import Engine, EngineResult, EngineStatus, Pillar

    sentinel = "S3amEgressSecretQ9xZ2wErtY7uIoP1aSdF4gHj"
    secret_registry.record("seam-egress", [sentinel])
    r = EngineResult(
        engine=Engine.GITLEAKS, pillar=Pillar.SECURITY, status=EngineStatus.COMPLETED,
        scan_id="seam-egress", raw={"finding": {"secret": f'token = "{sentinel}"'}},
    )
    assert sentinel not in r.model_dump_json(), "plaintext secret leaked through egress"


# ── Seam 3: the reliability source moves (issue_type=bug wiring) ─────────────
def test_seam_reliability_source_not_constant_across_repos():
    """A buggy repo must produce reliability BUGS that a clean/duplicated repo does
    not. If _QUALITY_BUG_RULES is emptied, the buggy repo's findings fall back to
    `code_smell`, the bug count collapses to 0 for every repo, and this fails —
    the exact re-plant the gate asks us to guard against."""
    from enrichment import enricher
    from models.scan_result import Engine, Finding, Pillar, Severity

    def mk(rid, pillar, sev=Severity.MEDIUM):
        return Finding(rule_id=rid, rule_name=rid, engine=Engine.SEMGREP, pillar=pillar,
                       severity=sev, title=rid, file_path="f", metadata={})

    def bug_count(findings):
        enricher.enrich_all(findings, "")
        return sum(1 for f in findings if f.issue_type == "bug")

    # A real bug-pack rule id — the reliability signal for the "vulnerable" repo.
    clean = [mk("quality/magic-numbers", Pillar.QUALITY)]
    vulnerable = [
        mk("aegis-bug-identical-if-else-branches", Pillar.QUALITY),
        mk("aegis-bug-return-in-finally", Pillar.QUALITY),
    ]
    duplicated = [mk("quality/duplicate-block", Pillar.QUALITY)]

    counts = {"clean": bug_count(clean), "vuln": bug_count(vulnerable), "dup": bug_count(duplicated)}
    assert counts["vuln"] >= 1, (
        f"buggy repo produced 0 reliability bugs — bug-pack tagging is broken "
        f"(is _QUALITY_BUG_RULES empty?). counts={counts}"
    )
    assert len(set(counts.values())) > 1, (
        f"reliability bug count is CONSTANT across clean/vulnerable/duplicated repos "
        f"({counts}) — reliability would be constant-A for every repo"
    )


# ── Seam 4: a degraded engine yields a DEGRADED result, never clean ─────────
def test_seam_degraded_engine_is_not_clean(monkeypatch):
    """Drive the real semgrep entrypoint but make the first (custom-pack) invocation
    fail hard (rc=2) and the registry-only retry succeed. The result must be
    completed-but-DEGRADED with the lost coverage named — never a clean success."""
    from engines import semgrep_engine
    from models.scan_request import ScanRequest
    from utils.sandbox import CommandResult

    calls = {"n": 0}

    async def fake_run_command(args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            # first call includes the custom packs → simulate a hard rule-load error
            return CommandResult(args=args, returncode=2, stdout="", stderr="invalid rule: boom",
                                 duration_seconds=0.01, timed_out=False)
        # retry with registry packs only → clean success, no findings
        return CommandResult(args=args, returncode=0, stdout='{"results": [], "errors": []}',
                             stderr="", duration_seconds=0.01, timed_out=False)

    monkeypatch.setattr(semgrep_engine, "run_command", fake_run_command)
    req = ScanRequest(path=str(_a_dir()), scan_id="seam-degraded")
    result = asyncio.run(semgrep_engine.run(req, settings))

    assert result.status.value in ("completed", "success"), "a broken pack must not fail the whole scan"
    assert result.degraded is True, "engine ran with reduced coverage but did not report DEGRADED"
    assert result.coverage_lost, "degraded result must name the coverage it lost"
    assert calls["n"] == 2, "expected a registry-only retry after the custom-pack failure"


# ── Seam 5: determinism — same repo twice, identical findings ───────────────
@_SEMGREP
def test_seam_scan_is_deterministic(tmp_path):
    from engines import semgrep_engine
    from models.scan_request import ScanRequest

    (tmp_path / "g.js").write_text(
        "function g(x) {\n  if (x.length < 0) {\n    return 1;\n  }\n}\n", encoding="utf-8"
    )

    def projection():
        req = ScanRequest(path=str(tmp_path), scan_id="seam-determinism")
        res = asyncio.run(semgrep_engine.run(req, settings))
        # Compare the MEANINGFUL output (findings), not volatile timing/scan_id.
        return sorted(
            (f.rule_id, f.file_path, f.line_start, f.severity.value) for f in res.findings
        )

    first, second = projection(), projection()
    assert first == second, f"scan is non-deterministic:\n  {first}\n  {second}"


def _a_dir():
    import tempfile
    d = tempfile.mkdtemp(prefix="seam-degraded-")
    with open(f"{d}/a.py", "w", encoding="utf-8") as fh:
        fh.write("x = 1\n")
    return d
