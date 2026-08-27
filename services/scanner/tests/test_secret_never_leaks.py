"""Plaintext-secret leak gate (S1 follow-up).

Removing gitleaks --redact means the raw value now transits the classification
boundary. This test plants a unique sentinel secret, runs a FULL scan through the
real entrypoint (gitleaks_engine.run), and asserts the sentinel plaintext appears
in NONE of the places a secret could escape. It is the gate — a code reading is not
sufficient.

Coverage map (10 sinks from the spec):
  1 EngineResult.raw            -> asserted directly
  2 scanner HTTP response body  -> result.model_dump_json() (exactly what is sent)
  3 scans.raw_gitleaks_output   -> persisted FROM result.raw (2/1); covered transitively
  4 findings row fields         -> asserted per finding (title/desc/snippet/metadata)
  5 DEBUG stdout/stderr          -> caplog at DEBUG
  6 SARIF export                 -> derived from the serialized EngineResult (2)
  7 compliance report            -> derived from the serialized EngineResult (2)
  8 Asynq/Redis task payload      -> the orchestrator enqueues the serialized result (2)
  9 exception traceback           -> forced raise inside annotate; separate test
 10 /tmp after the scan           -> sweep the gitleaks temp dir

3/6/7/8 are produced by the Go orchestrator from the scanner's serialized
EngineResult; if the sentinel is absent from that payload (1+2+4) it cannot reach
them. This test owns the scanner boundary, which is the sole source for all of them.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os

import pytest

from config import get_settings
from engines import gitleaks_engine
from enrichment import enricher, secret_context
from models.scan_request import ScanRequest
from models.scan_result import Engine, Finding, Pillar, Severity

settings = get_settings()

# unique, high-entropy — gitleaks flags it as a generic-api-key
SENTINEL = "S3nt1nelLeakTestZx7Qw2Ep9Rt4Yu1Io6Pa3Sd8Fg5H"


@pytest.mark.skipif(
    not __import__("utils.sandbox", fromlist=["binary_available"]).binary_available(
        settings.gitleaks_bin),
    reason="gitleaks binary not available",
)
def test_sentinel_secret_never_leaves_in_plaintext(tmp_path, caplog):
    (tmp_path / "config.py").write_text(f'api_key = "{SENTINEL}"\n', encoding="utf-8")
    # the AWS docs example (gitleaks allowlists it) — planted per spec
    (tmp_path / "aws.py").write_text('AWS = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")

    req = ScanRequest(path=str(tmp_path), scan_id="leaktest")
    with caplog.at_level(logging.DEBUG):
        result = asyncio.run(gitleaks_engine.run(req, settings))

    # the sentinel MUST have been detected (else the test is vacuous) — redacted.
    hit = [f for f in result.findings if f.file_path.endswith("config.py")]
    assert hit, "sentinel secret was not detected — test would be vacuous"

    # 1 + 2 + 3 + 4 + 6 + 7 + 8: the serialized EngineResult is the single payload
    # the scanner emits; every downstream sink derives from it.
    serialized = result.model_dump_json()
    assert SENTINEL not in serialized, "sentinel leaked in serialized EngineResult"
    assert SENTINEL not in json.dumps(result.raw or {}), "sentinel leaked in .raw"
    for f in result.findings:
        assert SENTINEL not in json.dumps(f.model_dump(), default=str), (
            f"sentinel leaked in finding {f.rule_id}"
        )

    # 5: DEBUG logs
    assert SENTINEL not in caplog.text, "sentinel leaked into DEBUG logs"

    # 10: /tmp — the report must be shredded; no gitleaks-* file may hold it
    tmpdir = gitleaks_engine._GK_TMPDIR
    if os.path.isdir(tmpdir):
        for name in os.listdir(tmpdir):
            p = os.path.join(tmpdir, name)
            try:
                data = open(p, "rb").read()
            except OSError:
                continue
            assert SENTINEL.encode() not in data, f"sentinel left on disk in {p}"


def _mk(match):
    return Finding(pillar=Pillar.SECURITY, engine=Engine.GITLEAKS, rule_id="generic-api-key",
                   rule_name="x", severity=Severity.CRITICAL, title="x", file_path="src/config.py",
                   code_snippet=f'api_key = "{match}"', metadata={"match": match, "entropy": 5.0})


def test_no_leak_in_exception_traceback(monkeypatch, caplog):
    """Force a raise inside annotate with the value on the stack; the traceback that
    gets logged must not contain the sentinel."""
    import traceback

    def boom(*_a, **_k):
        raise RuntimeError("classification error")  # message carries NO value

    monkeypatch.setattr(secret_context, "_is_placeholder", boom)

    # via the enricher's own guarded call (logs error=str(exc) at DEBUG)
    with caplog.at_level(logging.DEBUG):
        enricher.enrich_all([_mk(SENTINEL)], "")
    assert SENTINEL not in caplog.text

    # and the raw formatted traceback of annotate raising
    try:
        secret_context.annotate([_mk(SENTINEL)])
    except RuntimeError:
        assert SENTINEL not in traceback.format_exc()
    else:
        raise AssertionError("expected annotate to raise")


def test_finally_redacts_match_and_pops_raw_even_when_classification_raises(monkeypatch):
    """annotate's finally must scrub the match and drop the transient _secret_raw
    even if classification raises."""
    def boom(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr(secret_context, "_is_placeholder", boom)
    f = _mk(SENTINEL)
    f.metadata["_secret_raw"] = SENTINEL
    try:
        secret_context.annotate([f])
    except RuntimeError:
        pass
    assert SENTINEL not in (f.metadata.get("match") or "")
    assert "_secret_raw" not in f.metadata


# ── Hole 2: non-token-shaped secrets (gitleaks) ──────────────────────────────
@pytest.mark.skipif(
    not __import__("utils.sandbox", fromlist=["binary_available"]).binary_available(
        settings.gitleaks_bin),
    reason="gitleaks binary not available",
)
def test_non_token_shaped_secret_scrubbed_from_snippet(tmp_path):
    # password (low entropy, not token-shaped) + a URI credential, on adjacent lines
    (tmp_path / "db.py").write_text(
        'DB_PASSWORD = "summer2024"\n'
        'DATABASE_URL = "postgres://admin:hunter2@localhost/db"\n',
        encoding="utf-8",
    )
    req = ScanRequest(path=str(tmp_path), scan_id="nontoken")
    result = asyncio.run(gitleaks_engine.run(req, settings))
    assert result.findings, "expected the connection string to be detected"
    for f in result.findings:
        assert "summer2024" not in (f.code_snippet or ""), "password leaked in snippet"
        assert "hunter2" not in (f.code_snippet or ""), "URI credential leaked in snippet"
    blob = result.model_dump_json()
    assert "summer2024" not in blob and "hunter2" not in blob


# ── Hole 1: a hardcoded secret SEMGREP catches (not gitleaks) ────────────────
@pytest.mark.skipif(
    not __import__("utils.sandbox", fromlist=["binary_available"]).binary_available(
        settings.semgrep_bin),
    reason="semgrep binary not available",
)
def test_semgrep_detected_secret_scrubbed_from_snippet(tmp_path):
    from engines import semgrep_engine

    marker = "Zx7Qw2Ep9Rt4Yu1Io6Pa3Sd8Fg5Hj0KlSEMGREPSENTINEL"
    (tmp_path / "app.js").write_text(
        f'const secret = "{marker}";\nconst password = "{marker}2";\n', encoding="utf-8")
    req = ScanRequest(path=str(tmp_path), scan_id="semgrepsec")
    result = asyncio.run(semgrep_engine.run(req, settings))
    sec = [f for f in result.findings if f.file_path.endswith("app.js")]
    assert sec, "semgrep did not flag the planted secret — test would be vacuous"
    # IF flagged, the snippet AND the line-carrying metadata must be redacted
    # (Hole-1 guard + the metadata.lines carrier). NOTE: EngineResult.raw (the raw
    # semgrep JSON) is a SEPARATE pre-existing carrier, out of scope for the snippet
    # fix — see PRECISION_S1.md "known remaining carriers".
    for f in sec:
        assert marker not in (f.code_snippet or ""), (
            f"semgrep rule {f.rule_id} leaked plaintext in code_snippet"
        )
        assert marker not in json.dumps(f.metadata or {}, default=str), (
            f"semgrep rule {f.rule_id} leaked plaintext in metadata"
        )


# ── Gate 4: snippets stay READABLE — only the secret is masked ───────────────
def test_snippet_stays_readable_only_secret_masked():
    from utils import snippet
    line = 'DB_PASSWORD = "summer2024"  # set in prod'
    out = snippet._redact(line)
    assert "summer2024" not in out          # secret masked
    assert "DB_PASSWORD" in out             # variable name survives
    assert "# set in prod" in out           # trailing comment survives
