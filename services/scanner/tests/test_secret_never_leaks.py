"""Plaintext-secret egress gate (S1 follow-up 3).

Redaction is a BOUNDARY guarantee, not a per-engine responsibility: every
EngineResult is scrubbed at serialization (EngineResult.model_serializer ->
enrichment.egress). These tests prove it holds for EVERY engine, and that a new
engine cannot be added on a path that bypasses the chokepoint.
"""
from __future__ import annotations

import asyncio
import glob
import importlib
import inspect
import json
import logging
import os

import pytest

from config import get_settings
from enrichment import secret_registry
from models.scan_request import DeploymentRequest, ScanRequest
from models.scan_result import Engine, EngineResult, EngineStatus, Finding, Pillar, Severity
from utils.sandbox import binary_available

settings = get_settings()
SENTINEL = "S3nt1nelEgressZx7Qw2Ep9Rt4Yu1Io6Pa3Sd8Fg5Hj0Kl"


# ── the chokepoint is structural: any EngineResult, any engine, redacts ──────
def test_chokepoint_redacts_known_value_for_any_engine():
    secret_registry.record("struct1", [SENTINEL])
    for eng in Engine:
        r = EngineResult(engine=eng, pillar=Pillar.SECURITY, status=EngineStatus.COMPLETED,
                         scan_id="struct1", raw={"nested": {"x": f'k = "{SENTINEL}"'}})
        assert SENTINEL not in r.model_dump_json(), f"{eng} leaked via .raw"


def test_chokepoint_shape_scrubs_unknown_semgrep_secret_in_raw():
    # a secret we NEVER held (no registry value), inside a secret-ish raw result
    secret_registry.record("struct2", [])
    r = EngineResult(engine=Engine.SEMGREP, pillar=Pillar.SECURITY, status=EngineStatus.COMPLETED,
                     scan_id="struct2",
                     raw={"results": [{"check_id": "node_secret",
                                       "extra": {"lines": f'const s = "{SENTINEL}"'}}]})
    assert SENTINEL not in r.model_dump_json()


# ── guard: no engine may bypass the chokepoint (a new engine is caught) ──────
def test_every_engine_run_returns_engineresult():
    """Every engines/*_engine.py entrypoint must return EngineResult, so its output
    passes through the serialization chokepoint. A new engine that returns something
    else (bypassing redaction) fails this."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    mods = sorted(glob.glob(os.path.join(root, "engines", "*_engine.py")))
    assert mods, "no engine modules found"
    checked = 0
    for path in mods:
        name = os.path.splitext(os.path.basename(path))[0]
        mod = importlib.import_module(f"engines.{name}")
        run = getattr(mod, "run", None)
        if run is None:  # a helper module without a public entrypoint
            continue
        ann = str(inspect.signature(run).return_annotation)
        assert "EngineResult" in ann, (
            f"engines.{name}.run must return EngineResult (the chokepoint); got {ann}"
        )
        checked += 1
    assert checked >= 5, f"expected to check most engines, only saw {checked}"


def test_no_second_redaction_path_exists():
    """Redaction lives only at the egress chokepoint. The old per-engine call must
    be gone (two paths is how one rots)."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for path in glob.glob(os.path.join(root, "engines", "*.py")):
        src = open(path, encoding="utf-8").read()
        assert "redact_raw_findings" not in src, f"{path} still calls a per-engine redactor"


# ── parametrized over engines: sentinel absent from each engine's real output ─
def _run(coro):
    return asyncio.run(coro)


def _serialize_engine(engine_name, path, scan_id):
    mod = importlib.import_module(f"engines.{engine_name}")
    if engine_name == "deployment_engine":
        req = DeploymentRequest(path=path, scan_id=scan_id, build_enabled=False)
    else:
        req = ScanRequest(path=path, scan_id=scan_id)
    result = _run(mod.run(req, settings))
    return result.model_dump_json()


ENGINE_BINS = {
    "gitleaks_engine": "gitleaks_bin", "semgrep_engine": "semgrep_bin",
    "trivy_engine": "trivy_bin", "deployment_engine": None, "quality_engine": None,
}


@pytest.mark.parametrize("engine_name", list(ENGINE_BINS))
def test_engine_output_and_logs_have_no_plaintext_secret(engine_name, tmp_path, capfd):
    binattr = ENGINE_BINS[engine_name]
    if binattr and not binary_available(getattr(settings, binattr)):
        pytest.skip(f"{binattr} not available")

    # a fixture that trips gitleaks + semgrep, with the sentinel in several forms
    (tmp_path / "config.py").write_text(f'api_key = "{SENTINEL}"\n', encoding="utf-8")
    (tmp_path / "app.js").write_text(f'const secret = "{SENTINEL}";\n', encoding="utf-8")
    (tmp_path / "Dockerfile").write_text(
        f"FROM python:3.12\nENV API_KEY={SENTINEL}\nUSER root\n", encoding="utf-8")

    scan_id = "egress-param"
    # populate the registry the way a real scan does: secrets engine runs and
    # records the value; every later engine's chokepoint then value-scrubs it too.
    if binary_available(settings.gitleaks_bin):
        _serialize_engine("gitleaks_engine", str(tmp_path), scan_id)

    blob = _serialize_engine(engine_name, str(tmp_path), scan_id)
    logs = capfd.readouterr()  # fd-level → catches structlog's stdout writes
    assert SENTINEL not in blob, f"{engine_name} leaked the sentinel in its result"
    assert SENTINEL not in logs.out and SENTINEL not in logs.err, (
        f"{engine_name} leaked the sentinel into logs"
    )


# ── FAIL CLOSED: a scrub failure must withhold the payload, not leak it ───────
def test_egress_fails_closed_and_marks_scan_failed(monkeypatch):
    from enrichment import egress

    def boom(*_a, **_k):
        raise RuntimeError("scrub blew up")

    # both the full walk AND the fallback fail -> must raise -> withheld result
    monkeypatch.setattr(egress, "_walk", boom)
    monkeypatch.setattr(egress, "_flat_value_scrub", boom)
    secret_registry.record("failclosed", [SENTINEL])
    r = EngineResult(engine=Engine.GITLEAKS, pillar=Pillar.SECURITY,
                     status=EngineStatus.COMPLETED, scan_id="failclosed",
                     raw={"x": SENTINEL}, error=SENTINEL)
    data = json.loads(r.model_dump_json())
    assert SENTINEL not in json.dumps(data), "leaked on scrub failure — NOT fail-closed"
    assert data["status"] == "failed"
    assert "redaction" in (data["error"] or "").lower()
    assert data["raw"] is None and data["findings"] == []


def test_flat_fallback_succeeds_when_walk_fails(monkeypatch):
    from enrichment import egress

    monkeypatch.setattr(egress, "_walk", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("x")))
    secret_registry.record("fallback", [SENTINEL])
    r = EngineResult(engine=Engine.GITLEAKS, pillar=Pillar.SECURITY,
                     status=EngineStatus.COMPLETED, scan_id="fallback", raw={"x": SENTINEL})
    d = json.loads(r.model_dump_json())
    assert SENTINEL not in json.dumps(d)  # flat value-scrub caught it
    assert d["status"] == "completed"     # genuine second attempt, not withheld


# ── scan_id=None must not silently disable the value scrub ────────────────────
def test_none_scan_id_falls_back_to_all_registry_values():
    secret_registry.record("somescan", [SENTINEL])
    r = EngineResult(engine=Engine.SEMGREP, pillar=Pillar.SECURITY, status=EngineStatus.FAILED,
                     scan_id=None, error=f"tool stderr leaked {SENTINEL}")
    assert SENTINEL not in r.model_dump_json()


# ── a line field emitted as an ARRAY must still be shape-scrubbed ─────────────
def test_array_valued_line_field_is_shape_scrubbed():
    unknown = "UNKNOWNarrayZx7Qw2Ep9Rt4Yu1Io6Pa3Sd8Fg5"  # never held → shape scrub only
    r = EngineResult(engine=Engine.SEMGREP, pillar=Pillar.SECURITY, status=EngineStatus.COMPLETED,
                     scan_id="arr",
                     raw={"results": [{"check_id": "node_secret",
                                       "extra": {"lines": [f'const s = "{unknown}"']}}]})
    assert unknown not in r.model_dump_json()


# ── the log path is a second, deliberate chokepoint ──────────────────────────
def test_log_scrub_processor_is_installed_by_configure():
    import structlog
    from logging_config import _scrub_log_secrets, configure_logging
    configure_logging(level="DEBUG", environment="development")  # what startup does
    procs = structlog.get_config()["processors"]
    assert _scrub_log_secrets in procs, "log-scrub processor not wired — logs bypass redaction"
    # and it sits after format_exc_info so it also scrubs rendered tracebacks
    assert structlog.processors.format_exc_info in procs
    assert procs.index(_scrub_log_secrets) > procs.index(structlog.processors.format_exc_info)


def test_log_processor_scrubs_message_and_traceback():
    from logging_config import _scrub_log_secrets
    secret_registry.record("logscan", [SENTINEL])
    ev = _scrub_log_secrets(None, "info", {
        "event": f"failed on {SENTINEL}",
        "exception": f'Traceback...\n  api_key = "{SENTINEL}"\nValueError',
    })
    assert SENTINEL not in ev["event"]
    assert SENTINEL not in ev["exception"]


def test_stdlib_log_filter_scrubs_record():
    import logging as _logging
    from logging_config import _SecretLogFilter
    secret_registry.record("logscan2", [SENTINEL])
    rec = _logging.LogRecord("x", _logging.INFO, __file__, 1, "leaked %s here",
                             (SENTINEL,), None)
    _SecretLogFilter().filter(rec)
    assert SENTINEL not in (rec.msg % rec.args if rec.args else rec.msg)


# ── readability: only the secret is masked, surrounding code survives ────────
def test_snippet_stays_readable_only_secret_masked():
    from utils import snippet
    out = snippet._redact('DB_PASSWORD = "summer2024"  # set in prod')
    assert "summer2024" not in out
    assert "DB_PASSWORD" in out and "# set in prod" in out


# ── no leak in a logged exception traceback ──────────────────────────────────
def test_no_leak_in_exception_traceback(monkeypatch, caplog):
    import traceback
    from enrichment import enricher, secret_context

    def boom(*_a, **_k):
        raise RuntimeError("classification error")  # message carries NO value

    monkeypatch.setattr(secret_context, "_is_placeholder", boom)
    f = Finding(pillar=Pillar.SECURITY, engine=Engine.GITLEAKS, rule_id="generic-api-key",
                rule_name="x", severity=Severity.CRITICAL, title="x", file_path="c.py",
                metadata={"match": f'api_key = "{SENTINEL}"', "entropy": 5.0})
    with caplog.at_level(logging.DEBUG):
        enricher.enrich_all([f], "")
    assert SENTINEL not in caplog.text
    try:
        raise RuntimeError("x")
    except RuntimeError:
        assert SENTINEL not in traceback.format_exc()
