"""Ruff engine — a type-aware Python bug source for the quality pillar (Q3).

Ruff (astral-sh/ruff) is a single static Rust binary. It needs no Python
environment and no installed dependencies, so it gives us real semantic analysis
(scope resolution, control-flow) WITHOUT ever installing or executing customer
code — the property that made it the right answer to the six Q2 rules that failed
purely because Semgrep OSS has no type inference.

Boundaries enforced here:
  * `--isolated` — ignore the customer's pyproject.toml / ruff.toml so their
    config can neither silence our findings nor enable rules we did not audit.
  * `--select <explicit codes>` — ONLY the hand-picked allowlist in
    rules/quality/ruff_map.yaml. Never a whole category.
  * `--no-cache` — byte-identical repeat scans (Hardening Pass 1 determinism).

Findings are first-class quality-pillar findings: pillar=quality, engine=ruff,
issue_type from the map. They are returned raw (rule id, severity, file, line);
the quality engine merges them into its result and the shared enrichment pass
gives them ownership tagging, inline snippet, the content-based lifecycle
fingerprint and FP scoring — exactly like every other finding.
"""
from __future__ import annotations

import json
import os

from config import Settings
from logging_config import get_logger
from models.scan_request import ScanRequest
from models.scan_result import Engine, Finding, Pillar, Severity
from utils import normalizer
from utils.sandbox import binary_available, run_command

log = get_logger("ruff")

_MAP_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "rules", "quality", "ruff_map.yaml")

_SEVERITY = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
    "low": Severity.LOW, "info": Severity.INFO,
}

# Dependency / vendored / generated dirs to keep out of the scan. `--isolated`
# disables ruff's default excludes (it scanned a stray `.venv/site-packages` in
# testing), so we pass them explicitly — otherwise we'd flag third-party code and
# fabricate findings the customer can't fix.
_EXCLUDE_DIRS = (
    ".venv,venv,env,.env,virtualenv,site-packages,node_modules,vendor,vendored,"
    "third_party,third-party,.git,__pycache__,.tox,.nox,.mypy_cache,.pytest_cache,"
    ".ruff_cache,build,dist,.eggs,migrations,.next,_next,.svelte-kit"
)

_map_cache: dict[str, dict] | None = None


def _load_map() -> dict[str, dict]:
    """{ruff_code: {aegis_rule_id, issue_type, severity}} from the allowlist."""
    global _map_cache
    if _map_cache is None:
        try:
            import yaml

            with open(_MAP_PATH, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
            _map_cache = {str(k): v for k, v in (doc.get("rules") or {}).items()}
        except Exception as exc:  # noqa: BLE001 — a missing map must not break scans
            log.warning("ruff.map_load_failed", error=str(exc))
            _map_cache = {}
    return _map_cache


def allowlisted_codes() -> list[str]:
    return sorted(_load_map().keys())


def bug_rule_ids() -> set[str]:
    """aegis_rule_ids of allowlisted ruff rules typed as bugs (for enricher)."""
    return {
        str(v["aegis_rule_id"])
        for v in _load_map().values()
        if v.get("issue_type") == "bug" and v.get("aegis_rule_id")
    }


async def collect(req: ScanRequest, settings: Settings) -> tuple[list[Finding], dict]:
    """Run Ruff over the repo and return (findings, raw). Best-effort: if the
    binary is missing or Ruff errors, returns ([], {...}) so the quality scan is
    never lost."""
    rule_map = _load_map()
    if not rule_map or not binary_available(settings.ruff_bin):
        return [], {"skipped": "ruff unavailable" if rule_map else "empty allowlist"}

    select = ",".join(sorted(rule_map.keys()))
    args = [
        settings.ruff_bin, "check",
        "--output-format=json",
        "--no-cache",     # determinism: no cache variance between repeat scans
        "--isolated",     # ignore customer pyproject.toml / ruff.toml entirely
        "--exclude", _EXCLUDE_DIRS,  # never scan deps/vendored/generated code
        "--select", select,
        "--exit-zero",    # findings are not a process error for us
        req.path,
    ]
    result = await run_command(args, cwd=req.path, timeout=settings.ruff_timeout_seconds,
                               allowed_returncodes=(0, 1))
    if result.timed_out:
        log.warning("ruff.timeout", seconds=settings.ruff_timeout_seconds)
        return [], {"error": "ruff timed out"}
    if result.returncode not in (0, 1):
        log.warning("ruff.failed", rc=result.returncode,
                    stderr=normalizer.truncate(result.stderr, 1000))
        return [], {"error": normalizer.truncate(result.stderr, 1000)}

    try:
        raw = json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError as exc:
        log.warning("ruff.parse_failed", error=str(exc))
        return [], {"error": f"could not parse ruff output: {exc}"}

    findings = _parse(raw, req.path, rule_map)
    return findings, {"codes_selected": select, "findings": len(findings)}


def _parse(raw: list[dict], root: str, rule_map: dict[str, dict]) -> list[Finding]:
    out: list[Finding] = []
    for item in raw:
        code = item.get("code")
        entry = rule_map.get(code)
        if not entry:  # defensive: ruff only returns selected codes, but be strict
            continue
        loc = item.get("location", {}) or {}
        end = item.get("end_location", {}) or {}
        path = item.get("filename", "") or ""
        rel = normalizer.relative_path(path, root) if path else ""
        severity = _SEVERITY.get(str(entry.get("severity", "medium")).lower(), Severity.MEDIUM)
        rule_id = str(entry["aegis_rule_id"])
        msg = normalizer.truncate(item.get("message", "") or code, 1000)
        out.append(
            Finding(
                pillar=Pillar.QUALITY,
                engine=Engine.RUFF,
                rule_id=rule_id,
                rule_name=code,  # keep the raw ruff code visible for auditability
                severity=severity,
                title=f"{msg} ({code})" if msg else code,
                description=item.get("message", "") or code,
                file_path=rel,
                line_start=loc.get("row"),
                line_end=end.get("row") or loc.get("row"),
                column_start=loc.get("column"),
                column_end=end.get("column"),
                # issue_type is set by the enricher from _QUALITY_BUG_RULES, which
                # is loaded from this same map — single source of truth.
                metadata={"ruff_code": code, "ruleset": "ruff",
                          "url": (item.get("url") or None)},
            )
        )
    # Deterministic order (file, line, col, code) so repeat scans are byte-stable.
    out.sort(key=lambda f: (f.file_path or "", f.line_start or 0,
                            f.column_start or 0, f.rule_id))
    return out
