"""Joern deep-scan engine (bundled default).

Joern (Apache-2.0, joernio/joern) builds a Code Property Graph and runs
interprocedural taint queries — the cross-file dataflow that OSS Semgrep can't
do. Unlike CodeQL it is free to redistribute, so it is the *bundled* deep-scan
engine; it shares the `/scan/deep` interface with the CodeQL slot.

Pipeline: `joern-parse <src>` builds a CPG, then a Scala taint script
(engines/joern/taint.sc) queries it for SQLi / XSS / command injection / SSRF /
path traversal and writes JSON, which `_parse_output` (unit-tested against canned
output) normalizes into Findings with their dataflow paths preserved.

CPG construction is memory-hungry, so deep scans are skipped (not failed) for
repositories above `deep_scan_max_repo_mb`.
"""
from __future__ import annotations

import json
import os
import tempfile

from config import Settings
from logging_config import get_logger
from models.scan_request import ScanRequest
from models.scan_result import (
    Engine,
    EngineResult,
    EngineStatus,
    Finding,
    Pillar,
    Severity,
    SeveritySummary,
)
from utils import normalizer
from utils.sandbox import binary_available, run_command

log = get_logger("joern")

_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "joern", "taint.sc")

# Vuln-class -> (CWE, OWASP, default severity). The Scala script tags each flow
# with a vulnClass; this is the authoritative classification/back-fill.
_VULN_META: dict[str, tuple[str, str, Severity]] = {
    "sql-injection": ("CWE-89", "A03:2021 - Injection", Severity.CRITICAL),
    "command-injection": ("CWE-78", "A03:2021 - Injection", Severity.CRITICAL),
    "xss": ("CWE-79", "A03:2021 - Injection", Severity.HIGH),
    "ssrf": ("CWE-918", "A10:2021 - Server-Side Request Forgery (SSRF)", Severity.HIGH),
    "path-traversal": ("CWE-22", "A01:2021 - Broken Access Control", Severity.HIGH),
}

_SEVERITY_BY_NAME = {s.value: s for s in Severity}


def _skipped(scan_id: str | None, message: str, duration: float = 0.0) -> EngineResult:
    return EngineResult(
        engine=Engine.JOERN, pillar=Pillar.SECURITY, status=EngineStatus.SKIPPED,
        findings=[], summary=SeveritySummary(), error=message,
        scan_id=scan_id, duration_seconds=duration,
    )


async def run(req: ScanRequest, settings: Settings) -> EngineResult:
    if not binary_available(settings.joern_parse_bin) or not binary_available(settings.joern_bin):
        log.info("joern.unavailable", scan_id=req.scan_id)
        return _skipped(req.scan_id, "Joern CLI not installed on this scanner image")

    limit_mb = settings.deep_scan_max_repo_mb
    if _exceeds_size(req.path, limit_mb):
        msg = f"repository exceeds deep-scan size limit of {limit_mb}MB; Joern deep scan skipped"
        log.info("joern.repo_too_large", scan_id=req.scan_id, limit_mb=limit_mb)
        return _skipped(req.scan_id, msg)

    duration = 0.0
    with tempfile.TemporaryDirectory(prefix="aegis-joern-") as workdir:
        cpg = os.path.join(workdir, "cpg.bin")
        out = os.path.join(workdir, "findings.json")

        parse = await run_command(
            [settings.joern_parse_bin, req.path, "--output", cpg],
            cwd=req.path, timeout=settings.deep_scan_timeout_seconds,
        )
        duration += parse.duration_seconds
        if parse.timed_out or not parse.ok:
            log.warning("joern.parse_failed", error=normalizer.truncate(parse.stderr, 500))
            return _skipped(req.scan_id, "Joern CPG construction failed", duration)

        analyze = await run_command(
            [settings.joern_bin, "--script", _SCRIPT,
             "--param", f"cpgFile={cpg}", "--param", f"outFile={out}"],
            cwd=workdir, timeout=settings.deep_scan_timeout_seconds,
        )
        duration += analyze.duration_seconds
        if analyze.timed_out or not analyze.ok:
            log.warning("joern.script_failed", error=normalizer.truncate(analyze.stderr, 500))
            return _skipped(req.scan_id, "Joern taint query failed", duration)

        try:
            with open(out, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("joern.output_read_failed", error=str(exc))
            return _skipped(req.scan_id, "Joern produced no readable output", duration)

    findings = _parse_output(data, req.path)
    log.info("joern.completed", scan_id=req.scan_id, findings=len(findings))
    return EngineResult(
        engine=Engine.JOERN, pillar=Pillar.SECURITY, status=EngineStatus.COMPLETED,
        findings=findings, summary=SeveritySummary.from_findings(findings),
        raw={"finding_count": len(findings)}, duration_seconds=duration, scan_id=req.scan_id,
    )


# ── Output parsing (independently unit-tested) ────────────────────────────────
def _parse_output(data: dict, root: str) -> list[Finding]:
    findings: list[Finding] = []
    for item in data.get("findings", []) or []:
        vuln_class = (item.get("vulnClass") or "").lower()
        cwe_default, owasp, sev_default = _VULN_META.get(
            vuln_class, (item.get("cwe"), None, Severity.HIGH)
        )
        severity = _SEVERITY_BY_NAME.get((item.get("severity") or "").lower(), sev_default)
        cwe = item.get("cwe") or cwe_default

        flow = _normalize_flow(item.get("flow", []) or [], root)
        name = item.get("name") or vuln_class or "taint flow"
        message = item.get("message") or f"Untrusted data reaches a {name} sink"

        findings.append(
            Finding(
                pillar=Pillar.SECURITY,
                engine=Engine.JOERN,
                rule_id=f"joern/{vuln_class or 'taint'}",
                rule_name=normalizer.truncate(name, 500) or "taint flow",
                severity=severity,
                title=normalizer.truncate(message.splitlines()[0], 1000) or name,
                description=normalizer.truncate(message, 8000),
                file_path=normalizer.to_repo_relative(item.get("file", ""), root),
                line_start=item.get("lineStart"),
                line_end=item.get("lineEnd", item.get("lineStart")),
                cwe_id=cwe,
                owasp_category=owasp,
                metadata={
                    "deep_scan": True,
                    "engine_detail": "joern",
                    "vuln_class": vuln_class,
                    "method": item.get("method"),
                    # Interprocedural taint path source -> sink.
                    "dataflow": flow,
                    "dataflow_steps": len(flow),
                },
            )
        )
    findings.sort(key=lambda f: (_sev_rank(f.severity), f.file_path, f.line_start or 0))
    return findings


def _normalize_flow(flow: list[dict], root: str) -> list[dict]:
    steps: list[dict] = []
    for step in flow:
        steps.append({
            "file": normalizer.to_repo_relative(step.get("file", ""), root),
            "line": step.get("line"),
            "message": normalizer.truncate(step.get("code") or step.get("message"), 500),
        })
    return steps


def _exceeds_size(path: str, limit_mb: int) -> bool:
    """Return True as soon as the tree exceeds limit_mb (early-exit walk)."""
    limit_bytes = limit_mb * 1024 * 1024
    total = 0
    for dirpath, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(dirpath, name))
            except OSError:
                continue
            if total > limit_bytes:
                return True
    return False


def _sev_rank(sev: Severity) -> int:
    from models.scan_result import SEVERITY_ORDER

    return SEVERITY_ORDER[sev]
