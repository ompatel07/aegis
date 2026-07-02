"""Gitleaks secrets engine.

Detects committed secrets (API keys, tokens, credentials). Every gitleaks
finding is treated as `critical` — an exposed secret is always a critical issue.

Gitleaks writes its JSON report to a file; we use a temp file inside the system
tmp dir, read it, then delete it.
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

log = get_logger("gitleaks")


async def run(req: ScanRequest, settings: Settings) -> EngineResult:
    if not binary_available(settings.gitleaks_bin):
        return EngineResult.failed(
            Engine.GITLEAKS, Pillar.SECURITY,
            "gitleaks binary not found on PATH", scan_id=req.scan_id,
        )

    report_fd, report_path = tempfile.mkstemp(prefix="gitleaks-", suffix=".json")
    os.close(report_fd)

    try:
        args = [
            settings.gitleaks_bin, "detect",
            "--source", req.path,
            "--no-git",            # scan the working tree, not git history
            "--report-format", "json",
            "--report-path", report_path,
            "--no-banner",
            "--redact",            # redact secret values in the report
            "--exit-code", "0",    # findings are not an error for our purposes
        ]

        result = await run_command(
            args, cwd=req.path, timeout=settings.gitleaks_timeout_seconds,
            allowed_returncodes=(0, 1),
        )

        if result.timed_out:
            return EngineResult.failed(
                Engine.GITLEAKS, Pillar.SECURITY,
                f"gitleaks timed out after {settings.gitleaks_timeout_seconds}s",
                scan_id=req.scan_id, duration_seconds=result.duration_seconds,
            )
        if result.returncode not in (0, 1):
            return EngineResult.failed(
                Engine.GITLEAKS, Pillar.SECURITY,
                normalizer.truncate(result.stderr, 2000) or "gitleaks failed",
                scan_id=req.scan_id, duration_seconds=result.duration_seconds,
            )

        raw_findings = _read_report(report_path)
    finally:
        try:
            os.remove(report_path)
        except OSError:
            pass

    findings = _parse(raw_findings, req.path)
    from enrichment import enricher

    enricher.enrich_all(findings)
    return EngineResult(
        engine=Engine.GITLEAKS,
        pillar=Pillar.SECURITY,
        status=EngineStatus.COMPLETED,
        findings=findings,
        summary=SeveritySummary.from_findings(findings),
        raw={"findings": raw_findings},
        duration_seconds=result.duration_seconds,
        scan_id=req.scan_id,
    )


def _read_report(path: str) -> list[dict]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read().strip()
    except OSError:
        return []
    if not content:
        return []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        log.warning("gitleaks.report_parse_failed")
        return []
    return data if isinstance(data, list) else []


def _parse(raw_findings: list[dict], root: str) -> list[Finding]:
    findings: list[Finding] = []
    for item in raw_findings:
        rule_id = item.get("RuleID", "generic-secret")
        description = item.get("Description") or "Exposed secret detected"
        file_path = item.get("File", "")
        # Gitleaks paths may be absolute or already relative; normalize either way.
        if os.path.isabs(file_path):
            file_path = normalizer.relative_path(file_path, root)

        findings.append(
            Finding(
                pillar=Pillar.SECURITY,
                engine=Engine.GITLEAKS,
                rule_id=rule_id,
                rule_name=normalizer.truncate(description, 500) or rule_id,
                severity=Severity.CRITICAL,  # exposed secrets are always critical
                title=normalizer.truncate(f"Exposed secret: {description}", 1000) or "Exposed secret",
                description=normalizer.truncate(
                    "A potential secret was detected in source. Rotate the credential "
                    "immediately and remove it from version control history.", 8000,
                ),
                file_path=file_path,
                line_start=item.get("StartLine"),
                line_end=item.get("EndLine"),
                column_start=item.get("StartColumn"),
                column_end=item.get("EndColumn"),
                cwe_id="CWE-798",  # Use of Hard-coded Credentials
                owasp_category="A07:2021 - Identification and Authentication Failures",
                fix_suggestion=(
                    "Remove the secret from the codebase, rotate it, and load it from a "
                    "secrets manager or environment variable instead."
                ),
                metadata={
                    "match": normalizer.truncate(item.get("Match"), 500),
                    "entropy": item.get("Entropy"),
                    "tags": item.get("Tags"),
                    "commit": item.get("Commit"),
                },
            )
        )
    findings.sort(key=lambda f: (f.file_path, f.line_start or 0))
    return findings
