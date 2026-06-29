"""Semgrep SAST engine.

Runs Semgrep with OWASP/security base packs plus language-appropriate rule
packs, then normalizes each result into a `Finding`. Semgrep's taint-mode rules
(shipped inside the security packs) provide the cross-file dataflow that catches
SQLi / XSS / SSRF — the SonarQube-competing capability.
"""
from __future__ import annotations

import json

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
from utils import language_detector, normalizer
from utils.sandbox import binary_available, run_command

log = get_logger("semgrep")

# Canonical Semgrep registry packs per language (valid registry shortcuts).
_LANGUAGE_RULESETS: dict[str, list[str]] = {
    "python": ["p/python"],
    "javascript": ["p/javascript"],
    "typescript": ["p/typescript"],
    "java": ["p/java"],
    "go": ["p/golang"],
    "ruby": ["p/ruby"],
    "php": ["p/php"],
    "csharp": ["p/csharp"],
}

# Infrastructure-as-Code packs added when the relevant files are present.
_IAC_RULESETS: dict[str, list[str]] = {
    "docker": ["p/dockerfile"],
    "terraform": ["p/terraform"],
}


def _select_configs(settings: Settings, languages: list[str], project_types: list[str]) -> list[str]:
    """Build the ordered, de-duplicated `--config` list for this scan."""
    configs: list[str] = list(settings.semgrep_base_config_list)
    for lang in languages:
        configs.extend(_LANGUAGE_RULESETS.get(lang, []))
    for ptype in project_types:
        configs.extend(_IAC_RULESETS.get(ptype, []))
    # Preserve order while removing duplicates.
    seen: set[str] = set()
    ordered: list[str] = []
    for c in configs:
        if c not in seen:
            seen.add(c)
            ordered.append(c)
    return ordered


async def run(req: ScanRequest, settings: Settings) -> EngineResult:
    """Execute Semgrep against `req.path` and return normalized findings."""
    if not binary_available(settings.semgrep_bin):
        return EngineResult.failed(
            Engine.SEMGREP, Pillar.SECURITY,
            "semgrep binary not found on PATH", scan_id=req.scan_id,
        )

    # Resolve languages/types: trust caller-provided values, else detect.
    languages = req.languages
    project_types = req.project_types
    if languages is None or project_types is None:
        detection = language_detector.detect(req.path)
        languages = languages or detection.languages
        project_types = project_types or detection.project_types

    configs = _select_configs(settings, languages, project_types)

    args = [settings.semgrep_bin, "scan", "--json", "--quiet", "--metrics", "off",
            "--disable-version-check", "--timeout", "60", "--max-target-bytes", "2000000"]
    for cfg in configs:
        args += ["--config", cfg]
    args.append(req.path)

    # Semgrep exits 0 (no findings) or 1 (findings present); >=2 is an error.
    result = await run_command(
        args, cwd=req.path, timeout=settings.semgrep_timeout_seconds,
        allowed_returncodes=(0, 1),
        env={"SEMGREP_RULES_CACHE_DIR": settings.semgrep_rules_cache},
    )

    if result.timed_out:
        return EngineResult.failed(
            Engine.SEMGREP, Pillar.SECURITY,
            f"semgrep timed out after {settings.semgrep_timeout_seconds}s",
            scan_id=req.scan_id, duration_seconds=result.duration_seconds,
        )

    if result.returncode not in (0, 1):
        return EngineResult.failed(
            Engine.SEMGREP, Pillar.SECURITY,
            normalizer.truncate(result.stderr, 2000) or "semgrep failed",
            scan_id=req.scan_id, duration_seconds=result.duration_seconds,
        )

    try:
        raw = json.loads(result.stdout) if result.stdout.strip() else {"results": []}
    except json.JSONDecodeError as exc:
        return EngineResult.failed(
            Engine.SEMGREP, Pillar.SECURITY,
            f"could not parse semgrep output: {exc}",
            scan_id=req.scan_id, duration_seconds=result.duration_seconds,
        )

    findings = _parse(raw, req.path)
    return EngineResult(
        engine=Engine.SEMGREP,
        pillar=Pillar.SECURITY,
        status=EngineStatus.COMPLETED,
        findings=findings,
        summary=SeveritySummary.from_findings(findings),
        raw=raw,
        duration_seconds=result.duration_seconds,
        scan_id=req.scan_id,
    )


def _parse(raw: dict, root: str) -> list[Finding]:
    findings: list[Finding] = []
    for item in raw.get("results", []):
        extra = item.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        start = item.get("start", {}) or {}
        end = item.get("end", {}) or {}

        check_id = item.get("check_id", "unknown-rule")
        rule_short = check_id.rsplit(".", 1)[-1]
        message = extra.get("message") or rule_short

        severity = normalizer.normalize_semgrep_severity(extra.get("severity", ""), metadata)

        findings.append(
            Finding(
                pillar=Pillar.SECURITY,
                engine=Engine.SEMGREP,
                rule_id=check_id,
                rule_name=normalizer.truncate(rule_short, 500) or rule_short,
                severity=severity,
                title=normalizer.truncate(message.splitlines()[0], 1000) or rule_short,
                description=normalizer.truncate(message, 8000),
                file_path=normalizer.relative_path(item.get("path", ""), root),
                line_start=start.get("line"),
                line_end=end.get("line"),
                column_start=start.get("col"),
                column_end=end.get("col"),
                cwe_id=normalizer.extract_cwe(metadata),
                owasp_category=normalizer.extract_owasp(metadata),
                fix_suggestion=normalizer.truncate(extra.get("fix"), 8000),
                metadata={
                    "confidence": metadata.get("confidence"),
                    "references": metadata.get("references"),
                    "category": metadata.get("category"),
                    "technology": metadata.get("technology"),
                    "lines": normalizer.truncate(extra.get("lines"), 2000),
                },
            )
        )
    # Most severe first for a stable, useful ordering.
    findings.sort(key=lambda f: (_severity_rank(f.severity), f.file_path, f.line_start or 0))
    return findings


def _severity_rank(sev: Severity) -> int:
    from models.scan_result import SEVERITY_ORDER

    return SEVERITY_ORDER[sev]
