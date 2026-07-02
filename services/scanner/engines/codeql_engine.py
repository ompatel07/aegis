"""CodeQL deep-scan engine (opt-in slot).

CodeQL performs interprocedural, cross-file dataflow analysis — the capability
OSS Semgrep taint mode lacks. It is wired here behind the same interface as the
Joern engine, but the CodeQL CLI is intentionally NOT bundled: GitHub's CodeQL
terms do not permit redistributing it inside a commercial analysis product.
When the CLI is absent (the default), this engine returns a structured SKIPPED
result — the scan is not failed — so a customer who has their own CodeQL license
can drop the CLI in and enable it. Joern is the bundled default.

Regardless of whether the CLI runs, `_parse_sarif` (SARIF 2.1.0) is fully
implemented and unit-tested against canned CodeQL output, including CWE mapping,
security-severity, and CodeQL's dataflow paths (SARIF codeFlows).
"""
from __future__ import annotations

import json
import os
import re
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

log = get_logger("codeql")

# Our detected language -> CodeQL DB language.
_CODEQL_LANGS: dict[str, str] = {
    "javascript": "javascript", "typescript": "javascript",
    "python": "python", "go": "go", "java": "java", "kotlin": "java",
    "csharp": "csharp", "ruby": "ruby", "cpp": "cpp", "c": "cpp",
}

_CWE_RE = re.compile(r"cwe[-/](\d+)", re.IGNORECASE)

_UNAVAILABLE_MSG = (
    "CodeQL CLI not installed. CodeQL deep scanning is opt-in and requires a "
    "customer-provided CodeQL license — GitHub's terms do not permit bundling the "
    "CodeQL CLI in a commercial product. Joern is the bundled default deep-scan engine."
)


def _skipped(scan_id: str | None, message: str, duration: float = 0.0) -> EngineResult:
    return EngineResult(
        engine=Engine.CODEQL, pillar=Pillar.SECURITY, status=EngineStatus.SKIPPED,
        findings=[], summary=SeveritySummary(), error=message,
        scan_id=scan_id, duration_seconds=duration,
    )


async def run(req: ScanRequest, settings: Settings) -> EngineResult:
    if not binary_available(settings.codeql_bin):
        log.info("codeql.unavailable", scan_id=req.scan_id)
        return _skipped(req.scan_id, _UNAVAILABLE_MSG)

    languages = req.languages or []
    targets = _dedupe(_CODEQL_LANGS[lang] for lang in languages if lang in _CODEQL_LANGS)
    if not targets:
        return _skipped(req.scan_id, "no CodeQL-supported language detected in project")

    findings: list[Finding] = []
    total_duration = 0.0
    analyzed: list[str] = []
    with tempfile.TemporaryDirectory(prefix="aegis-codeql-") as workdir:
        for lang in targets:
            sarif, dur = await _analyze_language(req, settings, lang, workdir)
            total_duration += dur
            if sarif is not None:
                findings.extend(_parse_sarif(sarif, req.path))
                analyzed.append(lang)

    if not analyzed:
        return _skipped(req.scan_id, "CodeQL database creation/analysis produced no output", total_duration)

    from enrichment import enricher

    enricher.enrich_all(findings)
    log.info("codeql.completed", scan_id=req.scan_id, findings=len(findings), languages=analyzed)
    return EngineResult(
        engine=Engine.CODEQL, pillar=Pillar.SECURITY, status=EngineStatus.COMPLETED,
        findings=findings, summary=SeveritySummary.from_findings(findings),
        raw={"languages": analyzed}, duration_seconds=total_duration, scan_id=req.scan_id,
    )


async def _analyze_language(
    req: ScanRequest, settings: Settings, lang: str, workdir: str
) -> tuple[dict | None, float]:
    """Create a CodeQL DB for one language and analyze it with security-extended."""
    db = os.path.join(workdir, f"db-{lang}")
    sarif_path = os.path.join(workdir, f"{lang}.sarif")
    duration = 0.0

    create = await run_command(
        [settings.codeql_bin, "database", "create", db, f"--language={lang}",
         f"--source-root={req.path}", "--overwrite"],
        cwd=req.path, timeout=settings.deep_scan_timeout_seconds,
    )
    duration += create.duration_seconds
    if create.timed_out or not create.ok:
        log.warning("codeql.db_create_failed", lang=lang,
                    error=normalizer.truncate(create.stderr, 500))
        return None, duration

    suite = f"codeql/{lang}-queries:codeql-suites/{lang}-security-extended.qls"
    analyze = await run_command(
        [settings.codeql_bin, "database", "analyze", db, suite,
         "--format=sarif-latest", f"--output={sarif_path}", "--no-download"],
        cwd=req.path, timeout=settings.deep_scan_timeout_seconds,
    )
    duration += analyze.duration_seconds
    if analyze.timed_out or not analyze.ok:
        log.warning("codeql.analyze_failed", lang=lang,
                    error=normalizer.truncate(analyze.stderr, 500))
        return None, duration

    try:
        with open(sarif_path, encoding="utf-8") as fh:
            return json.load(fh), duration
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("codeql.sarif_read_failed", lang=lang, error=str(exc))
        return None, duration


# ── SARIF 2.1.0 parsing (independently unit-tested) ───────────────────────────
def _parse_sarif(sarif: dict, root: str) -> list[Finding]:
    findings: list[Finding] = []
    for run_obj in sarif.get("runs", []) or []:
        rules = _index_rules(run_obj)
        for result in run_obj.get("results", []) or []:
            finding = _result_to_finding(result, rules, root)
            if finding is not None:
                findings.append(finding)
    findings.sort(key=lambda f: (_sev_rank(f.severity), f.file_path, f.line_start or 0))
    return findings


def _index_rules(run_obj: dict) -> dict[str, dict]:
    driver = (run_obj.get("tool", {}) or {}).get("driver", {}) or {}
    rules: dict[str, dict] = {}
    for rule in driver.get("rules", []) or []:
        rid = rule.get("id")
        if rid:
            rules[rid] = rule
    return rules


def _result_to_finding(result: dict, rules: dict[str, dict], root: str) -> Finding | None:
    rule_id = result.get("ruleId") or (result.get("rule", {}) or {}).get("id") or "codeql-rule"
    rule = rules.get(rule_id, {})
    props = rule.get("properties", {}) or {}

    loc = _primary_location(result)
    if loc is None:
        return None
    file_path, region = loc

    message = ((result.get("message", {}) or {}).get("text")) or _rule_desc(rule) or rule_id
    severity = _severity(result, props)
    cwe = _extract_cwe(props)
    dataflow = _dataflow(result, root)

    return Finding(
        pillar=Pillar.SECURITY,
        engine=Engine.CODEQL,
        rule_id=rule_id,
        rule_name=normalizer.truncate((rule.get("name") or rule_id), 500) or rule_id,
        severity=severity,
        title=normalizer.truncate(message.splitlines()[0], 1000) or rule_id,
        description=normalizer.truncate(message, 8000),
        file_path=normalizer.to_repo_relative(file_path, root),
        line_start=region.get("startLine"),
        line_end=region.get("endLine", region.get("startLine")),
        column_start=region.get("startColumn"),
        column_end=region.get("endColumn"),
        cwe_id=cwe,
        owasp_category=None,
        fix_suggestion=None,
        metadata={
            "deep_scan": True,
            "engine_detail": "codeql",
            "security_severity": props.get("security-severity"),
            "tags": props.get("tags"),
            # CodeQL's interprocedural dataflow path — the premium signal.
            "dataflow": dataflow,
            "dataflow_steps": len(dataflow),
        },
    )


def _primary_location(result: dict) -> tuple[str, dict] | None:
    for location in result.get("locations", []) or []:
        phys = (location.get("physicalLocation", {}) or {})
        uri = (phys.get("artifactLocation", {}) or {}).get("uri")
        if uri:
            return uri, (phys.get("region", {}) or {})
    return None


def _dataflow(result: dict, root: str) -> list[dict]:
    """Flatten SARIF codeFlows into an ordered list of taint-path steps."""
    steps: list[dict] = []
    for code_flow in result.get("codeFlows", []) or []:
        for thread_flow in code_flow.get("threadFlows", []) or []:
            for tfl in thread_flow.get("locations", []) or []:
                loc = (tfl.get("location", {}) or {})
                phys = (loc.get("physicalLocation", {}) or {})
                uri = (phys.get("artifactLocation", {}) or {}).get("uri")
                if not uri:
                    continue
                region = phys.get("region", {}) or {}
                steps.append({
                    "file": normalizer.to_repo_relative(uri, root),
                    "line": region.get("startLine"),
                    "message": normalizer.truncate((loc.get("message", {}) or {}).get("text"), 500),
                })
        if steps:
            break  # first code flow is representative
    return steps


def _severity(result: dict, props: dict) -> Severity:
    score = props.get("security-severity")
    if score is not None:
        try:
            return normalizer.cvss_to_severity(float(score))
        except (TypeError, ValueError):
            pass
    level = (result.get("level") or "").lower()
    return {"error": Severity.HIGH, "warning": Severity.MEDIUM, "note": Severity.LOW}.get(
        level, Severity.MEDIUM
    )


def _extract_cwe(props: dict) -> str | None:
    for tag in props.get("tags", []) or []:
        m = _CWE_RE.search(str(tag))
        if m:
            return f"CWE-{int(m.group(1))}"
    return None


def _rule_desc(rule: dict) -> str | None:
    for key in ("fullDescription", "shortDescription"):
        text = (rule.get(key, {}) or {}).get("text")
        if text:
            return text
    return None


def _dedupe(items) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


def _sev_rank(sev: Severity) -> int:
    from models.scan_result import SEVERITY_ORDER

    return SEVERITY_ORDER[sev]
