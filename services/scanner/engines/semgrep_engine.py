"""Semgrep SAST engine.

Runs Semgrep with OWASP/security base packs, language-appropriate rule packs,
and Aegis's own custom taint-mode rulesets, then normalizes each result into a
`Finding`. The custom rules (rules/taint/*.yaml) add cross-file dataflow
detection for SQLi / XSS / command injection / SSRF / path traversal / NoSQL /
LDAP injection across Python, JS/TS, Go and Java — the SonarQube/Snyk-competing
capability. Each ships with positive + sanitized-negative tests (`semgrep
--test`) so false positives are caught before release.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import shutil
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
from utils import language_detector, normalizer
from utils.sandbox import binary_available, run_command

log = get_logger("semgrep")

# Canonical Semgrep registry packs per language (valid registry shortcuts).
_LANGUAGE_RULESETS: dict[str, list[str]] = {
    # p/nodejsscan adds ~150 Node-specific security rules on top of p/javascript.
    "python": ["p/python"],
    "javascript": ["p/javascript", "p/nodejsscan"],
    "typescript": ["p/typescript", "p/nodejsscan"],
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

# Absolute path to Aegis's bundled custom taint rulesets. Shipped in the image
# at /app/rules/taint (COPY . .); also resolves correctly when run from a local
# checkout. Passed as an extra --config alongside the registry packs.
_CUSTOM_RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "taint"
)


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


def _write_project_rules(rules: list[str] | None) -> str | None:
    """Write per-project custom rule YAML docs to a temp dir for this scan."""
    if not rules:
        return None
    try:
        d = tempfile.mkdtemp(prefix="aegis-project-rules-")
        for i, doc in enumerate(rules):
            with open(os.path.join(d, f"rule_{i}.yaml"), "w", encoding="utf-8") as fh:
                fh.write(doc)
        return d
    except OSError as exc:  # noqa: BLE001
        log.warning("semgrep.project_rules_write_failed", error=str(exc))
        return None


def _rule_pack_version(configs: list[str], custom_rules: list[str] | None) -> str:
    """A reproducible id for the rule set used: date + hash of the config set.
    Recorded on the scan so re-scans can surface rule-pack changes."""
    h = hashlib.sha256()
    for c in sorted(configs):
        h.update(c.encode())
    for r in custom_rules or []:
        h.update(r.encode())
    date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d")
    return f"rp-{date}-{h.hexdigest()[:10]}"


def _custom_rules_dir() -> str | None:
    """Return the custom rules dir if it exists and is non-empty, else None."""
    try:
        if os.path.isdir(_CUSTOM_RULES_DIR) and any(
            name.endswith((".yaml", ".yml")) for name in os.listdir(_CUSTOM_RULES_DIR)
        ):
            return _CUSTOM_RULES_DIR
    except OSError as exc:  # pragma: no cover — defensive
        log.warning("semgrep.custom_rules_stat_failed", path=_CUSTOM_RULES_DIR, error=str(exc))
    return None


def _build_args(settings: Settings, configs: list[str], path: str) -> list[str]:
    """Assemble the semgrep CLI invocation for the given config list."""
    args = [settings.semgrep_bin, "scan", "--json", "--quiet", "--metrics", "off",
            "--disable-version-check", "--timeout", "60", "--max-target-bytes", "2000000"]
    for cfg in configs:
        args += ["--config", cfg]
    args.append(path)
    return args


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

    registry_configs = _select_configs(settings, languages, project_types)
    custom_dir = _custom_rules_dir()

    # Per-project custom rules (already validated at upload) live for the duration
    # of this scan in a temp dir added on top of the registry + Aegis packs.
    project_rules_dir = _write_project_rules(req.custom_rules)
    if project_rules_dir:
        registry_configs = registry_configs + [project_rules_dir]

    configs = registry_configs + ([custom_dir] if custom_dir else [])
    rule_pack_version = _rule_pack_version(configs, req.custom_rules)

    async def _semgrep(cfgs: list[str]):
        # Semgrep exits 0 (no findings) or 1 (findings present); >=2 is an error.
        return await run_command(
            _build_args(settings, cfgs, req.path),
            cwd=req.path, timeout=settings.semgrep_timeout_seconds,
            allowed_returncodes=(0, 1),
            env={"SEMGREP_RULES_CACHE_DIR": settings.semgrep_rules_cache},
        )

    result = await _semgrep(configs)

    # A hard error (rc >= 2) after including the custom rulesets must not lose the
    # entire SAST run. Log it and retry with the registry packs only: a broken
    # custom rule degrades to registry coverage rather than dropping all findings.
    # A genuine semgrep failure then still surfaces below (as a degraded engine).
    custom_applied = custom_dir is not None
    if custom_applied and not result.timed_out and result.returncode not in (0, 1):
        log.warning(
            "semgrep.custom_rules_failed_retrying",
            error=normalizer.truncate(result.stderr, 1000),
        )
        custom_applied = False
        result = await _semgrep(registry_configs)

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

    if project_rules_dir:
        shutil.rmtree(project_rules_dir, ignore_errors=True)

    findings = _parse(raw, req.path)
    from enrichment import enricher

    enricher.enrich_all(findings)
    custom_count = sum(1 for f in findings if f.rule_id.startswith("aegis-"))
    log.info(
        "semgrep.completed",
        findings=len(findings),
        custom_findings=custom_count,
        custom_rules_applied=custom_applied,
        project_rules=len(req.custom_rules or []),
        rule_pack_version=rule_pack_version,
        errors=len(raw.get("errors", []) or []),
    )
    return EngineResult(
        engine=Engine.SEMGREP,
        pillar=Pillar.SECURITY,
        status=EngineStatus.COMPLETED,
        findings=findings,
        summary=SeveritySummary.from_findings(findings),
        raw=raw,
        duration_seconds=result.duration_seconds,
        scan_id=req.scan_id,
        rule_pack_version=rule_pack_version,
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
        # Rules loaded from a local dir are namespaced by semgrep with a
        # path-derived prefix (e.g. "rules.taint.aegis-js-xss" for our bundled
        # packs, or "tmp.aegis-project-rules-XXXX.rule" for per-project rules).
        # Normalize both to their stable rule id; keep registry ids canonical.
        is_project = "aegis-project-rules-" in check_id
        is_aegis = rule_short.startswith("aegis-")
        rule_id = rule_short if (is_project or is_aegis) else check_id
        ruleset = "project-custom" if is_project else ("aegis-custom" if is_aegis else "registry")

        severity = normalizer.normalize_semgrep_severity(extra.get("severity", ""), metadata)

        findings.append(
            Finding(
                pillar=Pillar.SECURITY,
                engine=Engine.SEMGREP,
                rule_id=rule_id,
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
                    "ruleset": ruleset,
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
