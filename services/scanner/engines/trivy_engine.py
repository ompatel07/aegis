"""Trivy SCA + IaC engine.

Scans the filesystem for dependency vulnerabilities (CVE) and Infrastructure-as-
Code misconfigurations (Dockerfile, Terraform, k8s). Secrets are intentionally
left to the Gitleaks engine so we don't double-count the same finding.

CVSS → severity mapping: >=9.0 critical, >=7.0 high, >=4.0 medium, else low.
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
    SeveritySummary,
)
from utils import normalizer
from utils.sandbox import binary_available, run_with_retry

log = get_logger("trivy")


async def run(req: ScanRequest, settings: Settings) -> EngineResult:
    if not binary_available(settings.trivy_bin):
        return EngineResult.failed(
            Engine.TRIVY, Pillar.SECURITY,
            "trivy binary not found on PATH", scan_id=req.scan_id,
        )

    args = [
        settings.trivy_bin, "fs",
        "--format", "json",
        "--scanners", "vuln,misconfig",
        "--quiet",
        "--no-progress",
        "--cache-dir", settings.trivy_cache_dir,
        req.path,
    ]

    # Trivy may refresh its vuln DB over the network on first run — retry that.
    result = await run_with_retry(
        args, cwd=req.path, timeout=settings.trivy_timeout_seconds,
        allowed_returncodes=(0,), retries=2, base_delay=2.0,
    )

    if result.timed_out:
        return EngineResult.failed(
            Engine.TRIVY, Pillar.SECURITY,
            f"trivy timed out after {settings.trivy_timeout_seconds}s",
            scan_id=req.scan_id, duration_seconds=result.duration_seconds,
        )
    if not result.ok:
        return EngineResult.failed(
            Engine.TRIVY, Pillar.SECURITY,
            normalizer.truncate(result.stderr, 2000) or "trivy failed",
            scan_id=req.scan_id, duration_seconds=result.duration_seconds,
        )

    try:
        raw = json.loads(result.stdout) if result.stdout.strip() else {"Results": []}
    except json.JSONDecodeError as exc:
        return EngineResult.failed(
            Engine.TRIVY, Pillar.SECURITY,
            f"could not parse trivy output: {exc}",
            scan_id=req.scan_id, duration_seconds=result.duration_seconds,
        )

    findings = _parse(raw, req.path)
    return EngineResult(
        engine=Engine.TRIVY,
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
    for res in raw.get("Results", []) or []:
        target = res.get("Target", "")
        findings.extend(_parse_vulnerabilities(res, target))
        findings.extend(_parse_misconfigurations(res, target))
    findings.sort(key=lambda f: (_rank(f), f.file_path))
    return findings


def _parse_vulnerabilities(res: dict, target: str) -> list[Finding]:
    out: list[Finding] = []
    for vuln in res.get("Vulnerabilities", []) or []:
        score = _best_cvss(vuln.get("CVSS", {}))
        severity = normalizer.cvss_to_severity(score, vuln.get("Severity"))
        pkg = vuln.get("PkgName", "")
        installed = vuln.get("InstalledVersion", "")
        fixed = vuln.get("FixedVersion")
        cwe_list = vuln.get("CweIDs") or []

        fix = (
            f"Upgrade {pkg} from {installed} to {fixed} or later."
            if fixed else f"No fixed version published yet for {pkg} {installed}."
        )

        out.append(
            Finding(
                pillar=Pillar.SECURITY,
                engine=Engine.TRIVY,
                rule_id=vuln.get("VulnerabilityID", "UNKNOWN-CVE"),
                rule_name=normalizer.truncate(f"{pkg} {installed}", 500) or pkg,
                severity=severity,
                title=normalizer.truncate(
                    vuln.get("Title") or f"{vuln.get('VulnerabilityID')} in {pkg}", 1000
                ) or pkg,
                description=normalizer.truncate(vuln.get("Description"), 8000),
                file_path=target or pkg,
                cwe_id=str(cwe_list[0]) if cwe_list else None,
                cve_id=vuln.get("VulnerabilityID"),
                owasp_category="A06:2021 - Vulnerable and Outdated Components",
                fix_suggestion=fix,
                metadata={
                    "package": pkg,
                    "installed_version": installed,
                    "fixed_version": fixed,
                    "cvss_score": score,
                    "primary_url": vuln.get("PrimaryURL"),
                    "data_source": (vuln.get("DataSource") or {}).get("Name"),
                },
            )
        )
    return out


def _parse_misconfigurations(res: dict, target: str) -> list[Finding]:
    out: list[Finding] = []
    for mis in res.get("Misconfigurations", []) or []:
        # Only report actual failures, not passed/skipped checks.
        if mis.get("Status") and mis.get("Status") != "FAIL":
            continue
        cause = mis.get("CauseMetadata", {}) or {}
        out.append(
            Finding(
                pillar=Pillar.SECURITY,
                engine=Engine.TRIVY,
                rule_id=mis.get("ID", "UNKNOWN-MISCONF"),
                rule_name=normalizer.truncate(mis.get("Title", ""), 500) or "misconfiguration",
                severity=normalizer.label_to_severity(mis.get("Severity")),
                title=normalizer.truncate(mis.get("Title") or mis.get("ID"), 1000) or "misconfiguration",
                description=normalizer.truncate(
                    f"{mis.get('Description', '')}\n\nResolution: {mis.get('Resolution', '')}", 8000
                ),
                file_path=target,
                line_start=cause.get("StartLine"),
                line_end=cause.get("EndLine"),
                owasp_category="A05:2021 - Security Misconfiguration",
                fix_suggestion=normalizer.truncate(mis.get("Resolution"), 8000),
                metadata={
                    "type": mis.get("Type"),
                    "namespace": mis.get("Namespace"),
                    "primary_url": mis.get("PrimaryURL"),
                },
            )
        )
    return out


def _best_cvss(cvss: dict) -> float | None:
    """Pick the highest V3 base score across all CVSS data sources."""
    best: float | None = None
    for source in (cvss or {}).values():
        if not isinstance(source, dict):
            continue
        score = source.get("V3Score") or source.get("V2Score")
        if isinstance(score, (int, float)):
            best = score if best is None else max(best, score)
    return best


def _rank(f: Finding) -> int:
    from models.scan_result import SEVERITY_ORDER

    return SEVERITY_ORDER[f.severity]
