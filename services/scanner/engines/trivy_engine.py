"""Trivy SCA + IaC engine.

Scans the filesystem for dependency vulnerabilities (CVE) and Infrastructure-as-
Code misconfigurations (Dockerfile, Terraform, k8s). Secrets are intentionally
left to the Gitleaks engine so we don't double-count the same finding.

CVSS → severity mapping: >=9.0 critical, >=7.0 high, >=4.0 medium, else low.
"""
from __future__ import annotations

import json
import os

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
from enrichment import enricher
from utils import epss, kev, normalizer, reachability, vendored_fingerprint
from utils.sandbox import binary_available, run_with_retry

log = get_logger("trivy")


# Demo/sample/dependency dirs excluded from SCA + IaC scanning (glob patterns).
_SKIP_DIRS = ["**/node_modules/**", "**/vendor/**", "**/examples/**", "**/example/**",
              "**/samples/**", "**/sample/**", "**/docs/**", "**/docs_src/**"]

# Human labels for the IaC config type Trivy reports.
_IAC_TYPE_LABEL = {
    "dockerfile": "Dockerfile", "terraform": "Terraform", "terraformplan": "Terraform",
    "kubernetes": "Kubernetes", "helm": "Helm", "cloudformation": "CloudFormation",
    "azure-arm": "Azure ARM", "rbac": "Kubernetes RBAC", "yaml": "config", "json": "config",
}


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
        # Skip demo/sample/dependency trees so IaC + SCA respect the same
        # production-scoping discipline as SAST (COMPARATIVE_ANALYSIS.md / Phase 2E).
        "--skip-dirs", ",".join(_SKIP_DIRS),
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

    # Reachability index (import/usage graph). Best-effort: a failure here must
    # never fail SCA — findings then simply carry reachable=None (full penalty).
    try:
        index = reachability.build_index(req.path)
    except Exception as exc:  # noqa: BLE001
        log.warning("trivy.reachability_index_failed", error=str(exc))
        index = None

    findings = _parse(raw, req.path, index)
    # Vendored-library fingerprinting: catch CVEs in libraries copied into the repo
    # without a manifest (Trivy can't see them). Deduped against Trivy's results so a
    # manifest-managed dep is never double-counted. Best-effort — never fails SCA.
    try:
        findings.extend(_fingerprint_findings(req.path, findings))
    except Exception as exc:  # noqa: BLE001
        log.warning("trivy.fingerprint_failed", error=str(exc))
    # EPSS: one batched exploit-probability lookup for all CVEs in this scan.
    # Best-effort — a failure just leaves findings without an EPSS field.
    try:
        _attach_epss(findings)
    except Exception as exc:  # noqa: BLE001
        log.warning("trivy.epss_failed", error=str(exc))
    enricher.enrich_all(findings, req.path)
    reachable = sum(1 for f in findings if (f.metadata or {}).get("reachable") is True)
    log.info(
        "trivy.completed",
        findings=len(findings),
        reachable_deps=reachable,
    )
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


def _fingerprint_findings(root: str, existing: list[Finding]) -> list[Finding]:
    """Detect vendored (copied-in) libraries by fingerprint and turn their known
    OSV CVEs into SCA findings. Deduped against Trivy's manifest results by
    (package, cve) so a dependency is never counted twice. Tagged third-party +
    detected_via=fingerprint so the report is clear about provenance."""
    # (package_lower, cve_id) pairs Trivy already reported — don't duplicate.
    seen: set[tuple[str, str]] = set()
    for f in existing:
        pkg = ((f.metadata or {}).get("package") or "").lower()
        if pkg and f.cve_id:
            seen.add((pkg, f.cve_id))

    out: list[Finding] = []
    for lib in vendored_fingerprint.detect_libraries(root):
        pkg, ver, eco, path = lib["package"], lib["version"], lib["ecosystem"], lib["file"]
        for v in vendored_fingerprint.osv_vulns(pkg, eco, ver):
            cve = vendored_fingerprint.cve_id(v) or v.get("id", "")
            if not cve or (pkg.lower(), cve) in seen:
                continue
            seen.add((pkg.lower(), cve))
            fixed = vendored_fingerprint.fixed_version(v, pkg)
            fix = (f"Update the vendored {lib['lib']} ({pkg} {ver}) to {fixed} or later."
                   if fixed else f"Update or replace the vendored {lib['lib']} ({pkg} {ver}).")
            out.append(Finding(
                pillar=Pillar.SECURITY,
                engine=Engine.TRIVY,
                rule_id=cve,
                rule_name=normalizer.truncate(f"{pkg} {ver}", 500) or pkg,
                severity=normalizer.label_to_severity(vendored_fingerprint.vuln_severity(v)),
                title=normalizer.truncate(
                    f"{v.get('summary') or cve} in vendored {lib['lib']} {ver}", 1000) or cve,
                description=normalizer.truncate(
                    f"{v.get('details') or v.get('summary') or ''}\n\n"
                    f"Detected via fingerprint: a copy of {lib['lib']} ({pkg} {ver}) is vendored "
                    f"into this repo at {path} (no package manifest). {cve} affects this version.", 8000),
                file_path=path,
                cve_id=cve,
                owasp_category="A06:2021 - Vulnerable and Outdated Components",
                fix_suggestion=fix,
                metadata={
                    "package": pkg,
                    "installed_version": ver,
                    "fixed_version": fixed,
                    "detected_via": "fingerprint",
                    "vendored": True,
                    "library": lib["lib"],
                    "code_ownership": "third_party",
                    "ownership_reason": f"vendored library (fingerprint): {lib['lib']} {ver}",
                    "primary_url": (v.get("references") or [{}])[0].get("url") if v.get("references") else None,
                    **kev.kev_info(cve),
                },
            ))
    return out


def _attach_epss(findings: list[Finding]) -> None:
    """Batch-fetch EPSS scores for every CVE in the scan and attach them. One
    request for all CVEs; best-effort."""
    cve_ids = [f.cve_id for f in findings if f.cve_id]
    if not cve_ids:
        return
    scores = epss.scores_for(cve_ids)
    if not scores:
        return
    for f in findings:
        if not f.cve_id:
            continue
        info = scores.get(f.cve_id.strip().upper())
        if info:
            meta = f.metadata if isinstance(f.metadata, dict) else {}
            meta.update(info)
            f.metadata = meta


def _parse(raw: dict, root: str, index: "reachability.ReachabilityIndex | None") -> list[Finding]:
    findings: list[Finding] = []
    for res in raw.get("Results", []) or []:
        target = res.get("Target", "")
        ecosystem = reachability.ecosystem_for_type(res.get("Type"))
        dep_paths = _dependency_paths(res)
        findings.extend(_parse_vulnerabilities(res, target, ecosystem, index, root, dep_paths))
        findings.extend(_parse_misconfigurations(res, target, res.get("Type", "")))
    findings.sort(key=lambda f: (_rank(f), f.file_path))
    return findings


def _dependency_paths(res: dict) -> dict[str, dict]:
    """Build pkgID -> introduced-through metadata from Trivy's dependency graph.

    Trivy emits Packages[] with Relationship (root/direct/indirect) and DependsOn
    (child pkg IDs). For a transitive (indirect) vulnerable package we walk the
    graph from a DIRECT dependency down to it, so the finding can show
    "your-app -> dep-A -> vulnerable-dep-B" — telling the user which of THEIR
    direct dependencies to update. Trivy usually omits the synthetic root node, so
    we synthesize it for display and derive transitivity from each package's own
    Relationship (not chain length). Returns {} when the lockfile carries no graph.
    """
    pkgs = res.get("Packages") or []
    if not pkgs:
        return {}
    by_id: dict[str, dict] = {}
    children: dict[str, list[str]] = {}
    root_label = "your app"
    directs: list[str] = []
    for p in pkgs:
        pid = p.get("ID")
        if not pid:
            continue
        by_id[pid] = p
        children[pid] = list(p.get("DependsOn") or [])
        rel = p.get("Relationship")
        if rel == "root":
            root_label = _pkg_label(p, pid)
        elif rel == "direct":
            directs.append(pid)

    # BFS from every direct dependency; record the shortest chain (direct -> pkg)
    # to each reachable package. chain[0] is always the actionable direct dep.
    from collections import deque

    best: dict[str, list[str]] = {}
    for start in directs:
        q: deque[list[str]] = deque([[start]])
        seen_local: set[str] = {start}
        while q:
            path = q.popleft()
            node = path[-1]
            if node not in best or len(path) < len(best[node]):
                best[node] = path
            for child in children.get(node, []):
                if child not in seen_local:
                    seen_local.add(child)
                    q.append(path + [child])

    out: dict[str, dict] = {}
    for pid, p in by_id.items():
        rel = p.get("Relationship")
        chain = best.get(pid)
        if chain is None:
            # A direct dep is its own entry point; anything else without a chain
            # (no graph edge found) we leave unannotated.
            if rel == "direct":
                chain = [pid]
            else:
                continue
        labels = [_pkg_label(by_id.get(n) or {}, n) for n in chain]
        transitive = rel == "indirect" or len(chain) > 1
        out[pid] = {
            "dependency_path": [root_label] + labels,
            "introduced_through": labels[0],  # the direct dep the user declared
            "is_transitive": transitive,
        }
    return out


def _pkg_label(p: dict, pid: str) -> str:
    name = p.get("Name") or pid.split("@")[0]
    ver = p.get("Version")
    return f"{name}@{ver}" if ver else (name or pid)


def _locate_in_lockfile(root: str, target: str, pkg: str, installed: str) -> int | None:
    """Best-effort: find the line where pkg@installed appears in the lockfile.

    Trivy does not emit a line/location for dependency-file vulnerabilities, so the
    SCA finding otherwise points at "package-lock.json" with no line. We locate the
    exact entry ourselves — preferring a line that names BOTH the package and the
    flagged version (this disambiguates e.g. two postcss versions in one lockfile),
    falling back to a package-name token. Any failure returns None (no regression).
    """
    if not target or not pkg:
        return None
    path = os.path.join(root, target)
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > 8_000_000:
            return None
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return None

    name_hit: int | None = None
    for i, line in enumerate(lines, 1):
        if pkg not in line:
            continue
        # A line naming the package + the exact flagged version is the best anchor.
        if installed and installed in line:
            return i
        if name_hit is None:
            # Token-ish match ("pkg": / pkg== / pkg@ / /pkg") to avoid substrings.
            for probe in (f'"{pkg}"', f"'{pkg}'", f"{pkg}==", f"{pkg}@", f"/{pkg}", f"{pkg} "):
                if probe in line:
                    name_hit = i
                    break
    return name_hit


def _parse_vulnerabilities(
    res: dict,
    target: str,
    ecosystem: str | None,
    index: "reachability.ReachabilityIndex | None",
    root: str = "",
    dep_paths: dict[str, list[str]] | None = None,
) -> list[Finding]:
    out: list[Finding] = []
    dep_paths = dep_paths or {}
    for vuln in res.get("Vulnerabilities", []) or []:
        cvss = vuln.get("CVSS", {}) or {}
        score, cvss_source, vector = _select_cvss(cvss)
        severity = normalizer.cvss_to_severity(score, vuln.get("Severity"))
        pkg = vuln.get("PkgName", "")
        installed = vuln.get("InstalledVersion", "")
        fixed = vuln.get("FixedVersion")
        cwe_list = vuln.get("CweIDs") or []

        fix = (
            f"Upgrade {pkg} from {installed} to {fixed} or later."
            if fixed else f"No fixed version published yet for {pkg} {installed}."
        )

        reach: dict = {}
        if index is not None and ecosystem is not None and pkg:
            reach = index.annotate(ecosystem, pkg)

        # CISA KEV: is this CVE actively exploited in the wild? The strongest
        # triage signal — flagged prominently + weighted up in scoring.
        kev_meta = kev.kev_info(vuln.get("VulnerabilityID"))

        # Dependency path: for a transitive vuln, the introduced-through chain
        # (your-app -> dep-A -> vulnerable-dep-B), so the user knows which of THEIR
        # direct deps to update. From Trivy's dependency graph via PkgID.
        pkg_id = vuln.get("PkgID") or (f"{pkg}@{installed}" if pkg and installed else "")
        dep_meta = dep_paths.get(pkg_id) or {}

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
                line_start=_locate_in_lockfile(root, target, pkg, installed),
                cwe_id=str(cwe_list[0]) if cwe_list else None,
                cve_id=vuln.get("VulnerabilityID"),
                owasp_category="A06:2021 - Vulnerable and Outdated Components",
                fix_suggestion=fix,
                metadata={
                    "package": pkg,
                    "installed_version": installed,
                    "fixed_version": fixed,
                    "cvss_score": score,
                    "cvss_vector": vector,
                    "cvss_source": cvss_source,
                    "primary_url": vuln.get("PrimaryURL"),
                    "data_source": (vuln.get("DataSource") or {}).get("Name"),
                    # Reachability (import/usage-level). reachable is None when
                    # undetermined; is_direct None when no manifest was found.
                    "reachable": reach.get("reachable"),
                    "reachable_files": reach.get("reachable_files", []),
                    "reachable_file_count": reach.get("reachable_file_count"),
                    "is_direct": reach.get("is_direct"),
                    "reachability_ecosystem": reach.get("reachability_ecosystem"),
                    **kev_meta,
                    **dep_meta,
                },
            )
        )
    return out


def _parse_misconfigurations(res: dict, target: str, result_type: str = "") -> list[Finding]:
    out: list[Finding] = []
    for mis in res.get("Misconfigurations", []) or []:
        # Only report actual failures, not passed/skipped checks.
        if mis.get("Status") and mis.get("Status") != "FAIL":
            continue
        cause = mis.get("CauseMetadata", {}) or {}
        # Prefer the (clean) result Type — "dockerfile"/"terraform"/"kubernetes" —
        # over the misconfiguration's verbose Type ("Dockerfile Security Check").
        iac_type = (result_type or mis.get("Type") or "").lower()
        iac_label = _IAC_TYPE_LABEL.get(iac_type, iac_type or "IaC")
        base_title = normalizer.truncate(mis.get("Title") or mis.get("ID"), 1000) or "misconfiguration"
        out.append(
            Finding(
                pillar=Pillar.SECURITY,
                engine=Engine.TRIVY,
                rule_id=mis.get("ID", "UNKNOWN-MISCONF"),
                rule_name=normalizer.truncate(mis.get("Title", ""), 500) or "misconfiguration",
                severity=normalizer.label_to_severity(mis.get("Severity")),
                # Prefix with the IaC kind so it's unmistakably an IaC finding.
                title=f"[IaC · {iac_label}] {base_title}"[:1000],
                description=normalizer.truncate(
                    f"{mis.get('Description', '')}\n\nResolution: {mis.get('Resolution', '')}", 8000
                ),
                file_path=target,
                line_start=cause.get("StartLine"),
                line_end=cause.get("EndLine"),
                owasp_category="A05:2021 - Security Misconfiguration",
                fix_suggestion=normalizer.truncate(mis.get("Resolution"), 8000),
                metadata={
                    "category": "iac-misconfiguration",
                    "iac_type": iac_type,
                    "iac_kind": iac_label,
                    "type": mis.get("Type"),
                    "namespace": mis.get("Namespace"),
                    "primary_url": mis.get("PrimaryURL"),
                },
            )
        )
    return out


# CVSS source precedence (precision S1). NEVER take max() across sources — that
# inflated scores (V1 reported axios CVE-2026-42043 at 10.0 when NVD says 7.2,
# because a vendor source disagreed and max() won). Authoritative order: NVD, then
# GHSA, then any vendor source. The chosen source is recorded in `cvss_source`.
_CVSS_PRECEDENCE = ("nvd", "ghsa")


def _select_cvss(cvss: dict) -> tuple[float | None, str | None, str | None]:
    """Return (score, source, vector) chosen by source precedence — not by max().
    Prefers the V3 base score; falls back to V2 only within the same source. When
    no source carries a score, returns (None, source-of-vector-if-any, vector) so
    the caller derives severity from the advisory's own label instead of guessing."""
    if not isinstance(cvss, dict) or not cvss:
        return None, None, None
    ordered = [k for k in _CVSS_PRECEDENCE if k in cvss] + sorted(
        k for k in cvss if k not in _CVSS_PRECEDENCE
    )
    vector_only: tuple[str, str] | None = None  # (source, vector) if no score found
    for src in ordered:
        s = cvss.get(src)
        if not isinstance(s, dict):
            continue
        score = s.get("V3Score")
        if not isinstance(score, (int, float)):
            score = s.get("V2Score")
        if isinstance(score, (int, float)):
            return float(score), src, s.get("V3Vector")
        if vector_only is None and s.get("V3Vector"):
            vector_only = (src, s["V3Vector"])
    if vector_only is not None:
        return None, vector_only[0], vector_only[1]
    return None, None, None


def _rank(f: Finding) -> int:
    from models.scan_result import SEVERITY_ORDER

    return SEVERITY_ORDER[f.severity]
