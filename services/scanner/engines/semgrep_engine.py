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
import re
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
from enrichment import steps_to_reproduce
from utils import bundled_assets, language_detector, normalizer
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

# Aegis IaC rules (Phase 2E Task 2): docker-compose misconfigurations — the one
# IaC surface Trivy's misconfig scanner doesn't cover. Always-on; path-scoped to
# compose files so they never fire on ordinary YAML.
_IAC_RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "iac"
)

# Aegis reliability-bug rules (Q1): aegis-bug-* patterns that assert "your code is
# wrong" on a real grammar. They carry metadata.pillar=quality so _parse routes
# them to the QUALITY pillar (not security), where the enricher tags them
# issue_type=bug and they drive the SonarQube-style Reliability rating.
_QUALITY_RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "quality"
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


def _bundled_rules_dir(path: str) -> str | None:
    """Return a bundled Aegis rules dir if it exists and holds YAML, else None."""
    try:
        if os.path.isdir(path) and any(
            name.endswith((".yaml", ".yml")) for name in os.listdir(path)
        ):
            return path
    except OSError as exc:  # pragma: no cover — defensive
        log.warning("semgrep.bundled_rules_stat_failed", path=path, error=str(exc))
    return None


def _custom_rules_dir() -> str | None:
    return _bundled_rules_dir(_CUSTOM_RULES_DIR)


# ── Project-defined sanitizer detection (precision-first XSS) ──────────────────
# HTML-escaping functions. A project function whose body calls one of these is a
# real output-escaping wrapper (e.g. `function sanitize($x){return htmlspecialchars($x);}`)
# and must silence the XSS taint rule — otherwise we false-positive on every use
# of a well-written app's own escaper. We trust ONLY wrappers we have *seen* escape
# (never a name guess), so this adds no false negatives.
_HTML_ESCAPERS = ("htmlspecialchars", "htmlentities", "htmlescape", "strip_tags")
_PHP_FUNC_DEF = re.compile(r"function\s+([A-Za-z_]\w*)\s*\(", re.IGNORECASE)
_WALK_SKIP = {".git", "vendor", "node_modules", ".next", "_next", "dist", "build"}


def _php_escaper_wrappers(root: str, cap_files: int = 5000, cap_bytes: int = 2_000_000) -> set[str]:
    """Names of project PHP functions whose body calls an HTML-escaper — verified
    escaping wrappers we can trust as XSS sanitizers. Best-effort; bounded."""
    out: set[str] = set()
    scanned = 0
    try:
        for dirpath, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in _WALK_SKIP]
            for fn in files:
                if not fn.endswith((".php", ".inc", ".phtml")):
                    continue
                scanned += 1
                if scanned > cap_files:
                    return out
                path = os.path.join(dirpath, fn)
                try:
                    if os.path.getsize(path) > cap_bytes:
                        continue
                    with open(path, encoding="utf-8", errors="ignore") as fh:
                        text = fh.read()
                except OSError:
                    continue
                for m in _PHP_FUNC_DEF.finditer(text):
                    name = m.group(1)
                    if name.lower() in _HTML_ESCAPERS:
                        continue
                    body = text[m.end(): m.end() + 1000]
                    nxt = body.find("function ")  # don't bleed into the next def
                    if nxt != -1:
                        body = body[:nxt]
                    if any(e in body for e in _HTML_ESCAPERS):
                        out.add(name)
    except Exception as exc:  # noqa: BLE001 — detection must never break a scan
        log.debug("semgrep.escaper_scan_failed", error=str(exc))
    return out


def _augmented_taint_dir(root: str, base_dir: str) -> str | None:
    """If the project defines its own HTML-escaping wrapper(s), return a temp copy
    of the taint rules with aegis-php-xss taught to treat them as sanitizers.
    Returns None (use the static rules) when there's nothing to add. Best-effort."""
    wrappers = _php_escaper_wrappers(root)
    if not wrappers:
        return None
    try:
        import yaml

        tmp = tempfile.mkdtemp(prefix="aegis-taint-")
        for fn in os.listdir(base_dir):  # copy every rule file verbatim
            if fn.endswith((".yaml", ".yml")):
                shutil.copy(os.path.join(base_dir, fn), os.path.join(tmp, fn))
        php_path = os.path.join(tmp, "php.yaml")
        with open(php_path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        extra = [{"pattern": f"{w}(...)"} for w in sorted(wrappers)]
        for rule in doc.get("rules", []):
            if rule.get("id") != "aegis-php-xss":
                continue
            for san in rule.get("pattern-sanitizers", []) or []:
                pe = san.get("pattern-either")
                if isinstance(pe, list):
                    pe.extend(extra)
        with open(php_path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(doc, fh, sort_keys=False, allow_unicode=True)
        log.info("semgrep.project_sanitizers", wrappers=sorted(wrappers))
        return tmp
    except Exception as exc:  # noqa: BLE001 — augmentation must never break a scan
        log.warning("semgrep.sanitizer_augment_failed", error=str(exc))
        return None


def _semgrep_jobs(settings: Settings) -> int:
    """Worker count for Semgrep's per-file parallelism (Track 1e). Honors an
    explicit SEMGREP_JOBS override, else uses all CPUs the container is allotted
    (cgroup-aware via os.sched_getaffinity where available)."""
    configured = getattr(settings, "semgrep_jobs", 0) or 0
    if configured > 0:
        return configured
    try:
        return max(1, len(os.sched_getaffinity(0)))  # respects cgroup CPU limits
    except AttributeError:
        return max(1, os.cpu_count() or 1)


# Demo / sample / documentation directories excluded by default so production
# scans don't flag non-production example code (the code_relevant discipline from
# COMPARATIVE_ANALYSIS.md — Consul/Vault). Matched by path component, so real
# source (incl. the OWASP Benchmark's `testcode/`) is unaffected.
_DEFAULT_EXCLUDE_DIRS = [
    # dependencies / build
    "node_modules", "vendor",
    # demo / sample / documentation only (the scoping requested for Track 2f).
    # `docs_src` covers fastapi-style tutorial trees. Test directories are
    # deliberately NOT excluded: real code lives there and over-scoping would
    # hide genuine findings (and mask the scanner's own test fixtures).
    "examples", "example", "samples", "sample", "docs", "doc", "docs_src",
]

# Recall-safe default rule exclusions (Track 2f accuracy pass). Every entry either
# flags a non-weakness or is an indiscriminate audit rule; NONE fires on the OWASP
# Benchmark (all JS/Go), so recall there is provably unchanged — verified by
# re-running the benchmark after adding these. The high-precision profile
# (SEMGREP_EXCLUDE_RULES) still applies on top for teams wanting a deeper trade.
_DEFAULT_EXCLUDE_RULES = [
    # Cookie attributes whose ABSENCE is not a security weakness: path/domain
    # default to safe (host-only) values and maxAge/expires absence just means a
    # session cookie. The real ones — no-secure, no-httponly, sameSite,
    # default-name, hardcoded-secret — are deliberately kept.
    "javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-domain",
    "javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-path",
    "javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-expires",
    "ajinabraham.njsscan.headers.header_cookie.cookie_session_no_domain",
    "ajinabraham.njsscan.headers.header_cookie.cookie_session_no_path",
    "ajinabraham.njsscan.headers.header_cookie.cookie_session_no_maxage",
    # Indiscriminate audit rules that flag EVERY framework write to an
    # http.ResponseWriter regardless of content-type or taint (a JSON/protobuf
    # serializer is not XSS). Real dataflow XSS in Go is covered by Aegis's own
    # go taint rules (rules/taint/go.yaml); these add only noise.
    "go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter",
    "go.lang.security.audit.xss.no-fprintf-to-responsewriter.no-fprintf-to-responsewriter",
    # PHP: `echoed-request` flags ANY echo of request data with no dataflow and no
    # sanitizer awareness — it fires straight through htmlspecialchars() wrappers
    # (e.g. a project's sanitize() helper), a large false-positive source. Real
    # PHP XSS is covered precisely, sanitizer-aware, by Aegis's own taint rule
    # (rules/taint/php.yaml: aegis-php-xss), so this only adds noise + double-counts.
    "php.lang.security.injection.echoed-request.echoed-request",
    # `tainted-callable` is over-broad: it fired on `$pdo->prepare($query)` (a
    # prepared statement, not a callable) — a clear false positive. Dynamic-callable
    # RCE from request data is rare and better handled by a precise rule if added.
    "php.lang.security.injection.tainted-callable.tainted-callable",
]


def _build_args(settings: Settings, configs: list[str], path: str,
                extra_excludes: list[str] = ()) -> list[str]:
    """Assemble the semgrep CLI invocation for the given config list."""
    args = [settings.semgrep_bin, "scan", "--json", "--quiet", "--metrics", "off",
            "--disable-version-check", "--timeout", "60", "--max-target-bytes", "2000000",
            # Emit taint source→sink dataflow traces so findings can carry
            # steps-to-reproduce (Phase 2E Task 1). Only populated for taint rules.
            "--dataflow-traces",
            "--jobs", str(_semgrep_jobs(settings))]
    for cfg in configs:
        args += ["--config", cfg]
    for d in _DEFAULT_EXCLUDE_DIRS:
        args += ["--exclude", d]
    # Bundled/minified third-party JS/TS assets (T1): excluded from SAST ONLY. These
    # are third-party code (SAST findings in them are noise) and one 720KB file cost
    # 239s under p/nodejsscan — the timeout root cause. SCA + vendored-fingerprinting
    # still scan them for real CVEs. See utils.bundled_assets.
    for f in extra_excludes:
        args += ["--exclude", f]
    # Recall-safe defaults, then the opt-in high-precision profile (Track 2d/2f).
    for rule in _DEFAULT_EXCLUDE_RULES + settings.semgrep_exclude_rule_list:
        args += ["--exclude-rule", rule]
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

    # Teach the PHP XSS taint rule about the project's own HTML-escaping wrappers
    # (e.g. a sanitize() helper) so it doesn't false-positive on escaped output.
    # Uses a per-scan augmented copy of the taint rules; cleaned up below.
    aug_taint_dir = _augmented_taint_dir(req.path, custom_dir) if custom_dir else None
    if aug_taint_dir:
        custom_dir = aug_taint_dir

    # Per-project custom rules (already validated at upload) live for the duration
    # of this scan in a temp dir added on top of the registry + Aegis packs.
    project_rules_dir = _write_project_rules(req.custom_rules)
    if project_rules_dir:
        registry_configs = registry_configs + [project_rules_dir]

    iac_dir = _bundled_rules_dir(_IAC_RULES_DIR)
    quality_dir = _bundled_rules_dir(_QUALITY_RULES_DIR)
    bundled = (([custom_dir] if custom_dir else [])
               + ([iac_dir] if iac_dir else []) + ([quality_dir] if quality_dir else []))
    configs = registry_configs + bundled
    rule_pack_version = _rule_pack_version(configs, req.custom_rules)

    # T1 fix: exclude bundled/minified third-party JS/TS from SAST (one 720KB library
    # cost 239s under p/nodejsscan). SAST-only — SCA + vendored-fingerprinting still
    # scan these files. Counted + surfaced (never a silent skip): see excluded_bundled.
    asset_skip = set(_WALK_SKIP) | set(_DEFAULT_EXCLUDE_DIRS)
    if os.getenv("AEGIS_DISABLE_BUNDLED_EXCLUDE") == "1":
        asset_paths, asset_bytes, asset_reasons = [], 0, {}
    else:
        asset_paths, asset_bytes, asset_reasons = bundled_assets.find_bundled(req.path, asset_skip)
    if asset_paths:
        log.info("semgrep.bundled_assets_excluded", count=len(asset_paths),
                 bytes=asset_bytes, reasons=asset_reasons)
    excluded_bundled = ({
        "files": len(asset_paths), "bytes": asset_bytes, "reasons": asset_reasons,
        "sample": sorted(asset_paths)[:25],
    } if asset_paths else None)

    async def _semgrep(cfgs: list[str]):
        # Semgrep exits 0 (no findings) or 1 (findings present); >=2 is an error.
        return await run_command(
            _build_args(settings, cfgs, req.path, extra_excludes=asset_paths),
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
    degraded = False
    degraded_reason: str | None = None
    coverage_lost: str | None = None
    if custom_applied and not result.timed_out and result.returncode not in (0, 1):
        log.warning(
            "semgrep.custom_rules_failed_retrying",
            error=normalizer.truncate(result.stderr, 1000),
        )
        custom_applied = False
        # DEGRADED, not clean: registry rules still ran, but the Aegis custom packs
        # (taint, AI-code taint, IaC, reliability bug pack) did NOT. Surface it — do
        # not report a successful SAST as if it had full coverage.
        degraded = True
        degraded_reason = "custom rule pack failed to load; retried with registry packs only"
        coverage_lost = "Aegis custom taint, AI-code taint, IaC, and reliability bug-pack rules"
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
    if aug_taint_dir:
        shutil.rmtree(aug_taint_dir, ignore_errors=True)

    findings = _parse(raw, req.path)
    from enrichment import enricher

    filtered_secrets: dict[str, int] = {}
    enricher.enrich_all(findings, req.path, stats=filtered_secrets)
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
        degraded=degraded,
        degraded_reason=degraded_reason,
        coverage_lost=coverage_lost,
        filtered_secrets={k: v for k, v in filtered_secrets.items() if v} or None,
        excluded_bundled=excluded_bundled,
    )


def _is_non_subresource_link(matched: str) -> bool:
    """True when a missing-integrity match is on a <link> whose rel is NOT a
    subresource (stylesheet / preload / modulepreload) — SRI is meaningless on
    rel=canonical/alternate/icon/preconnect/dns-prefetch/manifest/..., so flagging
    those is a false positive. <script src> and real stylesheet/preload links are
    kept (returns False)."""
    m = matched.lower()
    if "<link" not in m:
        return False  # <script> or non-link match — a valid SRI target, keep it
    for rel in ('rel="stylesheet"', "rel='stylesheet'", 'rel="preload"',
                "rel='preload'", 'rel="modulepreload"', "rel='modulepreload'"):
        if rel in m:
            return False  # a genuine subresource link — keep it
    return True  # a <link> with no subresource rel — false positive, drop it


# Hardcoded-secret / password rules (njsscan node_password, generic hardcoded-
# secret) fire on any `password = "literal"`. They over-match masked or placeholder
# values that are obviously NOT credentials — e.g. booklore's
# `dummyPassword = "***********************"` display mask, or `password: ''`.
_SECRET_RULE_HINTS = (
    "hardcoded_secret", "hardcoded-secret", "hardcoded_password", "hardcoded-password",
    "node_password", "node_username", "node_secret",
)
_STRING_LIT_RE = re.compile(r"""(['"`])((?:(?!\1).)*)\1""")
_MASK_RE = re.compile(r"^[*x•.\-_\s]{3,}$", re.I)
_PLACEHOLDER_SECRET_WORDS = {
    "changeme", "change_me", "placeholder", "example", "dummy", "sample",
    "redacted", "none", "null", "undefined", "todo", "test", "password", "secret",
}


def _is_placeholder_secret(lines: str) -> bool:
    """True when a hardcoded-secret rule matched a line whose every string-literal
    value is a non-credential: empty, a mask (`****`), or a placeholder word. A real
    literal value anywhere on the line → False (keep the finding). Precision-first:
    recall for genuine hardcoded secrets is unaffected."""
    vals = [m.group(2) for m in _STRING_LIT_RE.finditer(lines or "")]
    if not vals:
        return False
    for v in vals:
        s = v.strip()
        if not s or len(set(s)) <= 1 or _MASK_RE.match(s):
            continue  # empty / single-repeated-char / mask
        low = s.lower()
        if low in _PLACEHOLDER_SECRET_WORDS or low.startswith(
            ("your_", "your-", "example", "changeme", "placeholder", "dummy", "<")
        ):
            continue
        return False  # a real-looking value — keep the finding
    return True  # every value on the line was empty / mask / placeholder


def _parse(raw: dict, root: str) -> list[Finding]:
    findings: list[Finding] = []
    for item in raw.get("results", []):
        extra = item.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        start = item.get("start", {}) or {}
        end = item.get("end", {}) or {}

        check_id = item.get("check_id", "unknown-rule")
        rule_short = check_id.rsplit(".", 1)[-1]

        # Precision: the registry missing-integrity (SRI) rule fires on ANY external
        # <link>, but Subresource Integrity only applies to <script> and
        # <link rel="stylesheet"|"preload"|"modulepreload">. Firing on
        # rel="canonical"/"alternate"/"icon"/... is a false positive — drop those.
        if "missing-integrity" in check_id and _is_non_subresource_link(extra.get("lines", "") or ""):
            continue

        # Precision: hardcoded-secret rules over-match masked / placeholder values
        # (a `dummyPassword = "****"` display mask, `password: ''`) that are plainly
        # not credentials. Drop those; a real literal value keeps the finding.
        if any(h in check_id for h in _SECRET_RULE_HINTS) and _is_placeholder_secret(
            extra.get("lines", "") or ""
        ):
            continue

        message = extra.get("message") or rule_short
        # Rules loaded from a local dir are namespaced by semgrep with a
        # path-derived prefix (e.g. "rules.taint.aegis-js-xss" for our bundled
        # packs, or "tmp.aegis-project-rules-XXXX.rule" for per-project rules).
        # Normalize both to their stable rule id; keep registry ids canonical.
        is_project = "aegis-project-rules-" in check_id
        is_aegis = rule_short.startswith("aegis-")
        rule_id = rule_short if (is_project or is_aegis) else check_id
        ruleset = (
            "project-custom" if is_project
            else "aegis-custom" if is_aegis
            else "registry"
        )

        # Route by the rule's declared pillar: aegis-bug-* quality rules carry
        # metadata.pillar=quality and belong to the QUALITY pillar (reliability
        # bugs), not security. Everything else stays a security finding.
        rule_pillar = Pillar.QUALITY if metadata.get("pillar") == "quality" else Pillar.SECURITY

        severity = normalizer.normalize_semgrep_severity(extra.get("severity", ""), metadata)
        cwe_id = normalizer.extract_cwe(metadata)
        # Steps-to-reproduce from Semgrep's taint dataflow trace (Phase 2E Task 1).
        # Only present for taint-mode findings; None → the section is omitted.
        sor = steps_to_reproduce.build(extra.get("dataflow_trace"), cwe_id, rule_id)

        findings.append(
            Finding(
                pillar=rule_pillar,
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
                cwe_id=cwe_id,
                owasp_category=normalizer.extract_owasp(metadata),
                fix_suggestion=normalizer.truncate(extra.get("fix"), 8000),
                context_metadata={"steps_to_reproduce": sor} if sor else None,
                metadata={
                    "ruleset": ruleset,
                    "confidence": metadata.get("confidence"),
                    "references": metadata.get("references"),
                    "category": metadata.get("category"),
                    "iac_type": metadata.get("iac_type"),  # e.g. docker-compose (Phase 2E)
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
