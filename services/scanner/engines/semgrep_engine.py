"""Semgrep SAST engine.

Runs the Semgrep CE engine (LGPL-2.1) over rule packs Aegis owns or may ship:
Aegis's own packs (rules/taint, rules/quality, rules/iac, rules/cicd) on every
scan, plus the pinned njsscan pack (LGPL-3.0-or-later) for JS/TS. Normalizes
each result into a `Finding`. The taint packs add cross-file dataflow detection
for SQLi / XSS / command injection / SSRF / path traversal / NoSQL / LDAP
injection; each ships with positive + sanitized-negative tests.

N1 (2026-09-19): the Semgrep-registry packs were removed -- their licence does
not permit commercial shipping -- together with every path that could fetch
rules from the registry. Only local rule files ever reach the command line.
"""
from __future__ import annotations

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
from utils import bundled_assets, language_detector, normalizer, rule_coverage
from utils.sandbox import binary_available, run_command

log = get_logger("semgrep")

# Third-party packs per language. N1 removed every Semgrep-registry pack (Semgrep
# Rules License v1.0 -- no commercial shipping); the only third-party pack left is
# njsscan (LGPL-3.0-or-later, 114 Node rules), pinned to its upstream commit in
# rules/manifest.yaml. Every other language is covered by Aegis's own packs alone
# (rules/taint, rules/quality, ...), which load for every scan below.
# Dockerfile/Terraform had registry packs too; Trivy's misconfig scanner covers both.
_LANGUAGE_RULESETS: dict[str, list[str]] = {
    "javascript": ["nodejsscan"],
    "typescript": ["nodejsscan"],
}

# Absolute path to Aegis's bundled custom taint rulesets. Shipped in the image
# at /app/rules/taint (COPY . .); also resolves correctly when run from a local
# checkout. Passed as an extra --config alongside the pinned third-party packs.
_CUSTOM_RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "taint"
)

# Aegis IaC rules (Phase 2E Task 2): docker-compose misconfigurations — the one
# IaC surface Trivy's misconfig scanner doesn't cover. Always-on; path-scoped to
# compose files so they never fire on ordinary YAML.
_IAC_RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "iac"
)

# Aegis CI/CD supply-chain rules (H2): aegis-cicd-* patterns over GitHub Actions
# workflow definitions. Always-on and language-independent -- the pipeline is the
# one surface every repo has regardless of what it is written in. Path-scoped to
# .github/workflows so they never fire on ordinary YAML, and deliberately scoped
# away from Dockerfile/Terraform/Kubernetes, which Trivy already covers.
_CICD_RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "cicd"
)

# Aegis reliability-bug rules (Q1): aegis-bug-* patterns that assert "your code is
# wrong" on a real grammar. They carry metadata.pillar=quality so _parse routes
# them to the QUALITY pillar (not security), where the enricher tags them
# issue_type=bug and they drive the SonarQube-style Reliability rating.
_QUALITY_RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "quality"
)


# Pinned third-party packs (G2, narrowed by N1). Nothing is ever fetched from a rule
# registry: a pack is used only if its file is shipped in rules/vendor/ and described
# by rules/manifest.yaml (tools/check_rule_licences.py enforces the licence side).
_VENDOR_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "vendor")


def _vendored(pack: str) -> str | None:
    """Resolve a pack name (`nodejsscan`) to its pinned local file, or None.

    Before N1 a missing file fell back to the `p/<pack>` registry shortcut, which
    semgrep then downloaded from semgrep.dev. That fallback is gone: a missing pack
    is dropped and logged, never fetched.
    """
    name = pack[2:] if pack.startswith("p/") else pack
    path = os.path.join(_VENDOR_DIR, name.replace("/", "_") + ".yaml")
    if os.path.isfile(path):
        return path
    log.warning("semgrep.vendored_pack_missing", pack=pack, expected=path)
    return None


def _local_configs_only(configs: list[str]) -> list[str]:
    """Drop any config that is not a local file or directory.

    Semgrep treats `p/...`, `r/...`, `s/...`, `auto`, and URLs as instructions to
    download rules from the Semgrep registry. Nothing that reaches the command line
    may be one of those -- not from settings, not from a pack map, not from a
    future edit. Refused entries are logged, never passed through.
    """
    out: list[str] = []
    for c in configs:
        if os.path.isfile(c) or os.path.isdir(c):
            out.append(c)
        else:
            log.warning("semgrep.non_local_config_refused", config=c)
    return out


def _select_configs(settings: Settings, languages: list[str], project_types: list[str]) -> list[str]:
    """Build the ordered, de-duplicated `--config` list of third-party packs.

    `project_types` is accepted for interface stability; since N1 no pack is
    selected by project type (Trivy covers Dockerfile/Terraform).
    """
    configs: list[str] = list(settings.semgrep_base_config_list)
    for lang in languages:
        for pack in _LANGUAGE_RULESETS.get(lang, []):
            path = _vendored(pack)
            if path:
                configs.append(path)
    seen: set[str] = set()
    ordered: list[str] = []
    for c in configs:
        if c not in seen:
            seen.add(c)
            ordered.append(c)
    return _local_configs_only(ordered)


def _rule_ids_in(config: str) -> set[str]:
    """Rule ids declared by one --config entry (file or directory of YAML).

    The id in the YAML is the canonical id `_parse` reports: our rules and
    per-project rules report their bare id, vendored rules their full id.
    """
    import yaml

    paths = ([os.path.join(config, fn) for fn in sorted(os.listdir(config)) if fn.endswith((".yaml", ".yml"))]
             if os.path.isdir(config) else [config])
    ids: set[str] = set()
    for p in paths:
        try:
            with open(p, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
        except (OSError, yaml.YAMLError):
            continue
        if isinstance(doc, dict) and isinstance(doc.get("rules"), list):
            ids |= {str(r.get("id")) for r in doc["rules"] if isinstance(r, dict) and r.get("id")}
    return ids


def _shipped_rule_ids() -> list[str]:
    """Every semgrep rule id Aegis ships (all of rules/, ours + vendored)."""
    root = os.path.dirname(_VENDOR_DIR)
    ids: set[str] = set()
    for dirpath, _dirs, _files in os.walk(root):
        ids |= _rule_ids_in(dirpath)
    return sorted(ids)


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


def _rule_content_hash(config: str) -> bytes:
    """Bytes identifying a single --config entry BY CONTENT, never by path."""
    h = hashlib.sha256()
    if os.path.isdir(config):
        for fn in sorted(os.listdir(config)):
            if fn.endswith((".yaml", ".yml")):
                h.update(fn.encode())
                with open(os.path.join(config, fn), "rb") as fh:
                    h.update(fh.read())
    elif os.path.isfile(config):
        with open(config, "rb") as fh:
            h.update(fh.read())
    else:
        # Unreachable since N1 (_local_configs_only drops non-local configs); kept so
        # the id still never fails a scan if a caller passes something unexpected.
        h.update(config.encode())
    return h.digest()


def _rule_pack_version(configs: list[str], custom_rules: list[str] | None) -> str:
    """A reproducible id for the rule set actually used.

    Hashes rule CONTENT, never filesystem paths. The previous version hashed the
    config strings, so the per-scan augmented-taint temp dir — a `mkdtemp` path that
    differs every run — changed the id between two byte-identical scans (F1 row 1b),
    making every re-scan look like a rule-pack change. Content hashing also means a
    silently-updated pack DOES change the id, which is the point of recording it.

    The date component comes from the pinned manifest, not `now()`: a wall-clock date
    would break reproducibility across midnight for an unchanged rule set.
    """
    h = hashlib.sha256()
    for c in sorted(configs):
        h.update(_rule_content_hash(c))
    for r in custom_rules or []:
        h.update(r.encode())
    return f"rp-{_manifest_pinned_at()}-{h.hexdigest()[:10]}"


def _manifest_pinned_at() -> str:
    """Pin date from the vendored rule manifest; 'unpinned' when it is absent."""
    path = os.path.join(os.path.dirname(_VENDOR_DIR), "manifest.yaml")
    try:
        import yaml

        with open(path, encoding="utf-8") as fh:
            return str((yaml.safe_load(fh) or {}).get("pinned_at", "unpinned")).replace("-", "")
    except Exception:  # noqa: BLE001 - the id must never fail a scan
        return "unpinned"


def _canonical_check_id(check_id: str) -> str:
    """Strip the vendored-path prefix semgrep prepends to locally-loaded rules.

    Loading a pack from a file makes semgrep derive the rule id from that path, so
    `php.lang.security.exec-use.exec-use` becomes
    `app.rules.vendor.php.lang.security.exec-use.exec-use`. Left alone, pinning the
    packs (G2) would silently rewrite every registry rule id — which changes finding
    fingerprints, so an unchanged codebase would report its entire backlog as NEW and
    break lifecycle continuity. Normalising here keeps ids identical to the live-fetch
    form, so the pin is invisible to everything downstream.
    """
    marker = "rules.vendor."
    idx = check_id.find(marker)
    return check_id[idx + len(marker):] if idx != -1 else check_id


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
    # default to safe (host-only) values and maxAge absence just means a session
    # cookie. The real ones -- no-secure, no-httponly, sameSite -- are kept.
    # (N1 removed the Semgrep-registry equivalents of these along with their packs,
    # and the Go/PHP registry-rule exclusions that used to follow.)
    "ajinabraham.njsscan.headers.header_cookie.cookie_session_no_domain",
    "ajinabraham.njsscan.headers.header_cookie.cookie_session_no_path",
    "ajinabraham.njsscan.headers.header_cookie.cookie_session_no_maxage",
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
    # --exclude-rule matches the rule id EXACTLY. Pinned packs load from a file, so
    # semgrep prefixes their ids with the vendor path (app.rules.vendor.php.lang...),
    # which silently stopped every exclusion from matching — one suppressed rule came
    # back on the first pinned scan. Emit both spellings so the list keeps working
    # whether a pack is vendored or fetched live.
    _vendor_prefix = _VENDOR_DIR.strip("/\\").replace("\\", ".").replace("/", ".") + "."
    for rule in _DEFAULT_EXCLUDE_RULES + settings.semgrep_exclude_rule_list:
        args += ["--exclude-rule", rule]
        args += ["--exclude-rule", _vendor_prefix + rule]
    args.append(path)
    return args


async def run(req: ScanRequest, settings: Settings) -> EngineResult:
    """Execute Semgrep against `req.path` and return normalized findings."""
    if not binary_available(settings.semgrep_bin):
        return EngineResult.failed(
            Engine.SEMGREP, Pillar.SECURITY,
            "semgrep binary not found on PATH", scan_id=req.scan_id,
        )

    # Resolve languages/types: trust caller-provided values, else detect. Detection
    # runs REGARDLESS (N2) because per-language LOC drives the coverage report, and
    # the orchestrator always passes languages -- so gating the walk on them being
    # absent meant coverage was never measured on a real scan.
    detection = language_detector.detect(req.path)
    languages = req.languages or detection.languages
    project_types = req.project_types or detection.project_types

    # Per-language SAST coverage. A repo whose code is mostly in languages we cover
    # thinly produces few findings, and few findings read as clean -- so coverage
    # travels with the result and can withdraw the score (utils/rule_coverage.py).
    coverage = rule_coverage.summarise(detection.language_code_lines, detection.unreadable_files)
    if coverage and not coverage["confident"]:
        log.info("semgrep.coverage_not_confident", strong_fraction=coverage["strong_fraction"],
                 summary=coverage["summary"])

    thirdparty_configs = _select_configs(settings, languages, project_types)
    custom_dir = _custom_rules_dir()

    # Teach the PHP XSS taint rule about the project's own HTML-escaping wrappers
    # (e.g. a sanitize() helper) so it doesn't false-positive on escaped output.
    # Uses a per-scan augmented copy of the taint rules; cleaned up below.
    aug_taint_dir = _augmented_taint_dir(req.path, custom_dir) if custom_dir else None
    if aug_taint_dir:
        custom_dir = aug_taint_dir

    # Per-project custom rules (already validated at upload) live for the duration
    # of this scan in a temp dir added on top of the third-party + Aegis packs.
    project_rules_dir = _write_project_rules(req.custom_rules)
    if project_rules_dir:
        thirdparty_configs = thirdparty_configs + [project_rules_dir]

    iac_dir = _bundled_rules_dir(_IAC_RULES_DIR)
    cicd_dir = _bundled_rules_dir(_CICD_RULES_DIR)
    quality_dir = _bundled_rules_dir(_QUALITY_RULES_DIR)
    bundled = (([custom_dir] if custom_dir else [])
               + ([iac_dir] if iac_dir else []) + ([cicd_dir] if cicd_dir else [])
               + ([quality_dir] if quality_dir else []))
    configs = _local_configs_only(thirdparty_configs + bundled)
    if not configs:
        # Never invoke semgrep with no --config: its default is `--config auto`,
        # which downloads rules from the Semgrep registry. A scan with no rule set
        # at all is a broken image, and must say so rather than fetch.
        return EngineResult.failed(
            Engine.SEMGREP, Pillar.SECURITY,
            "no local rule packs found (rules/ missing from the image?)", scan_id=req.scan_id,
        )
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
    used_configs = configs  # the config set whose result we keep (lifecycle evidence)

    # A hard error (rc >= 2) after including the custom rulesets must not lose the
    # entire SAST run. Log it and retry with the pinned third-party packs only: a
    # broken custom rule degrades to that coverage rather than dropping all findings.
    # A genuine semgrep failure then still surfaces below (as a degraded engine).
    custom_applied = custom_dir is not None
    degraded = False
    degraded_reason: str | None = None
    coverage_lost: str | None = None
    if (custom_applied and thirdparty_configs and not result.timed_out
            and result.returncode not in (0, 1)):
        log.warning(
            "semgrep.custom_rules_failed_retrying",
            error=normalizer.truncate(result.stderr, 1000),
        )
        custom_applied = False
        # DEGRADED, not clean: the third-party pack still ran, but the Aegis packs
        # (taint, AI-code taint, IaC, reliability bug pack) did NOT. Surface it — do
        # not report a successful SAST as if it had full coverage.
        degraded = True
        degraded_reason = "Aegis rule packs failed to load; retried with the pinned third-party pack only"
        coverage_lost = "Aegis custom taint, AI-code taint, IaC, and reliability bug-pack rules"
        result = await _semgrep(thirdparty_configs)
        used_configs = thirdparty_configs

    if result.timed_out:
        # Carry excluded_bundled even on timeout: the exclusion still APPLIED, and
        # seeing "N files excluded, still timed out" is the diagnostic that the
        # remaining cost is elsewhere (e.g. a large PHP/TS source tree, not bundles).
        failed = EngineResult.failed(
            Engine.SEMGREP, Pillar.SECURITY,
            f"semgrep timed out after {settings.semgrep_timeout_seconds}s",
            scan_id=req.scan_id, duration_seconds=result.duration_seconds,
        )
        failed.excluded_bundled = excluded_bundled
        failed.security_coverage = coverage
        return failed

    if result.returncode not in (0, 1):
        failed = EngineResult.failed(
            Engine.SEMGREP, Pillar.SECURITY,
            normalizer.truncate(result.stderr, 2000) or "semgrep failed",
            scan_id=req.scan_id, duration_seconds=result.duration_seconds,
        )
        failed.excluded_bundled = excluded_bundled
        failed.security_coverage = coverage
        return failed

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
        rules_executed=sorted(set().union(*(_rule_ids_in(c) for c in used_configs))),
        rules_shipped=_shipped_rule_ids(),
        security_coverage=coverage,
        degraded=degraded,
        degraded_reason=degraded_reason,
        coverage_lost=coverage_lost,
        filtered_secrets={k: v for k, v in filtered_secrets.items() if v} or None,
        excluded_bundled=excluded_bundled,
    )


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

        check_id = _canonical_check_id(item.get("check_id", "unknown-rule"))
        rule_short = check_id.rsplit(".", 1)[-1]

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
        # Normalize both to their stable rule id; keep third-party ids canonical.
        is_project = "aegis-project-rules-" in check_id
        is_aegis = rule_short.startswith("aegis-")
        rule_id = rule_short if (is_project or is_aegis) else check_id
        ruleset = (
            "project-custom" if is_project
            else "aegis-custom" if is_aegis
            else "third-party"  # the pinned njsscan pack (N1: no registry rules ship)
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
