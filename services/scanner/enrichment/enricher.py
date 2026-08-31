"""Finding enrichment — turns raw rule output into context-rich, actionable
findings (title_human / impact / risk_level / remediation / effort /
context_metadata).

A template (enrichment/rule_templates.yaml) is matched per finding by a derived
key. Where no template exists (e.g. a registry Semgrep rule) we fall back to the
finding's own rule metadata so a field is never left empty. Engine-specific
enrichment (CVSS-vector → plain English for CVEs) is layered on top.
"""
from __future__ import annotations

import os

from logging_config import get_logger
from models.scan_result import Finding

log = get_logger("enrichment")

_TEMPLATES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rule_templates.yaml")
_templates: dict | None = None

_RISK_BY_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "informational",
}

# Effort fallback when a template does not specify one.
_EFFORT_BY_ENGINE = {
    "gitleaks": "quick",
    "trivy": "quick",
    "quality": "moderate",
    "semgrep": "moderate",
    "codeql": "moderate",
    "joern": "moderate",
}

# CVSS v3 vector component dictionaries.
_CVSS = {
    "AV": ("attack_vector", {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}),
    "AC": ("attack_complexity", {"L": "Low", "H": "High"}),
    "PR": ("privileges_required", {"N": "None", "L": "Low", "H": "High"}),
    "UI": ("user_interaction", {"N": "None", "R": "Required"}),
    "S": ("scope", {"U": "Unchanged", "C": "Changed"}),
    "C": ("confidentiality_impact", {"H": "High", "L": "Low", "N": "None"}),
    "I": ("integrity_impact", {"H": "High", "L": "Low", "N": "None"}),
    "A": ("availability_impact", {"H": "High", "L": "Low", "N": "None"}),
}


class _SafeDict(dict):
    def __missing__(self, key):  # noqa: D401 — leave unknown placeholders visible-but-safe
        return "?"


def _load() -> dict:
    global _templates
    if _templates is None:
        try:
            import yaml

            with open(_TEMPLATES_PATH, encoding="utf-8") as fh:
                _templates = yaml.safe_load(fh) or {}
        except Exception as exc:  # noqa: BLE001 — enrichment must never break a scan
            log.warning("enrichment.templates_load_failed", error=str(exc))
            _templates = {}
    return _templates


def enrich_all(findings: list[Finding], root: str = "", stats: dict | None = None) -> list[Finding]:
    """Enrich every finding in place; returns the same list for convenience.

    `root` is the scan's repo root — when given, every finding gets an inline
    code_snippet (P1c) and a stable lifecycle fingerprint (P1a). Both are
    best-effort and never fail a scan.

    `stats`, if given, is updated with the secret-filter counts (see
    secret_context.annotate) — {"placeholder": n, "expired_jwt": n} — so the engine
    can surface "N placeholder / M expired-JWT matches filtered" on its result."""
    templates = _load()
    vendored = _vendored_asset_paths(findings, root)
    for f in findings:
        try:
            _enrich(f, templates)
        except Exception as exc:  # noqa: BLE001 — one bad finding must not abort
            log.debug("enrichment.finding_failed", rule_id=f.rule_id, error=str(exc))
            _fallback_only(f)
        _tag_ownership(f, vendored)
        _classify_issue_type(f)
    _attach_snippets(findings, root)
    # Secret precision (S1/P1): SUPPRESS placeholder + expired-JWT findings (they are
    # definitively not credentials), KEEP test-fixture-path secrets at LOW + tagged.
    # Runs after snippets so the bcrypt fallback value is populated. A live-format
    # provider credential is left untouched. The suppression counts flow to `stats`.
    try:
        from enrichment import secret_context

        filtered = secret_context.annotate(findings)
        if stats is not None and filtered:
            for k, v in filtered.items():
                stats[k] = stats.get(k, 0) + v
    except Exception as exc:  # noqa: BLE001 — a tagging pass must never fail a scan
        log.debug("enrichment.secret_context_failed", error=str(exc))
    _score_false_positives(findings)
    return findings


# Quality-pillar rules that represent a genuine reliability *bug* (SonarQube
# "Bug"), as opposed to a maintainability smell. Loaded ONCE from the bundled
# rules/quality/*.yaml pack (single source of truth — never hand-maintained here)
# so a finding whose rule declares metadata.issue_type=bug is tagged issue_type=
# "bug" and drives the Reliability rating. Precision-first: when a quality rule is
# not in this set, it stays a code_smell.
def _load_quality_bug_rules() -> set[str]:
    ids: set[str] = set()
    rules_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "quality"
    )
    try:
        import yaml

        for name in os.listdir(rules_dir):
            # Only Semgrep bug packs here — ruff_map.yaml has a different schema
            # (a dict of ruff codes) and is loaded via ruff_engine.bug_rule_ids().
            if not name.endswith((".yaml", ".yml")) or name == "ruff_map.yaml":
                continue
            try:
                with open(os.path.join(rules_dir, name), encoding="utf-8") as fh:
                    doc = yaml.safe_load(fh) or {}
                for rule in doc.get("rules", []) or []:
                    if not isinstance(rule, dict):
                        continue
                    meta = rule.get("metadata") or {}
                    if meta.get("issue_type") == "bug" and rule.get("id"):
                        ids.add(str(rule["id"]))
            except Exception as exc:  # noqa: BLE001 — one bad pack must not drop the rest
                log.debug("enrichment.bug_pack_load_failed", pack=name, error=str(exc))
    except Exception as exc:  # noqa: BLE001 — a missing/broken pack must not break scans
        log.debug("enrichment.bug_rule_load_failed", error=str(exc))
    # Ruff (Q3) bug rules share this single source: their aegis_rule_ids (issue_
    # type=bug in ruff_map.yaml) must be tagged issue_type=bug too — including the
    # dedup ids Ruff now owns (mutable-default, is-literal).
    try:
        from engines import ruff_engine

        ids |= ruff_engine.bug_rule_ids()
    except Exception as exc:  # noqa: BLE001
        log.debug("enrichment.ruff_bug_rule_load_failed", error=str(exc))
    return ids


_QUALITY_BUG_RULES: set[str] = _load_quality_bug_rules()


def _classify_issue_type(f: Finding) -> None:
    """SonarQube-style issue type (P2c): bug | vulnerability | code_smell.

    - Security-pillar findings (SAST / SCA / secrets) are vulnerabilities.
    - Quality-pillar findings are code smells (maintainability/complexity/
      duplication/style), except the few crash/logic-risk rules mapped to bug.
    - Deployment / other findings are left untyped.
    Precision-first: unsure between bug and smell -> smell.
    """
    try:
        pillar = f.pillar.value if hasattr(f.pillar, "value") else str(f.pillar)
        if pillar == "security":
            f.issue_type = "vulnerability"
        elif pillar == "quality":
            f.issue_type = "bug" if (f.rule_id or "") in _QUALITY_BUG_RULES else "code_smell"
    except Exception as exc:  # noqa: BLE001 — classification must never break a scan
        log.debug("enrichment.issue_type_failed", rule_id=getattr(f, "rule_id", "?"), error=str(exc))


def _attach_snippets(findings: list[Finding], root: str) -> None:
    """Attach inline code snippet + stable fingerprint to every finding (P1a/P1c).
    Best-effort: a read failure leaves the snippet empty and the fingerprint on a
    still-deterministic rule+file basis."""
    try:
        from utils import snippet

        snippet.attach(findings, root)
    except Exception as exc:  # noqa: BLE001 — must never break a scan
        log.debug("enrichment.snippet_failed", error=str(exc))


def _norm_path(p: str | None) -> str:
    return (p or "").replace("\\", "/")


def _vendored_asset_paths(findings: list[Finding], root: str) -> set[str]:
    """File paths that are vendored third-party libraries — so EVERY finding on them
    (quality complexity, semgrep, …), not just the SCA CVE, is tagged third-party.

    Two high-confidence signals:
      1. The SCA engine fingerprinted the file as a known library copy (its CVE
         findings carry detected_via=fingerprint / vendored on that exact path).
      2. The file is a JS/CSS build that opens with a distributed-library banner
         (e.g. an unminified assets/js/jquery-1.12.3.js or assets/js/bootstrap.js
         that neither sits in a vendored dir nor ends in .min).

    Without this, a repo that copies jQuery/Bootstrap into assets/js gets jQuery's
    own internal cyclomatic complexity and Sizzle's RegExp use reported as the
    user's APP bugs — noise a mature tool (CodeQL) never surfaces."""
    paths: set[str] = set()
    for f in findings:
        meta = f.metadata if isinstance(f.metadata, dict) else {}
        if (meta.get("detected_via") == "fingerprint" or meta.get("vendored")) and f.file_path:
            paths.add(_norm_path(f.file_path))
    if root:
        try:
            from utils import code_ownership

            seen: set[str] = set()
            for f in findings:
                rel = _norm_path(f.file_path)
                if not rel or rel in seen:
                    continue
                seen.add(rel)
                if rel in paths:
                    continue
                if code_ownership.is_vendored_asset(os.path.join(root, rel)):
                    paths.add(rel)
        except Exception as exc:  # noqa: BLE001 — banner scan must never break a scan
            log.debug("enrichment.vendored_scan_failed", error=str(exc))
    return paths


def _tag_ownership(f: Finding, vendored: set[str] | None = None) -> None:
    """Tag the finding with code ownership (app vs third-party/vendored), from its
    file path. Precision-first: defaults to "app" when not confident. Never raises."""
    try:
        from utils import code_ownership

        meta = f.metadata if isinstance(f.metadata, dict) else {}
        # A fingerprinted vendored library is third-party by definition — keep that,
        # don't let the path classifier (which may not recognise e.g.
        # assets/js/jquery-1.12.4.js) override it back to "app".
        if meta.get("detected_via") == "fingerprint" or meta.get("vendored"):
            meta["code_ownership"] = "third_party"
            f.metadata = meta
            return
        # Any finding on a file we identified as a vendored library (by fingerprint
        # propagation or distribution banner) is third-party — jQuery/Bootstrap's own
        # internal complexity and audit hits are not the user's app bugs.
        if vendored and _norm_path(f.file_path) in vendored:
            meta["code_ownership"] = "third_party"
            meta.setdefault("ownership_reason", "vendored third-party library (bundled build)")
            f.metadata = meta
            return
        # A dependency vulnerability (SCA CVE) lives in a third-party package — you
        # fix it by UPDATING the library, not by editing your own code — even though
        # the manifest (package-lock.json / requirements.txt / composer.lock) sits in
        # the app root. Tag it third-party so the UI/scoring treat it correctly.
        if f.cve_id and meta.get("package"):
            meta["code_ownership"] = "third_party"
            meta["ownership_reason"] = f"third-party dependency: {meta.get('package')}"
            f.metadata = meta
            return
        ownership, reason = code_ownership.classify(f.file_path)
        meta["code_ownership"] = ownership
        if reason:
            meta["ownership_reason"] = reason
        f.metadata = meta
    except Exception as exc:  # noqa: BLE001 — tagging must never break a scan
        log.debug("enrichment.ownership_failed", rule_id=getattr(f, "rule_id", "?"), error=str(exc))


def _score_false_positives(findings: list[Finding]) -> None:
    """Attach the local ML false-positive probability (advisory). Best-effort:
    if the model or its deps are unavailable, findings are simply left unscored."""
    try:
        from ml import classifier

        classifier.score_findings(findings)
    except Exception as exc:  # noqa: BLE001 — ML must never break a scan
        log.debug("enrichment.fp_scoring_skipped", error=str(exc))


def _enrich(f: Finding, templates: dict) -> None:
    tpl = _first_template(templates, _candidate_keys(f))
    ctx = _context(f)

    f.risk_level = (tpl.get("risk_level") if tpl else None) or _RISK_BY_SEVERITY.get(
        _sev(f), "low"
    )
    f.title_human = _fmt(tpl.get("title_human") if tpl else None, ctx) or _fallback_title(f)
    f.impact = _fmt(tpl.get("impact") if tpl else None, ctx) or _fallback_impact(f)
    f.remediation_action = _fmt(tpl.get("remediation_action") if tpl else None, ctx) or _fallback_remediation(f)
    f.remediation_details = _fmt(tpl.get("remediation_details") if tpl else None, ctx) or (
        f.fix_suggestion or None
    )
    f.estimated_effort = (tpl.get("estimated_effort") if tpl else None) or _EFFORT_BY_ENGINE.get(
        _engine(f), "moderate"
    )

    cm = dict(f.context_metadata or {})
    if _engine(f) == "trivy" and f.cve_id:
        cm.update(_cvss_breakdown(f))
    f.context_metadata = cm or None

    _apply_kev(f)


def _apply_kev(f: Finding) -> None:
    """If this CVE is on the CISA KEV list, make it prominent: lead the impact with
    an 'Actively exploited' marker + the date, and raise risk to critical. The raw
    kev_* fields already ride in f.metadata (set by the SCA engine)."""
    meta = f.metadata if isinstance(f.metadata, dict) else {}
    if not meta.get("kev"):
        return
    date = meta.get("kev_date_added")
    ransom = " — used in ransomware campaigns" if meta.get("kev_ransomware") else ""
    marker = f"⚠ Actively exploited in the wild (CISA KEV{f', added {date}' if date else ''}){ransom}. "
    f.impact = marker + (f.impact or "")
    # Actively-exploited vulnerabilities are top-priority regardless of CVSS band.
    f.risk_level = "critical"


def _fallback_only(f: Finding) -> None:
    f.risk_level = f.risk_level or _RISK_BY_SEVERITY.get(_sev(f), "low")
    f.title_human = f.title_human or _fallback_title(f)
    f.impact = f.impact or _fallback_impact(f)
    f.remediation_action = f.remediation_action or _fallback_remediation(f)
    f.estimated_effort = f.estimated_effort or "moderate"


# ── Template selection ────────────────────────────────────────────────────────
def _candidate_keys(f: Finding) -> list[str]:
    rid = f.rule_id or ""
    engine = _engine(f)
    keys: list[str] = []

    if rid.startswith("docker:"):
        keys.append(rid)  # deployment engine sets these directly
    if engine == "gitleaks":
        keys += [f"gitleaks:{rid.lower()}", "gitleaks:default"]
    elif engine == "trivy":
        keys.append("trivy:cve" if f.cve_id else "trivy:misconfig")
    elif engine in ("joern", "codeql") or rid.startswith("aegis-"):
        cls = _taint_class(rid)
        if cls:
            keys.append(f"taint:{cls}")
    if rid.startswith("quality/"):
        keys.append(rid)
    return keys


def _taint_class(rid: str) -> str | None:
    if rid.startswith("aegis-"):
        parts = rid.split("-", 2)  # aegis-<lang>-<class>
        return parts[2] if len(parts) == 3 else None
    if "/" in rid:  # joern/sql-injection, js/sql-injection
        return rid.split("/")[-1]
    return None


def _first_template(templates: dict, keys: list[str]) -> dict | None:
    for k in keys:
        tpl = templates.get(k)
        if isinstance(tpl, dict):
            return tpl
    return None


# ── Context + formatting ──────────────────────────────────────────────────────
def _context(f: Finding) -> dict:
    ctx: dict = {}
    if isinstance(f.metadata, dict):
        ctx.update({k: v for k, v in f.metadata.items() if v is not None})
    ctx.setdefault("cve_id", f.cve_id or "")
    ctx.setdefault("cwe_id", f.cwe_id or "")
    ctx.setdefault("file_path", f.file_path or "")
    ctx.setdefault("rule_id", f.rule_id or "")
    ctx.setdefault("fixed_version", ctx.get("fixed_version") or "the latest patched version")
    return ctx


def _fmt(template: str | None, ctx: dict) -> str | None:
    if not template:
        return None
    try:
        return template.format_map(_SafeDict(ctx)).strip()
    except Exception:  # noqa: BLE001
        return template


# ── Fallbacks (never leave empty) ─────────────────────────────────────────────
def _fallback_title(f: Finding) -> str:
    # A readable rule name beats the rule id; humanize slugs.
    if f.rule_name and f.rule_name.lower() != (f.rule_id or "").lower():
        return f.rule_name
    slug = (f.rule_id or "").split(".")[-1].split("/")[-1]
    words = slug.replace("-", " ").replace("_", " ").strip()
    return words[:1].upper() + words[1:] if words else (f.title or "Finding")


def _fallback_impact(f: Finding) -> str:
    if f.description:
        first = f.description.strip().splitlines()[0]
        if first:
            return first[:300]
    parts = []
    if f.cwe_id:
        parts.append(f.cwe_id)
    if f.owasp_category:
        parts.append(f.owasp_category)
    tag = f" ({', '.join(parts)})" if parts else ""
    return f"A {_sev(f)}-severity issue{tag} that should be reviewed and remediated."


def _fallback_remediation(f: Finding) -> str:
    for src in (f.fix_suggestion, f.description):
        if src:
            line = src.strip().splitlines()[0]
            if line:
                return line[:300]
    return f"Review this {f.rule_name or 'finding'} and apply the standard fix for its class."


# ── CVSS ──────────────────────────────────────────────────────────────────────
def _cvss_breakdown(f: Finding) -> dict:
    md = f.metadata or {}
    out: dict = {}
    score = md.get("cvss_score")
    if score is not None:
        out["cvss_score"] = score
    vector = md.get("cvss_vector")
    if isinstance(vector, str) and vector:
        out["cvss_vector"] = vector
        for part in vector.split("/"):
            if ":" not in part:
                continue
            metric, value = part.split(":", 1)
            spec = _CVSS.get(metric)
            if spec:
                field, mapping = spec
                out[field] = mapping.get(value, value)
    if md.get("package"):
        out["package"] = md.get("package")
        out["installed_version"] = md.get("installed_version")
        out["fixed_version"] = md.get("fixed_version")
    return out


def _sev(f: Finding) -> str:
    return f.severity.value if hasattr(f.severity, "value") else str(f.severity)


def _engine(f: Finding) -> str:
    return f.engine.value if hasattr(f.engine, "value") else str(f.engine)
