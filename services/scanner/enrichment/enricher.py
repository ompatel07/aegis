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


def enrich_all(findings: list[Finding]) -> list[Finding]:
    """Enrich every finding in place; returns the same list for convenience."""
    templates = _load()
    for f in findings:
        try:
            _enrich(f, templates)
        except Exception as exc:  # noqa: BLE001 — one bad finding must not abort
            log.debug("enrichment.finding_failed", rule_id=f.rule_id, error=str(exc))
            _fallback_only(f)
    _score_false_positives(findings)
    return findings


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
