"""Compliance report generation.

Maps Aegis findings to compliance-framework controls (via CWE / OWASP category)
and renders an auditor-facing report: executive summary, per-control findings,
remediation timeline, coverage, and a legal disclaimer. HTML always; PDF when
weasyprint is available.

Usage:
    python -m compliance.report --framework soc2 --findings scan.json --out report.html
"""
from __future__ import annotations

import argparse
import datetime as _dt
import html
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Framework mapping YAMLs ship next to this module (…/compliance/frameworks) so
# they resolve identically in the repo checkout and inside the scanner container.
# (Phase 2G: the old parents[3] path crashed in /app; the files weren't shipped.)
FRAMEWORK_DIR = Path(__file__).resolve().parent / "frameworks"

# Remediation SLAs by severity (days) — drives the remediation timeline.
SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": 365}

_OWASP_RE = re.compile(r"A\d{2}:20\d{2}", re.IGNORECASE)


def _owasp_key(value: str | None) -> str | None:
    if not value:
        return None
    m = _OWASP_RE.search(value)
    return m.group(0).upper() if m else None


def _cwe_key(value: str | None) -> str | None:
    if not value:
        return None
    m = re.search(r"CWE-\d+", value, re.IGNORECASE)
    return m.group(0).upper() if m else None


@dataclass
class ControlResult:
    id: str
    name: str
    in_scope: bool
    findings: list[dict] = field(default_factory=list)
    # J1: a control can be in the framework and genuinely in scope for an audit
    # while being something a repository scan cannot evidence either way (runtime
    # monitoring, change-approval workflow, patch installation). Reporting those
    # as "passing" claims an assurance we never produced, so they are called out
    # and excluded from the score entirely.
    assessable: bool = True
    not_assessed_reason: str = ""
    # J3: findings that were open against this control and are now proven fixed by
    # a later scan. They are evidence FOR the control, never against it, so they
    # are kept separate from `findings` and never touch `status`.
    remediated: list[dict] = field(default_factory=list)

    @property
    def status(self) -> str:
        if not self.in_scope:
            return "requires-external-evidence"
        if not self.assessable:
            return "not-assessed"
        open_ = [f for f in self.findings if _is_open(f)]
        # "no-findings", not "passing": we found no failing evidence, which is
        # not the same as having verified the control operates. The wording
        # matters because this document is read by auditors.
        return "needs-attention" if open_ else "no-findings"

    @property
    def open_count(self) -> int:
        return sum(1 for f in self.findings if _is_open(f))


def _is_open(f: dict) -> bool:
    return not (f.get("is_false_positive") or f.get("is_suppressed"))


def _is_generated_output(f: dict) -> bool:
    """True for findings inside generated / pre-rendered build output (deploy
    snapshots, bundles, minified files). These are build artifacts, not the org's
    hand-written code or its declared dependencies, so they are excluded from the
    compliance grade — otherwise hundreds of near-identical findings in a static
    export (e.g. a `netlify-static/` snapshot) drown the real controls. Vendored-
    library findings (dependency dirs / CVEs) are NOT excluded here — only build
    output is."""
    meta = f.get("metadata") or {}
    if meta.get("code_ownership") != "third_party":
        return False
    reason = str(meta.get("ownership_reason") or "").lower()
    return reason.startswith("build/bundled output") or "minified/bundled" in reason


def load_framework(name: str) -> dict:
    path = name if os.path.sep in name else str(FRAMEWORK_DIR / f"{name}.yaml")
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def map_findings(findings: list[dict], framework: dict,
                 remediated: list[dict] | None = None) -> list[ControlResult]:
    """Attribute each finding to AT MOST ONE control.

    Before J1 this attributed a finding to *every* control whose evidence matched,
    so one dependency CVE could fail two controls at once and inflate both the
    failure count and the remediation timeline."""
    results: list[ControlResult] = []
    for ctrl in framework.get("controls", []):
        scope = ctrl.get("aegis_scope")
        in_scope = scope != "out-of-scope"
        assessable = scope != "not-assessed"
        cr = ControlResult(
            id=str(ctrl["id"]), name=ctrl["name"], in_scope=in_scope,
            assessable=assessable,
            not_assessed_reason=str(ctrl.get("not_assessed_reason") or "").strip(),
        )
        results.append(cr)

    # ── single attribution ───────────────────────────────────────────────────
    # Each finding is attributed to AT MOST ONE control. Evidence keys are already
    # mutually exclusive within a framework, but a finding carries both a CWE and
    # an OWASP category and those can point at different controls, so a
    # precedence rule is still needed (J1).
    by_cwe: dict[str, ControlResult] = {}
    by_owasp: dict[str, ControlResult] = {}
    for cr, ctrl in zip(results, framework.get("controls", [])):
        if not (cr.in_scope and cr.assessable):
            continue
        ev = ctrl.get("evidence", {}) or {}
        for c in ev.get("cwe", []):
            by_cwe.setdefault(c.upper(), cr)
        for o in ev.get("owasp", []):
            by_owasp.setdefault(o.upper(), cr)

    for f in findings:
        if _is_generated_output(f):
            continue  # build artifacts don't drive the compliance grade
        ck, ok = _cwe_key(f.get("cwe_id")), _owasp_key(f.get("owasp_category"))
        # A dependency vulnerability is evidence about *vulnerability management*,
        # not about how the customer writes code. Such a finding carries the
        # upstream bug's CWE (prototype pollution, say), which would otherwise
        # attribute a third party's defect to the customer's secure-coding
        # control. The OWASP category (A06 Vulnerable and Outdated Components) is
        # the one that describes the customer's actual obligation, so for anything
        # carrying a CVE the category wins.
        if f.get("cve_id"):
            target = by_owasp.get(ok) or by_cwe.get(ck)
        else:
            # Otherwise the CWE is the more specific statement of the weakness.
            target = by_cwe.get(ck) or by_owasp.get(ok)
        if target is not None:
            target.findings.append(f)

    # Remediated findings are attributed by the same precedence rule, into a
    # separate bucket. A control's status is driven by OPEN findings only: a
    # weakness that was fixed is not a failure, it is the proof an auditor wants.
    for f in remediated or []:
        ck, ok = _cwe_key(f.get("cwe_id")), _owasp_key(f.get("owasp_category"))
        if f.get("cve_id"):
            target = by_owasp.get(ok) or by_cwe.get(ck)
        else:
            target = by_cwe.get(ck) or by_owasp.get(ok)
        if target is not None:
            target.remediated.append(f)
    return results


def attribution_conflicts(framework: dict) -> dict[str, list[str]]:
    """Evidence keys claimed by more than one assessable control.

    Compliance evidence must attribute a finding to exactly one control. When two
    controls share a CWE or an OWASP category, a single finding fails both, which
    inflates the failure count and the remediation timeline at the same time --
    the defect F1 found in SOC 2 CC6.8/CC7.1 (1,975 double-attributions across our
    corpus) and the largest of which was PCI 6.3.1/6.3.3 (1,942).

    Returns {evidence_key: [control ids]} for every key claimed twice. An empty
    dict is the invariant; tests/test_compliance_mappings.py enforces it for every
    framework we ship."""
    seen: dict[str, list[str]] = {}
    for ctrl in framework.get("controls", []):
        if ctrl.get("aegis_scope") in ("out-of-scope", "not-assessed"):
            continue
        ev = ctrl.get("evidence", {}) or {}
        for key in [c.upper() for c in ev.get("cwe", [])] + [o.upper() for o in ev.get("owasp", [])]:
            seen.setdefault(key, []).append(str(ctrl["id"]))
    return {k: v for k, v in seen.items() if len(v) > 1}


def build_report(scan_meta: dict, findings: list[dict], framework: dict,
                 remediated: list[dict] | None = None,
                 remediation_available: bool = True) -> dict:
    controls = map_findings(findings, framework, remediated)
    in_scope = [c for c in controls if c.in_scope]
    assessed = [c for c in in_scope if c.assessable]
    needs = [c for c in assessed if c.status == "needs-attention"]
    passing = [c for c in assessed if c.status == "no-findings"]
    not_assessed = [c for c in in_scope if not c.assessable]
    external = [c for c in controls if not c.in_scope]

    # Remediation timeline: worst finding severity per failing control → SLA.
    today = _dt.date.today()
    timeline = []
    for c in needs:
        worst = min((f.get("severity", "medium") for f in c.findings if _is_open(f)),
                    key=lambda s: list(SLA_DAYS).index(s) if s in SLA_DAYS else 99, default="medium")
        due = today + _dt.timedelta(days=SLA_DAYS.get(worst, 90))
        timeline.append({"control": c.id, "worst_severity": worst,
                         "open_findings": c.open_count, "due_by": due.isoformat()})
    timeline.sort(key=lambda t: t["due_by"])

    # Coverage is the share of the framework we can speak to at all, and the
    # score is computed over ASSESSED controls only. Counting a control we cannot
    # evidence as a pass is how an automated report overstates assurance (J1).
    coverage = round(100 * len(assessed) / len(controls)) if controls else 0
    score = round(100 * len(passing) / len(assessed)) if assessed else 0
    return {
        "framework": framework.get("framework"),
        "version": framework.get("version"),
        "scope": framework.get("scope") or {},
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "scan": scan_meta,
        "summary": {
            "controls_total": len(controls),
            "controls_in_scope": len(in_scope),
            "controls_assessed": len(assessed),
            "controls_no_findings": len(passing),
            "controls_needs_attention": len(needs),
            "controls_not_assessed": len(not_assessed),
            "controls_external": len(external),
            "coverage_pct": coverage,
            "compliance_score_pct": score,
            # J3: the closed half of the ledger. An auditor reads open-vs-closed;
            # a report that can only show the open half is a snapshot, not evidence.
            "findings_remediated": sum(len(c.remediated) for c in controls),
            "controls_with_remediation": sum(1 for c in controls if c.remediated),
            "remediation_available": bool(remediation_available),
        },
        "controls": controls,
        "timeline": timeline,
        "remediation_available": bool(remediation_available),
    }


DISCLAIMER = (
    "This report is automated technical evidence produced by static analysis. It "
    "covers code/configuration controls only and is NOT a certification or a "
    "substitute for assessment by a qualified auditor. Control scope and evidence "
    "must be independently validated before any formal attestation. "
    "\"No findings\" means this scan produced no failing evidence for that control "
    "-- it is not a statement that the control was tested and operates effectively. "
    "Controls marked \"not assessed\" are in scope for the framework but cannot be "
    "evidenced by scanning a repository, and are excluded from the percentage above "
    "rather than counted as passes. "
    "A control's status reflects OPEN findings only: a vulnerability that was found "
    "and later proven fixed appears under Remediation evidence and never counts "
    "against the control."
)


_CLAIM_TEXT = {
    "headline": ("This is one of the two frameworks Aegis assesses most directly.",
                 "#065f46", "#ecfdf5", "#6ee7b7"),
    "supporting-evidence": (
        "SUPPORTING EVIDENCE ONLY. Aegis assesses a small technical subset of this "
        "framework. This report is an input to an assessment, not coverage of the "
        "standard, and must not be presented as either.",
        "#7c2d12", "#fff7ed", "#fdba74"),
}


def _render_scope(report: dict) -> str:
    sc = report.get("scope") or {}
    if not sc:
        return ""
    claim = str(sc.get("claim") or "supporting-evidence")
    text, fg, bg, border = _CLAIM_TEXT.get(claim, _CLAIM_TEXT["supporting-evidence"])
    su = report["summary"]
    verif = str(sc.get("verification") or "")
    verif_text = {
        "normative-text": "Control text verified against the published normative standard.",
        "numbering-and-titles": (
            "Control numbering and titles verified against the published list; the full "
            "normative text is behind a paywall and was NOT read."),
    }.get(verif, "")
    return (
        f'<div style="margin:1rem 0;padding:10px;background:{bg};border:1px solid {border};color:{fg}">'
        f'<b>Scope.</b> {html.escape(text)}<br>'
        f'This standard has <b>{html.escape(str(sc.get("standard_total","?")))}</b>. '
        f'Aegis assesses <b>{su["controls_assessed"]}</b> of them; '
        f'{su["controls_not_assessed"]} are in scope for the framework but cannot be evidenced '
        f'by scanning a repository, and {su["controls_external"]} require external evidence.'
        + (f'<br>{html.escape(str(sc.get("note")))}' if sc.get("note") else "")
        + (f'<br><i>{html.escape(verif_text)}</i>' if verif_text else "")
        + '</div>'
    )


def _fmt_date(value: object) -> str:
    text = str(value or "")
    return text[:10] if len(text) >= 10 else text


def _render_remediation(report: dict) -> str:
    """The closed half of the ledger.

    An auditor does not verify every guideline in a standard; what they consume is
    open versus closed -- this vulnerability appeared, it was remediated, and a
    later scan proves it closed. Before J3 the compliance report could not express
    that at all: a resolved finding is absent from the current scan, so a
    point-in-time findings query only ever produced the open half."""
    if not report.get("remediation_available", True):
        return ('<p class="muted"><b>Remediation history unavailable.</b> The finding-lifecycle '
                'store could not be read for this project, so this section is empty because the '
                'history could not be retrieved &mdash; not because nothing was fixed.</p>')
    rows = []
    for c in report["controls"]:
        for f in c.remediated:
            opened, closed = _fmt_date(f.get("first_seen_at")), _fmt_date(f.get("resolved_at"))
            rows.append(
                f"<tr><td><b>{html.escape(c.id)}</b></td>"
                f"<td>[{html.escape(str(f.get('severity','?')))}] "
                f"{html.escape(str(f.get('title') or f.get('rule_id') or ''))[:160]}</td>"
                f"<td><code>{html.escape(str(f.get('file_path','')))}</code></td>"
                f"<td>{html.escape(opened)}</td><td>{html.escape(closed)}</td>"
                f"<td><code>{html.escape(str(f.get('resolved_scan_id',''))[:8])}</code></td></tr>"
            )
    if not rows:
        return ('<p class="muted">No findings have been observed opening and then closing on this '
                'project yet. This is expected on a first scan: remediation evidence accumulates '
                'as findings are fixed and later scans confirm they are gone.</p>')
    su = report["summary"]
    return (
        f'<p><b>{su["findings_remediated"]}</b> finding(s) across '
        f'<b>{su["controls_with_remediation"]}</b> control(s) were open on this project and are '
        f'now absent from a later scan. Each row is a closed item: what it was, when it was first '
        f'seen, and the scan that proved it gone.</p>'
        '<table><tr><th>Control</th><th>Finding</th><th>Location</th><th>First seen</th>'
        '<th>Confirmed fixed</th><th>By scan</th></tr>' + "".join(rows) + '</table>'
    )


def render_html(report: dict) -> str:
    s = report["summary"]
    scope_html = _render_scope(report)
    remediation_html = _render_remediation(report)
    rows = []
    for c in report["controls"]:
        badge = {"no-findings": "#16a34a", "needs-attention": "#dc2626",
                 "not-assessed": "#b45309",
                 "requires-external-evidence": "#6b7280"}[c.status]
        fnd = "".join(
            f"<li>[{html.escape(f.get('severity','?'))}] {html.escape(f.get('title', f.get('rule_id','')))} "
            f"<code>{html.escape(f.get('file_path',''))}</code></li>"
            for f in c.findings if _is_open(f)
        )
        detail = "<ul>" + fnd + "</ul>" if fnd else "&mdash;"
        if c.status == "not-assessed" and c.not_assessed_reason:
            detail = f"<i>{html.escape(c.not_assessed_reason)}</i>"
        rows.append(
            f"<tr><td><b>{html.escape(c.id)}</b><br>{html.escape(c.name)}</td>"
            f"<td style='color:{badge}'><b>{c.status.replace('-',' ')}</b></td>"
            f"<td>{c.open_count if c.assessable else '&mdash;'}</td>"
            f"<td>{detail}</td></tr>"
        )
    tl = "".join(
        f"<tr><td>{html.escape(t['control'])}</td><td>{t['worst_severity']}</td>"
        f"<td>{t['open_findings']}</td><td>{t['due_by']}</td></tr>"
        for t in report["timeline"]
    )
    return f"""<!doctype html><html><head><meta charset="utf-8">
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#111;margin:2rem;font-size:13px}}
 h1{{margin:0}} .muted{{color:#6b7280}} table{{border-collapse:collapse;width:100%;margin:1rem 0}}
 td,th{{border:1px solid #e5e7eb;padding:6px 8px;text-align:left;vertical-align:top}}
 th{{background:#f9fafb}} .kpi{{display:inline-block;margin-right:1.5rem}}
 .kpi b{{font-size:1.6rem;display:block}} code{{background:#f3f4f6;padding:1px 3px}}
 .disc{{margin-top:2rem;padding:10px;background:#fffbeb;border:1px solid #fcd34d;font-size:11px}}
</style></head><body>
<h1>{html.escape(str(report['framework']))} Compliance Report</h1>
<p class="muted">{html.escape(str(report['version']))} &middot; generated {report['generated_at']}
 &middot; project {html.escape(str(report['scan'].get('project','')))} &middot; grade {html.escape(str(report['scan'].get('grade','')))}</p>
<div>
 <span class="kpi"><b>{s['compliance_score_pct']}%</b>assessed controls with no findings</span>
 <span class="kpi"><b>{s['controls_needs_attention']}</b>need attention</span>
 <span class="kpi"><b>{s['controls_no_findings']}</b>no findings</span>
 <span class="kpi"><b>{s['findings_remediated']}</b>findings proven closed</span>
 <span class="kpi"><b>{s['controls_not_assessed']}</b>not assessed</span>
 <span class="kpi"><b>{s['controls_external']}</b>external evidence</span>
 <span class="kpi"><b>{s['coverage_pct']}%</b>of the framework assessed</span>
</div>
{scope_html}
<h2>Findings by control</h2>
<table><tr><th>Control</th><th>Status</th><th>Open</th><th>Open findings</th></tr>{''.join(rows)}</table>
<h2>Remediation evidence &mdash; vulnerabilities proven closed</h2>
{remediation_html}
<h2>Remediation timeline &mdash; open findings, by SLA</h2>
{('<table><tr><th>Control</th><th>Worst severity</th><th>Open</th><th>Due by (SLA)</th></tr>'+tl+'</table>') if tl else '<p class="muted">No open findings against in-scope controls.</p>'}
<div class="disc"><b>Disclaimer.</b> {html.escape(DISCLAIMER)}</div>
</body></html>"""


def render_pdf(html_str: str) -> bytes | None:
    try:
        from weasyprint import HTML  # optional heavy dep
    except Exception:
        return None
    return HTML(string=html_str).write_pdf()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--framework", required=True, help="name (soc2) or path to yaml")
    ap.add_argument("--findings", required=True, help="JSON: {scan:{...}, findings:[...]}")
    ap.add_argument("--out", required=True, help="output .html or .pdf")
    args = ap.parse_args()

    data = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    fw = load_framework(args.framework)
    report = build_report(data.get("scan", {}), data.get("findings", []), fw)
    html_str = render_html(report)
    if args.out.endswith(".pdf"):
        pdf = render_pdf(html_str)
        if pdf is None:
            raise SystemExit("weasyprint not installed; render .html instead")
        Path(args.out).write_bytes(pdf)
    else:
        Path(args.out).write_text(html_str, encoding="utf-8")
    su = report["summary"]
    print(f"wrote {args.out} — {su['compliance_score_pct']}% of assessed controls have no findings "
          f"({su['controls_needs_attention']} need attention, {su['controls_not_assessed']} not assessed)")


if __name__ == "__main__":
    main()
