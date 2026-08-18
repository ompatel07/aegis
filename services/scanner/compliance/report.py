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

    @property
    def status(self) -> str:
        if not self.in_scope:
            return "requires-external-evidence"
        open_ = [f for f in self.findings if _is_open(f)]
        return "needs-attention" if open_ else "passing"

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


def map_findings(findings: list[dict], framework: dict) -> list[ControlResult]:
    """Attribute each finding to every control whose evidence matches its
    CWE or OWASP category."""
    results: list[ControlResult] = []
    for ctrl in framework.get("controls", []):
        in_scope = ctrl.get("aegis_scope") != "out-of-scope"
        cr = ControlResult(id=str(ctrl["id"]), name=ctrl["name"], in_scope=in_scope)
        ev = ctrl.get("evidence", {}) or {}
        cwes = {c.upper() for c in ev.get("cwe", [])}
        owasps = {o.upper() for o in ev.get("owasp", [])}
        if in_scope:
            for f in findings:
                if _is_generated_output(f):
                    continue  # build artifacts don't drive the compliance grade
                if (_cwe_key(f.get("cwe_id")) in cwes) or (_owasp_key(f.get("owasp_category")) in owasps):
                    cr.findings.append(f)
        results.append(cr)
    return results


def build_report(scan_meta: dict, findings: list[dict], framework: dict) -> dict:
    controls = map_findings(findings, framework)
    in_scope = [c for c in controls if c.in_scope]
    needs = [c for c in in_scope if c.status == "needs-attention"]
    passing = [c for c in in_scope if c.status == "passing"]
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

    coverage = round(100 * len(in_scope) / len(controls)) if controls else 0
    score = round(100 * len(passing) / len(in_scope)) if in_scope else 0
    return {
        "framework": framework.get("framework"),
        "version": framework.get("version"),
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "scan": scan_meta,
        "summary": {
            "controls_total": len(controls),
            "controls_in_scope": len(in_scope),
            "controls_passing": len(passing),
            "controls_needs_attention": len(needs),
            "controls_external": len(external),
            "coverage_pct": coverage,
            "compliance_score_pct": score,
        },
        "controls": controls,
        "timeline": timeline,
    }


DISCLAIMER = (
    "This report is automated technical evidence produced by static analysis. It "
    "covers code/configuration controls only and is NOT a certification or a "
    "substitute for assessment by a qualified auditor. Control scope and evidence "
    "must be independently validated before any formal attestation."
)


def render_html(report: dict) -> str:
    s = report["summary"]
    rows = []
    for c in report["controls"]:
        badge = {"passing": "#16a34a", "needs-attention": "#dc2626",
                 "requires-external-evidence": "#6b7280"}[c.status]
        fnd = "".join(
            f"<li>[{html.escape(f.get('severity','?'))}] {html.escape(f.get('title', f.get('rule_id','')))} "
            f"<code>{html.escape(f.get('file_path',''))}</code></li>"
            for f in c.findings if _is_open(f)
        )
        rows.append(
            f"<tr><td><b>{html.escape(c.id)}</b><br>{html.escape(c.name)}</td>"
            f"<td style='color:{badge}'><b>{c.status.replace('-',' ')}</b></td>"
            f"<td>{c.open_count}</td>"
            f"<td>{'<ul>'+fnd+'</ul>' if fnd else '&mdash;'}</td></tr>"
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
 <span class="kpi"><b>{s['compliance_score_pct']}%</b>in-scope passing</span>
 <span class="kpi"><b>{s['controls_needs_attention']}</b>need attention</span>
 <span class="kpi"><b>{s['controls_passing']}</b>passing</span>
 <span class="kpi"><b>{s['controls_external']}</b>external evidence</span>
 <span class="kpi"><b>{s['coverage_pct']}%</b>control coverage</span>
</div>
<h2>Findings by control</h2>
<table><tr><th>Control</th><th>Status</th><th>Open</th><th>Open findings</th></tr>{''.join(rows)}</table>
<h2>Remediation timeline</h2>
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
    print(f"wrote {args.out} — score {report['summary']['compliance_score_pct']}% "
          f"({report['summary']['controls_needs_attention']} controls need attention)")


if __name__ == "__main__":
    main()
