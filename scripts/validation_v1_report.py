#!/usr/bin/env python3
"""Assemble docs/VALIDATION_RUN_V1.md from the per-repo JSON audit records.

Runs in-container: reads /workspaces/_v1out/*.json, writes the mechanical
sections (repo table, aggregates, quality ratings, operational) plus EVIDENCE
DUMPS for the human-judged sections (every bug finding; all critical/high
security; an SCA version-math sample; every secret, redacted). Verdicts are NOT
decided here — the report author fills them. Rule Zero: this only reads results.
"""
from __future__ import annotations

import glob
import json
import os
from collections import Counter, defaultdict

OUTDIR = "/workspaces/_v1out"
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, None: 0}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]

# corpus order (index used for the repo table)
ORDER = [
    "snipe/snipe-it", "monicahq/monica", "akaunting/akaunting", "pterodactyl/panel",
    "documenso/documenso", "formbricks/formbricks", "outline/outline",
    "mealie-recipes/mealie", "paperless-ngx/paperless-ngx", "netbox-community/netbox",
    "usememos/memos", "navidrome/navidrome", "pocketbase/pocketbase",
    "macrozheng/mall", "elunez/eladmin",
]


def load():
    recs = {}
    for p in sorted(glob.glob(os.path.join(OUTDIR, "*.json"))):
        try:
            d = json.load(open(p, encoding="utf-8"))
            recs[d["slug"]] = d
        except Exception as e:  # noqa: BLE001
            print("WARN load", p, e)
    return recs


def all_findings(d):
    return [f for e in d.get("engines", []) for f in e.get("findings", [])]


def eng_of(d, name):
    for e in d.get("engines", []):
        if e["engine"] == name:
            return e
    return {"status": "MISSING", "findings": [], "n_findings": 0, "wall_s": None}


def worst_rating(findings, issue_type):
    worst = 0
    for f in findings:
        if f.get("issue_type") == issue_type:
            worst = max(worst, SEV_RANK.get(f.get("severity"), 0))
    return "ABCDE"[worst]


def maint_rating(score):
    if score is None:
        return "A"
    return ("A" if score >= 90 else "B" if score >= 80 else
            "C" if score >= 70 else "D" if score >= 50 else "E")


def md_escape(s):
    return (s or "").replace("|", "\\|").replace("\n", " ")


def h(s):
    return "\n" + s + "\n"


def main():
    recs = load()
    out = []
    slugs = [s for s in ORDER if s in recs] + [s for s in recs if s not in ORDER]

    # ---- 2. REPO TABLE ----
    out.append(h("## 2. Repo table"))
    out.append("| # | repo | lang | stars | LOC | files | self-linted? | custom pack | scan s | status |")
    out.append("|---|------|------|-------|-----|-------|--------------|-------------|--------|--------|")
    for i, s in enumerate(slugs, 1):
        d = recs[s]
        gh = d.get("github") or {}
        sl = d.get("self_lint") or {}
        cp = d.get("custom_pack") or {}
        loaded = "?" if not cp else ("YES" if cp.get("loaded") else "**NO**")
        tools = ",".join(sl.get("tools", [])) or "-"
        out.append("| {} | {} | {} | {} | {} | {} | {} ({}) | {} | {} | {} |".format(
            i, s, (gh.get("gh_language") or "?"), gh.get("stars"),
            d["loc"]["code_loc"], d["loc"]["file_count"],
            sl.get("verdict", "?"), md_escape(tools), loaded,
            d.get("scan_wall_s"), d.get("status")))

    # ---- 3. AGGREGATE ----
    out.append(h("## 3. Aggregate findings"))
    out.append("| # | repo | status | total | security | quality | deploy | crit | high | med | low | bugs (semgrep/ruff) |")
    out.append("|---|------|--------|-------|----------|---------|--------|------|------|-----|-----|---------------------|")
    tot = Counter()
    bug_rows = []
    for i, s in enumerate(slugs, 1):
        d = recs[s]
        fs = all_findings(d)
        pil = Counter(f["pillar"] for f in fs)
        sev = Counter(f["severity"] for f in fs)
        bugs = [f for f in fs if f.get("issue_type") == "bug"]
        be = Counter(f["engine"] for f in bugs)
        tot.update(sev)
        out.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {}/{} |".format(
            i, s, d.get("status"), len(fs), pil.get("security", 0), pil.get("quality", 0),
            eng_of(d, "deployment")["n_findings"], sev.get("critical", 0), sev.get("high", 0),
            sev.get("medium", 0), sev.get("low", 0), be.get("semgrep", 0), be.get("ruff", 0)))
        for f in bugs:
            bug_rows.append((s, f))
    out.append("\n**Corpus severity totals:** " + ", ".join(
        f"{k}={tot.get(k,0)}" for k in SEV_ORDER))
    out.append(f"**Total bug findings across corpus:** {len(bug_rows)}")

    # ---- 4. BUG EVIDENCE ----
    out.append(h("## 4. Bug findings — full evidence"))
    if not bug_rows:
        out.append("_No finding across the corpus carries issue_type=bug._ "
                   "(See section 7 for why: the Semgrep bug pack is thin on PHP/TS, "
                   "and Ruff is Python-only.)")
    for s, f in bug_rows:
        out.append(f"\n### `{s}` — {f['file_path']}:{f.get('line_start')}")
        out.append(f"- rule: `{f['rule_id']}` (`{f.get('rule_name')}`) · engine={f['engine']} · sev={f['severity']}")
        out.append(f"- title: {md_escape(f.get('title'))}")
        c5 = f.get("context5")
        if c5 and c5.get("lines"):
            out.append("```")
            for n, ln in enumerate(c5["lines"], c5["start_line"]):
                mark = " >>" if n == c5.get("flagged_line") else "   "
                out.append(f"{n:5}{mark} {ln}")
            out.append("```")
        elif f.get("code_snippet"):
            out.append("```\n" + f["code_snippet"] + "\n```")
        out.append("- **PROPOSED VERDICT:** <TP/FP/UNCERTAIN> · confidence <h/m/l> · why: <one sentence>")

    # ---- 5. SECURITY EVIDENCE ----
    out.append(h("## 5. Security findings — evidence sample"))
    # 5a critical/high SAST (pillar security, engine != trivy-sca)
    out.append(h("### 5a. All CRITICAL/HIGH SAST findings"))
    out.append("| repo | rule | sev | file:line | verdict |")
    out.append("|------|------|-----|-----------|---------|")
    for s in slugs:
        for f in eng_of(recs[s], "sast")["findings"]:
            if f["severity"] in ("critical", "high"):
                out.append(f"| {s} | `{md_escape(f['rule_id'])}` | {f['severity']} | {f['file_path']}:{f.get('line_start')} | <fill> |")
    # 5b SCA sample with version math
    out.append(h("### 5b. SCA CVE sample — version math cross-check"))
    out.append("| repo | CVE | package | installed | fixed | cvss | reachable | verdict |")
    out.append("|------|-----|---------|-----------|-------|------|-----------|---------|")
    sca_all = [(s, f) for s in slugs for f in eng_of(recs[s], "sca")["findings"]]
    step = max(1, len(sca_all) // 15)
    for s, f in sca_all[::step][:15]:
        m = f.get("metadata") or {}
        out.append("| {} | {} | {} | {} | {} | {} | {} | <fill> |".format(
            s, f["rule_id"], m.get("package"), m.get("installed_version"),
            m.get("fixed_version"), m.get("cvss_score"), m.get("reachable")))
    out.append(f"\n_SCA total across corpus: {len(sca_all)} findings; sampled {min(15, len(sca_all))}._")
    # 5c secrets (redacted)
    out.append(h("### 5c. Secrets (redacted)"))
    out.append("| repo | rule | file:line | entropy | redacted match | in test? | verdict |")
    out.append("|------|------|-----------|---------|----------------|----------|---------|")
    for s in slugs:
        for f in eng_of(recs[s], "secrets")["findings"]:
            m = f.get("metadata") or {}
            match = m.get("match") or ""
            red = (match[:3] + "…" + match[-3:]) if len(match) > 8 else "…"
            intest = "yes" if "test" in (f["file_path"] or "").lower() else ""
            out.append(f"| {s} | `{f['rule_id']}` | {f['file_path']}:{f.get('line_start')} | {m.get('entropy')} | `{md_escape(red)}` | {intest} | <fill> |")

    # ---- 6. QUALITY PILLAR ----
    out.append(h("## 6. Quality pillar"))
    out.append("| repo | reliability | security | maintainability | maint score | coverage | dup% | top smells |")
    out.append("|------|-------------|----------|-----------------|-------------|----------|------|------------|")
    for s in slugs:
        d = recs[s]
        fs = all_findings(d)
        qm = eng_of(d, "quality").get("quality_metrics") or {}
        rel = worst_rating(fs, "bug")
        secr = worst_rating(fs, "vulnerability")
        cov = qm.get("test_coverage_score")
        cov_disp = "not measured" if cov is None else f"{cov:.1f}%"
        maint = qm.get("maintainability_score")
        smells = Counter(f["rule_name"] for f in eng_of(d, "quality")["findings"])
        top = "; ".join(f"{k}×{v}" for k, v in smells.most_common(5))
        out.append("| {} | {} | {} | {} | {} | {} | {} | {} |".format(
            s, rel, secr, maint_rating(maint), maint,
            cov_disp, qm.get("duplicated_line_percentage"), md_escape(top)))

    # ---- ownership ----
    out.append(h("## Code ownership tagging (measured)"))
    out.append("| repo | ownership tag counts | ruff findings (ownership) |")
    out.append("|------|----------------------|---------------------------|")
    for s in slugs:
        d = recs[s]
        own = Counter()
        ruff_own = Counter()
        for f in all_findings(d):
            m = f.get("metadata") or {}
            tag = m.get("code_ownership")
            own[tag] += 1
            if f["engine"] == "ruff":
                ruff_own[tag] += 1
        out.append(f"| {s} | {dict(own)} | {dict(ruff_own) or '-'} |")

    # ---- 9. OPERATIONAL ----
    out.append(h("## 9. Operational results"))
    out.append("| repo | LOC | files | clone s | scan s | total s | sast | sca | secrets | deploy | quality |")
    out.append("|------|-----|-------|---------|--------|---------|------|-----|---------|--------|---------|")
    for s in slugs:
        d = recs[s]
        def es(n):
            e = eng_of(d, n)
            return f"{e['status']}/{e['wall_s']}s"
        out.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
            s, d["loc"]["code_loc"], d["loc"]["file_count"], d.get("clone_s"),
            d.get("scan_wall_s"), d.get("total_wall_s"),
            es("sast"), es("sca"), es("secrets"), es("deployment"), es("quality")))

    # ---- determinism ----
    out.append(h("## Determinism checks"))
    any_det = False
    for s in slugs:
        det = recs[s].get("determinism")
        if det:
            any_det = True
            out.append(f"- `{s}`: run1={det['run1_findings']} run2={det['run2_findings']} "
                       f"identical={det['identical']}")
    if not any_det:
        out.append("_(determinism runs pending)_")

    with open(os.path.join(OUTDIR, "_auto_report.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(out))
    print("wrote _auto_report.md ;", len(bug_rows), "bugs ;", len(slugs), "repos")


if __name__ == "__main__":
    main()
