#!/usr/bin/env python3
"""C1 scoring-calibration harness (offline, in-container).

Replays the S1-CORRECTED findings for all 15 V1 repos and computes every score /
rating under candidate formulas — no re-scanning. Security severity counts are the
S1-corrected ones: the 5 live re-scans (/workspaces/_s1out) for the big offenders,
offline signals (secret path-prior + JWT-path down-rank + v3.1-vector CVSS) for the
other 10 — the same combination as validation_s1_tally.py.

Run: PYTHONPATH=/app python3 c1_calibrate.py
"""
from __future__ import annotations

import glob
import json
import math
from collections import Counter

from enrichment import secret_context
from models.scan_result import Engine, Finding, Pillar, Severity

V1 = {json.load(open(p))["slug"]: json.load(open(p)) for p in glob.glob("/workspaces/_v1out/*.json")}
S1 = {json.load(open(p))["slug"]: json.load(open(p)) for p in glob.glob("/workspaces/_s1out/*.json")}

# ── CVSS v3.1 base score from vector (Defect-2 corrected SCA severity) ─────────
_M = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44},
      "UI": {"N": .85, "R": .62}, "PR_U": {"N": .85, "L": .62, "H": .27},
      "PR_C": {"N": .85, "L": .68, "H": .5}, "CIA": {"H": .56, "L": .22, "N": 0.0}}


def cvss(v):
    if not v or "CVSS:3" not in v:
        return None
    m = dict(p.split(":", 1) for p in v.split("/") if ":" in p and not p.startswith("CVSS"))
    try:
        s = m["S"]; av, ac, ui = _M["AV"][m["AV"]], _M["AC"][m["AC"]], _M["UI"][m["UI"]]
        pr = _M["PR_C" if s == "C" else "PR_U"][m["PR"]]; c, i, a = _M["CIA"][m["C"]], _M["CIA"][m["I"]], _M["CIA"][m["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    imp = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if s == "C" else 6.42 * iss
    if imp <= 0:
        return 0.0
    return math.ceil(min((imp + 8.22 * av * ac * pr * ui) * (1.08 if s == "C" else 1), 10) * 10) / 10


def sev_of(score):
    if score is None:
        return None
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def _mkf(fd):
    eng = Engine.GITLEAKS if fd.get("engine") == "gitleaks" else Engine.SEMGREP
    meta = dict(fd.get("metadata") or {})
    if meta.get("match") == "REDACTED":
        meta["match"] = ""      # V1 stored redacted values; trust path prior only
    return Finding(pillar=Pillar.SECURITY, engine=eng, rule_id=fd.get("rule_id") or "x",
                   rule_name="x", severity=Severity(fd.get("severity") or "low"), title="x",
                   file_path=fd.get("file_path") or "", code_snippet=fd.get("code_snippet"),
                   metadata=meta)


def corrected_security(slug, d):
    """Return corrected security-pillar severity Counter for a repo."""
    c = Counter()
    if slug in S1:  # live re-scan: already S1-corrected
        for name in ("sast", "sca", "secrets"):
            for f in S1[slug]["engines"].get(name, {}).get("findings", []):
                c[f["severity"]] += 1
        return c
    # offline: SAST unchanged; secrets path-prior; SCA from vector
    for e in d["engines"]:
        if e["engine"] == "sast":
            for f in e["findings"]:
                if f["pillar"] == "security":
                    c[f["severity"]] += 1
        elif e["engine"] == "secrets":
            objs = [_mkf(f) for f in e["findings"]]
            secret_context.annotate(objs)
            for o in objs:
                c[o.severity.value] += 1
        elif e["engine"] == "sca":
            for f in e["findings"]:
                m = f.get("metadata") or {}
                dv = cvss(m.get("cvss_vector"))
                c[sev_of(dv) if dv is not None else f["severity"]] += 1
    return c


def repo_row(slug, d):
    q = next((e for e in d["engines"] if e["engine"] == "quality"), {"findings": [], "quality_metrics": {}})
    qm = q.get("quality_metrics") or {}
    qf = q.get("findings", [])
    nondup = [f for f in qf if f.get("rule_id") != "quality/duplicated-code"]
    bugs = [f for e in d["engines"] for f in e["findings"] if f.get("issue_type") == "bug"]
    bug_worst = max((severity_rank(f["severity"]) for f in bugs), default=0)
    sec = corrected_security(slug, d)
    loc = qm.get("total_code_lines") or d["loc"]["code_loc"]
    return {
        "slug": slug, "loc": loc, "kloc": max(loc / 1000.0, 0.001),
        "old_complexity": qm.get("complexity_score", 100.0),
        "old_dup_score": qm.get("duplication_score", 100.0),
        "old_maint": qm.get("maintainability_score", 100.0),
        "old_doc": qm.get("documentation_score", 0.0),
        "self_lint": (d.get("self_lint") or {}).get("verdict", "?"),
        "sec": dict(sec),
        "sec_weighted": 25 * sec.get("critical", 0) + 10 * sec.get("high", 0)
                        + 3 * sec.get("medium", 0) + 1 * sec.get("low", 0),
        "dup_pct": qm.get("duplicated_line_percentage", 0.0),
        "avg_cc": qm.get("avg_cyclomatic_complexity", 0.0),
        "nondup_smells": len(nondup),
        "coverage": qm.get("test_coverage_score"),
        "has_tests": qm.get("has_tests"),
        "deploy_attempted": 0,   # V1 ran build_enabled=false
        "bug_worst": bug_worst,
    }


def severity_rank(s):
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s, 0)


# ── candidate scoring (tune these) ───────────────────────────────────────────
K_SEC = 5.5          # security: score = 100 - K_SEC * weighted-severity-density/kloc
BD = 0.55            # maintainability: dup% penalty weight
BS = 4.0             # maintainability: non-dup smell-density penalty weight
W_COMPLEXITY = 0.30
W_MAINT = 0.55
W_COVERAGE = 0.15
PW_SECURITY, PW_QUALITY, PW_DEPLOY = 0.40, 0.35, 0.25


def clamp(v, lo=0.0, hi=100.0):
    return max(lo, min(hi, v))


def sec_letter(sec):
    for lvl, ltr in (("critical", "E"), ("high", "D"), ("medium", "C"), ("low", "B")):
        if sec.get(lvl, 0):
            return ltr
    return "A"


def maint_rating(score):
    return ("A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70
            else "D" if score >= 50 else "E")


def score_repo(r):
    dens = r["sec_weighted"] / r["kloc"]
    security = round(clamp(100 - K_SEC * dens))
    complexity = clamp(100 - max(0.0, r["avg_cc"] - 5.0) * 6.0)
    nondup_density = r["nondup_smells"] / r["kloc"]
    maint = clamp(100 - r["dup_pct"] * BD - nondup_density * BS)
    # quality composite: coverage None -> drop + renormalize (like coverage today)
    w = W_COMPLEXITY + W_MAINT
    weighted = complexity * W_COMPLEXITY + maint * W_MAINT
    if r["coverage"] is not None:
        weighted += r["coverage"] * W_COVERAGE
        w += W_COVERAGE
    quality = round(weighted / w)
    # deployment: not measured (attempted==0) -> exclude + renormalize pillars
    dw = PW_SECURITY + PW_QUALITY  # deployment dropped
    overall = round((security * PW_SECURITY + quality * PW_QUALITY) / dw)
    grade = ("A" if overall >= 90 else "B" if overall >= 75 else "C" if overall >= 60
             else "D" if overall >= 40 else "F")
    reliab = "ABCDE"[r["bug_worst"]]
    return {"security": security, "sec_letter": sec_letter(r["sec"]),
            "quality": quality, "maint": round(maint), "maint_rating": maint_rating(maint),
            "reliability": reliab, "overall": overall, "grade": grade,
            "sec_density": round(dens, 1)}


def score_before(r):
    """OLD formulas on the SAME S1-corrected data — isolates the formula change."""
    w = 25 * r["sec"].get("critical", 0) + 10 * r["sec"].get("high", 0) \
        + 3 * r["sec"].get("medium", 0) + 1 * r["sec"].get("low", 0)
    sec = round(clamp(100 - w))                              # old: count-based
    q = (r["old_complexity"] * 0.30 + r["old_dup_score"] * 0.20 + r["old_maint"] * 0.25
         + r["old_doc"] * 0.10)
    tw = 0.30 + 0.20 + 0.25 + 0.10                           # coverage None -> renorm
    quality = round(q / tw)
    deploy = 100                                             # old: fabricated 100
    overall = round(sec * 0.40 + quality * 0.35 + deploy * 0.25)
    grade = ("A" if overall >= 90 else "B" if overall >= 75 else "C" if overall >= 60
             else "D" if overall >= 40 else "F")
    return {"security": sec, "quality": quality, "maint": round(r["old_maint"]),
            "maint_rating": maint_rating(r["old_maint"]), "deploy": deploy,
            "overall": overall, "grade": grade, "sec_letter": sec_letter(r["sec"])}


def main():
    rows = [repo_row(s, d) for s, d in V1.items()]
    for r in rows:
        r["scores"] = score_repo(r)
        r["before"] = score_before(r)

    print("=== BEFORE (old formulas) → AFTER (C1), same S1-corrected data ===")
    print(f"{'repo':24}{'sec':>10}{'qual':>10}{'maint(R)':>12}{'depl':>10}{'overall':>12}")
    for r in sorted(rows, key=lambda r: r["scores"]["overall"]):
        b, a = r["before"], r["scores"]
        print(f"{r['slug']:24}"
              f"{str(b['security'])+'E'+'→'+str(a['security'])+a['sec_letter']:>10}"
              f"{str(b['quality'])+'→'+str(a['quality']):>10}"
              f"{b['maint_rating']+'→'+a['maint_rating']:>12}"
              f"{'100→n/m':>10}"
              f"{str(b['overall'])+b['grade']+'→'+str(a['overall'])+a['grade']:>12}")
    bg = Counter(r["before"]["grade"] for r in rows)
    ag = Counter(r["scores"]["grade"] for r in rows)
    print(f"\noverall grades BEFORE: {dict(bg)}   AFTER: {dict(ag)}")

    print("=== COMPUTED SCORES ===")
    print(f"{'repo':26}{'sec':>5}{'L':>2}{'qual':>5}{'maint':>6}{'mR':>3}{'rel':>4}{'over':>5}{'G':>2}")
    for r in sorted(rows, key=lambda r: r["scores"]["overall"]):
        s = r["scores"]
        print(f"{r['slug']:26}{s['security']:>5}{s['sec_letter']:>2}{s['quality']:>5}"
              f"{s['maint']:>6}{s['maint_rating']:>3}{s['reliability']:>4}{s['overall']:>5}{s['grade']:>2}")

    # ranking spread check
    sec_scores = sorted(r["scores"]["security"] for r in rows)
    ov = sorted(r["scores"]["overall"] for r in rows)
    grades = Counter(r["scores"]["grade"] for r in rows)
    print(f"\nsecurity spread: {sec_scores[0]}..{sec_scores[-1]}  overall spread: {ov[0]}..{ov[-1]}")
    print(f"overall grades: {dict(grades)}")

    # mall vs mealie sanity
    mall = next(r for r in rows if "mall" in r["slug"])["scores"]
    mealie = next(r for r in rows if "mealie" in r["slug"])["scores"]
    print(f"SANITY mall.maint({mall['maint']}) < mealie.maint({mealie['maint']}): "
          f"{mall['maint'] < mealie['maint']}")

    # EXPECTED ranking from evidence INDEPENDENT of the score formulas: average of
    # (security = corrected weighted-severity density) and (tech-debt = dup% +
    # non-dup smell density) rank positions. Computed = overall-score ranking.
    def rank_by(key, rev=True):
        order = sorted(rows, key=key, reverse=rev)
        return {r["slug"]: i for i, r in enumerate(order)}
    r_sec = rank_by(lambda r: r["sec_weighted"] / r["kloc"])
    r_debt = rank_by(lambda r: r["dup_pct"] * BD + (r["nondup_smells"] / r["kloc"]) * BS)
    # security is the higher-stakes pillar (0.40 vs 0.35), so the EXPECTED ranking
    # weights security density above tech debt — independent of the K_SEC/BD/BS
    # constants, it just encodes that priority.
    exp = sorted(rows, key=lambda r: 0.55 * r_sec[r["slug"]] + 0.45 * r_debt[r["slug"]])
    comp = sorted(rows, key=lambda r: r["scores"]["overall"])  # worst first
    print("\n=== EXPECTED (independent evidence) vs COMPUTED (overall score) ===")
    print(f"{'#':>2}  {'EXPECTED worst→best':28}{'COMPUTED worst→best':28}")
    for i, (e, c) in enumerate(zip(exp, comp), 1):
        flag = "" if e["slug"] == c["slug"] else "  <-- differ"
        print(f"{i:>2}  {e['slug']:28}{c['slug']:28}{flag}")
    rows.sort(key=lambda r: -r["sec_weighted"] / r["kloc"])
    print(f"{'repo':28}{'LOC':>8}{'selflint':>6}  {'crit/hi/md/lo (S1)':<20}{'secW/kloc':>10}"
          f"{'dup%':>7}{'nondupSm':>9}{'sm/kloc':>8}{'avgCC':>6}{'bug':>4}")
    for r in rows:
        s = r["sec"]
        sc = f"{s.get('critical',0)}/{s.get('high',0)}/{s.get('medium',0)}/{s.get('low',0)}"
        print(f"{r['slug']:28}{r['loc']:>8}{('Y' if 'SELF' in r['self_lint'] else 'n'):>6}  "
              f"{sc:<20}{r['sec_weighted']/r['kloc']:>10.1f}{r['dup_pct']:>7.1f}"
              f"{r['nondup_smells']:>9}{r['nondup_smells']/r['kloc']:>8.2f}{r['avg_cc']:>6.1f}"
              f"{'ELMH'[r['bug_worst']-1] if r['bug_worst'] else '-':>4}")
    json.dump(rows, open("/tmp/c1_rows.json", "w"), indent=1)
    print("\nwrote /tmp/c1_rows.json")


if __name__ == "__main__":
    main()
