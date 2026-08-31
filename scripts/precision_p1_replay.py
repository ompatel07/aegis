#!/usr/bin/env python3
"""Offline precision replay for Pass P1 — reproduces the per-engine before/after
finding counts on the committed V1 corpus (docs/validation_v1/, 15 repos). It does
NOT re-scan; it replays the Part A and Part B corrections over the stored findings.

Corrections applied:
  Part A — drop every `ai-code-*` finding (the deleted AI-detection pack).
  Part B — secrets: SUPPRESS placeholder + expired-JWT, KEEP test-fixture at LOW.
           The committed corpus stores REDACTED secret values, so token-shape and
           JWT-exp cannot be recomputed here; this script applies only the offline-
           decidable signals (fixture PATH prior + stored low-entropy) and reports
           them as a reproducible LOWER BOUND on suppression. The authoritative
           secret classification (585/630 findings) came from the S1 LIVE re-scan
           with real values (docs/PRECISION_S1.md; embedded below as LIVE_SECRET_CTX
           with provenance) and is what docs/ACCURACY.md cites.
  SCA severity — recompute each finding's severity from its stored CVSS v3.1 vector
           (single authoritative base score) instead of the historical max()-across-
           sources, which inflated severity. Version math / TP-FP verdicts unchanged.

Run from the repo root:  python scripts/precision_p1_replay.py
"""
from __future__ import annotations

import glob
import json
import math
import os
import re
import collections

CORPUS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "docs", "validation_v1")

# LIVE secret classification from the S1 re-scan (real values), covering the 5
# biggest-offender repos = 585/630 corpus secrets. Source: /workspaces/_s1out,
# S1 run 2026-08-26, build 66db94d (docs/PRECISION_S1.md). {repo: {ctx: n}}.
LIVE_SECRET_CTX = {
    "documenso/documenso":   {"kept": 20, "placeholder": 5,  "test-fixture": 0,   "expired": 0},
    "formbricks/formbricks": {"kept": 74, "placeholder": 40, "test-fixture": 14,  "expired": 0},
    "mealie-recipes/mealie": {"kept": 0,  "placeholder": 1,  "test-fixture": 17,  "expired": 0},
    "pocketbase/pocketbase": {"kept": 4,  "placeholder": 0,  "test-fixture": 392, "expired": 14},
    "snipe/snipe-it":        {"kept": 2,  "placeholder": 0,  "test-fixture": 2,   "expired": 0},
}

_FIXTURE = re.compile(
    r"(?ix)(_test\.|\.test\.|_spec\.|\.spec\.|(^|/)(test|tests|spec|specs|fixtures?"
    r"|factories|mocks?|__mocks__|testdata|seeds?|examples?|sample|samples|e2e|cypress)(/|$)"
    r"|\.example($|\.)|\.sample($|\.)|\.template($|\.)|(^|/)\.env\.(example|sample|template|local|dist)(\.|$))"
)

# CVSS v3.1 base-score recompute (same math as scripts/validation_s1_tally.py).
_M = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44},
      "UI": {"N": .85, "R": .62}, "PR_U": {"N": .85, "L": .62, "H": .27},
      "PR_C": {"N": .85, "L": .68, "H": .5}, "CIA": {"H": .56, "L": .22, "N": 0.0}}


def cvss_base(vec: str | None) -> float | None:
    if not vec or "CVSS:3" not in vec:
        return None
    m = dict(p.split(":", 1) for p in vec.split("/") if ":" in p and not p.startswith("CVSS"))
    try:
        s = m["S"]
        av, ac, ui = _M["AV"][m["AV"]], _M["AC"][m["AC"]], _M["UI"][m["UI"]]
        pr = _M["PR_C" if s == "C" else "PR_U"][m["PR"]]
        c, i, a = _M["CIA"][m["C"]], _M["CIA"][m["I"]], _M["CIA"][m["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    imp = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if s == "C" else 6.42 * iss
    if imp <= 0:
        return 0.0
    return math.ceil(min((imp + 8.22 * av * ac * pr * ui) * (1.08 if s == "C" else 1), 10) * 10) / 10


def sev_of(score: float | None) -> str | None:
    if score is None:
        return None
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def load():
    return [json.load(open(p, encoding="utf-8")) for p in sorted(glob.glob(os.path.join(CORPUS, "*.json")))]


def engine(d, name):
    for x in (d.get("engines") or []):
        if x.get("engine") == name:
            return x
    return {}


def sevctr():
    return collections.Counter({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})


def actionable(ctr):
    return ctr["critical"] + ctr["high"]


def main():
    repos = load()
    print(f"# P1 offline replay — {len(repos)} repos, corpus docs/validation_v1/\n")

    # ── SAST: before vs after Part A (drop ai-code-*) ─────────────────────────
    before, after, aicode = sevctr(), sevctr(), collections.Counter()
    for d in repos:
        for f in (engine(d, "sast").get("findings") or []):
            s = f.get("severity")
            if s not in before:
                continue
            before[s] += 1
            rid = (f.get("rule_id") or "").split(".")[-1]
            if rid.startswith("ai-code-"):
                aicode[s] += 1
            else:
                after[s] += 1
    print("## SAST (semgrep)")
    print(f"  before:  {dict(before)}  actionable(crit+high)={actionable(before)}")
    print(f"  ai-code: {dict(aicode)}  (removed by Part A; total={sum(aicode.values())})")
    print(f"  after:   {dict(after)}  actionable(crit+high)={actionable(after)}\n")

    # ── SCA: before vs after CVSS v3.1 recompute ──────────────────────────────
    b, a, moved = sevctr(), sevctr(), collections.Counter()
    for d in repos:
        for f in (engine(d, "sca").get("findings") or []):
            s = f.get("severity")
            if s not in b:
                continue
            b[s] += 1
            vec = (f.get("metadata") or {}).get("cvss_vector")
            ns = sev_of(cvss_base(vec)) if vec else None
            ns = ns or s  # no vector -> keep stored severity
            a[ns] += 1
            if ns != s:
                moved[f"{s}->{ns}"] += 1
    print("## SCA (trivy)")
    print(f"  before:  {dict(b)}  actionable={actionable(b)}")
    print(f"  after:   {dict(a)}  actionable={actionable(a)}")
    print(f"  severity corrections (v3.1 vector vs stored max()): {dict(moved)}\n")

    # ── Secrets: reproducible offline lower bound + LIVE authoritative ────────
    live = collections.Counter()
    for r, c in LIVE_SECRET_CTX.items():
        live.update(c)
    live_repos = set(LIVE_SECRET_CTX)
    off = collections.Counter()
    off_total = 0
    for d in repos:
        if d["slug"] in live_repos:
            continue
        for f in (engine(d, "secrets").get("findings") or []):
            off_total += 1
            fp = (f.get("file_path") or "").replace("\\", "/")
            ent = (f.get("metadata") or {}).get("entropy")
            try:
                ent = float(ent)
            except (TypeError, ValueError):
                ent = None
            if ent is not None and ent < 3.0:
                off["placeholder(entropy)"] += 1
            elif _FIXTURE.search(fp):
                off["test-fixture(path)"] += 1
            else:
                off["kept(unknown-offline)"] += 1
    print("## Secrets (gitleaks)")
    print(f"  LIVE 5 repos (S1 real values, 585 findings): {dict(live)}")
    print(f"    -> Part B SUPPRESSES placeholder+expired = {live['placeholder'] + live['expired']}"
          f" (was LOW under S1); test-fixture {live['test-fixture']} stay LOW; kept {live['kept']}")
    print(f"  OFFLINE 10 repos ({off_total} findings, redacted — lower bound): {dict(off)}")
    print("  NOTE: offline cannot see token-shape/JWT-exp; true suppression >= shown.\n")

    print("## Bug pack (reliability) — 5/5 TP on V1 (see docs/ACCURACY.md), unchanged by P1.")


if __name__ == "__main__":
    main()
