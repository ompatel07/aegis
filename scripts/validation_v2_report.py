#!/usr/bin/env python3
"""Aegis Validation Run V2 — report harness (MEASUREMENT ONLY, RULE ZERO).

Reads every /workspaces/_v2out/*.json record the driver wrote and derives the V2
report tables: operational results, self-lint, the P4a/P4b aggregated surfaces
(DEGRADED / NOT-MEASURED pillars / PARTIAL overall — mirroring the orchestrator's
aggregator so the offline records show what the product would show), the
Aegis-vs-registry-only delta (custom aegis-* rules are additive, so their marginal
contribution is exactly the aegis-* findings), rule-source coverage per language,
and finding inventories for hand-triage. It never edits engines/rules.

Usage (in container):  python3 validation_v2_report.py [--summary|--repo SLUG|--json]
"""
from __future__ import annotations

import collections
import glob
import json
import math
import os
import sys

OUT = "/workspaces/_v2out"

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def load():
    recs = []
    for p in sorted(glob.glob(os.path.join(OUT, "*.json"))):
        try:
            recs.append(json.load(open(p, encoding="utf-8")))
        except Exception as e:  # noqa: BLE001
            print(f"!! could not read {p}: {e}")
    return recs


def eng(rec, name):
    for e in rec.get("engines", []):
        if e.get("engine") == name:
            return e
    return {}


def all_findings(rec):
    for e in rec.get("engines", []):
        for f in e.get("findings", []):
            yield e.get("engine"), f


# ── P4a/P4b aggregation, mirrored from services/orchestrator/.../aggregator.go ──
def pillar_confidence(rec):
    """Return (degraded_engines, security_confident, quality_confident,
    reliability_confident) using the same rule the orchestrator uses: a pillar fed
    by any failed OR degraded engine is not confidently measured."""
    degraded = set()
    for e in rec.get("engines", []):
        st = e.get("status")
        if st in ("failed", "ERROR", "TIMEOUT"):
            degraded.add(e.get("engine"))
        elif e.get("degraded"):
            degraded.add(e.get("engine"))
    # driver engine names: sast(semgrep), sca(trivy), secrets(gitleaks), quality
    sec = not (degraded & {"sast", "sca", "secrets"})
    qual = not (degraded & {"quality"})
    rel = not (degraded & {"sast", "quality"})
    return degraded, sec, qual, rel


def summarize(recs):
    print(f"# V2 records: {len(recs)}\n")
    print("## Operational + pack + self-lint")
    print(f"{'repo':28} {'LOC':>8} {'wall_s':>7} {'PACK':>5} {'selflint':>14} {'status':>10}")
    for r in recs:
        loc = (r.get("loc") or {}).get("code_loc")
        cp = r.get("custom_pack") or {}
        pack = "YES" if cp.get("loaded") else ("NO!!" if cp else "?")
        sl = (r.get("self_lint") or {}).get("verdict", "?")
        print(f"{r['slug']:28} {str(loc):>8} {str(r.get('total_wall_s')):>7} {pack:>5} {sl:>14} {r.get('status',''):>10}")

    print("\n## P4a/P4b surfaces (DEGRADED / NOT-MEASURED pillars / filtered secrets)")
    print(f"{'repo':28} {'degraded_engines':>28} {'sec':>4} {'qual':>4} {'filtered_secrets':>18}")
    for r in recs:
        deg, sec, qual, rel = pillar_confidence(r)
        fsum = collections.Counter()
        for e in r.get("engines", []):
            for k, v in (e.get("filtered_secrets") or {}).items():
                fsum[k] += v
        print(f"{r['slug']:28} {','.join(sorted(deg)) or '-':>28} "
              f"{'OK' if sec else 'N/M':>4} {'OK' if qual else 'N/M':>4} {str(dict(fsum)) or '-':>18}")

    print("\n## Findings by engine + rule source (Aegis custom vs registry)")
    print(f"{'repo':28} {'sast':>6} {'aegis*':>7} {'reg':>6} {'sca':>5} {'secrets':>8} {'quality':>8}")
    for r in recs:
        sast = eng(r, "sast"); sca = eng(r, "sca"); sec = eng(r, "secrets"); q = eng(r, "quality")
        aegis = sum(1 for f in sast.get("findings", []) if (f.get("rule_id") or "").startswith("aegis-"))
        regi = sast.get("n_findings", 0) - aegis
        print(f"{r['slug']:28} {sast.get('n_findings',0):>6} {aegis:>7} {regi:>6} "
              f"{sca.get('n_findings',0):>5} {sec.get('n_findings',0):>8} {q.get('n_findings',0):>8}")

    print("\n## Aegis-vs-registry-only DELTA (marginal value of custom rules)")
    print("   Custom packs are ADDITIVE — registry rules fire regardless — so the")
    print("   custom rules' contribution over registry-only IS the aegis-* finding set.")
    total_aegis = collections.Counter()
    for r in recs:
        for _, f in all_findings(r):
            rid = (f.get("rule_id") or "")
            if rid.startswith("aegis-"):
                total_aegis[rid.split(".")[-1]] += 1
    print(f"   distinct aegis-* rules fired across corpus: {len(total_aegis)}")
    for rid, n in total_aegis.most_common():
        print(f"     {n:>4}  {rid}")


def repo_detail(recs, slug):
    r = next((x for x in recs if x["slug"] == slug or x["slug"].endswith(slug)), None)
    if not r:
        print("no such repo:", slug); return
    print(f"# {r['slug']}  LOC={ (r.get('loc') or {}).get('code_loc') }  wall={r.get('total_wall_s')}s")
    print("custom_pack:", r.get("custom_pack"))
    for e in r.get("engines", []):
        print(f"  {e['engine']:11} status={e['status']} n={e['n_findings']} wall={e.get('wall_s')}s "
              f"degraded={e.get('degraded')} filtered={e.get('filtered_secrets')}")
    print("\n  top findings by severity:")
    fs = sorted(((eng, f) for eng, f in all_findings(r)),
                key=lambda ef: SEV_ORDER.get(ef[1].get("severity"), 9))
    for eng_name, f in fs[:40]:
        rid = (f.get("rule_id") or "").split(".")[-1]
        print(f"    [{f.get('severity'):8}] {rid:42} {f.get('file_path')}:{f.get('line_start')}")


if __name__ == "__main__":
    recs = load()
    if "--repo" in sys.argv:
        repo_detail(recs, sys.argv[sys.argv.index("--repo") + 1])
    else:
        summarize(recs)
