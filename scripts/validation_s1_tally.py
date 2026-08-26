#!/usr/bin/env python3
"""S1 corpus critical tally (in-container). Combines the 5 LIVE re-scans (real
secret values + NVD-precedence CVSS) with offline-valid signals for the other 10
repos (path prior + bcrypt for secrets; v3.1-vector-derived CVSS for SCA). SAST
criticals are unchanged by S1. Prints corpus criticals before vs after."""
from __future__ import annotations

import glob
import json
import math

from enrichment import secret_context
from models.scan_result import Engine, Finding, Pillar, Severity

V1 = {json.load(open(p))["slug"]: json.load(open(p)) for p in glob.glob("/workspaces/_v1out/*.json")}
S1 = {json.load(open(p))["slug"]: json.load(open(p)) for p in glob.glob("/workspaces/_s1out/*.json")}
LIVE = set(S1)

_M = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44},
      "UI": {"N": .85, "R": .62}, "PR_U": {"N": .85, "L": .62, "H": .27},
      "PR_C": {"N": .85, "L": .68, "H": .5}, "CIA": {"H": .56, "L": .22, "N": 0.0}}


def base(v):
    if not v or "CVSS:3" not in v:
        return None
    m = dict(p.split(":", 1) for p in v.split("/") if ":" in p and not p.startswith("CVSS"))
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


def sev(x):
    if x is None:
        return None
    return "critical" if x >= 9 else "high" if x >= 7 else "medium" if x >= 4 else "low"


def mkf(fd):
    eng = Engine.GITLEAKS if fd.get("engine") == "gitleaks" else Engine.SEMGREP
    return Finding(pillar=Pillar.SECURITY, engine=eng, rule_id=fd.get("rule_id") or "x",
                   rule_name="x", severity=Severity(fd.get("severity") or "low"), title="x",
                   file_path=fd.get("file_path") or "", code_snippet=fd.get("code_snippet"),
                   metadata=fd.get("metadata") or {})


def main():
    hdr = "repo".ljust(30) + "before".rjust(8) + "after".rjust(8) + "   source"
    print(hdr)
    tb = ta = 0
    for slug, d in sorted(V1.items()):
        cb = sum(1 for e in d["engines"] for f in e["findings"] if f["severity"] == "critical")
        tb += cb
        sast_c = sum(1 for e in d["engines"] if e["engine"] == "sast"
                     for f in e["findings"] if f["severity"] == "critical")
        if slug in LIVE:
            s = S1[slug]
            sec_c = sum(1 for f in s["engines"]["secrets"].get("findings", []) if f["severity"] == "critical")
            sca_c = sum(1 for f in s["engines"]["sca"].get("findings", []) if f["severity"] == "critical")
            src = "LIVE re-scan"
        else:
            objs = [mkf(f) for e in d["engines"] for f in e["findings"] if f.get("engine") == "gitleaks"]
            secret_context.annotate(objs)
            sec_c = sum(1 for o in objs if o.severity.value == "critical")
            sca_c = 0
            for e in d["engines"]:
                if e["engine"] != "sca":
                    continue
                for f in e["findings"]:
                    dv = base((f.get("metadata") or {}).get("cvss_vector"))
                    if (sev(dv) if dv is not None else f["severity"]) == "critical":
                        sca_c += 1
            src = "offline (path+CVSS; value-based N/A)"
        ca = sast_c + sec_c + sca_c
        ta += ca
        print(slug.ljust(30) + str(cb).rjust(8) + str(ca).rjust(8) + "   " + src)
    print(f"\nCORPUS CRITICALS  before={tb}  after={ta}  (removed {tb - ta})")
    print("note: other-10 secrets use path-prior only (V1 stored redacted values), so their")
    print("after-count is an UPPER bound — a live re-scan would down-rank a few more.")


if __name__ == "__main__":
    main()
