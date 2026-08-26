#!/usr/bin/env python3
"""Offline replay of the S1 fixes over the stored V1 findings (in-container).

IMPORTANT — what is and isn't replayable offline:
  * CVSS (Defect 2): FULLY replayable. V1 stored each finding's real v3.1 vector,
    so we re-derive the base score from the vector and audit it against the stored
    (max-across-sources-inflated) score. The new engine picks the NVD source's own
    score, which equals its own vector — so vector-derived ~= post-fix score.
  * Secrets (Defect 1): only PARTIALLY replayable. gitleaks ran with --redact in
    V1, so the stored `match` is the literal string "REDACTED" — the JWT-expiry,
    placeholder, and provider-format signals CANNOT be evaluated on V1 data. Only
    the path prior (file_path) and the bcrypt rule (code_snippet) are valid
    offline. The authoritative secrets numbers come from the live re-scan of 5
    repos (gate #2), where --redact is now off.
"""
from __future__ import annotations

import glob
import json
import math

OUT = "/workspaces/_v1out"

_M = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x): return math.ceil(x * 10) / 10.0


def cvss31_base(vector):
    if not vector or "CVSS:3" not in vector:
        return None
    m = dict(p.split(":", 1) for p in vector.split("/") if ":" in p and not p.startswith("CVSS"))
    try:
        scope = m["S"]
        av, ac, ui = _M["AV"][m["AV"]], _M["AC"][m["AC"]], _M["UI"][m["UI"]]
        pr = _M["PR_C" if scope == "C" else "PR_U"][m["PR"]]
        c, i, a = _M["CIA"][m["C"]], _M["CIA"][m["I"]], _M["CIA"][m["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope == "C" else 6.42 * iss
    if impact <= 0:
        return 0.0
    expl = 8.22 * av * ac * pr * ui
    return _roundup(min((impact + expl) * (1.08 if scope == "C" else 1.0), 10.0))


def sev_from_score(s):
    if s is None:
        return None
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"


def main():
    repos = {json.load(open(p))["slug"]: json.load(open(p)) for p in sorted(glob.glob(f"{OUT}/*.json"))}

    print("=== CVSS audit: stored score vs v3.1-vector-derived (|diff| > 0.5) ===")
    n_sca = n_vec = 0
    flagged = []
    for slug, d in repos.items():
        for e in d["engines"]:
            if e["engine"] != "sca":
                continue
            for fd in e["findings"]:
                m = fd.get("metadata") or {}
                n_sca += 1
                stored, derived = m.get("cvss_score"), cvss31_base(m.get("cvss_vector"))
                if derived is None or not isinstance(stored, (int, float)):
                    continue
                n_vec += 1
                if abs(stored - derived) > 0.5:
                    flagged.append((slug, fd.get("rule_id"), m.get("package"), stored, derived,
                                    fd["severity"], sev_from_score(derived), m.get("cvss_vector")))
    print(f"SCA findings={n_sca}; auditable (have vector)={n_vec}; mismatches>0.5={len(flagged)}")
    dropped = sum(1 for x in flagged if x[5] == "critical" and x[6] != "critical")
    print(f"of which stored=critical but vector says NOT critical: {dropped}\n")
    for slug, cve, pkg, st, dv, so, sn, vec in sorted(flagged, key=lambda x: -(x[3] - x[4])):
        flag = "  <-- crit->%s" % sn if (so == "critical" and sn != "critical") else ""
        print(f"  [{slug}] {cve} {pkg}: stored={st}({so}) vector={dv}({sn}){flag}")

    print("\n=== CORPUS CRITICAL COUNT — CVSS fix only (offline-valid) ===")
    before = after = 0
    for slug, d in repos.items():
        for e in d["engines"]:
            for fd in e["findings"]:
                if fd["severity"] == "critical":
                    before += 1
                m = fd.get("metadata") or {}
                if e["engine"] == "sca":
                    dv = cvss31_base(m.get("cvss_vector"))
                    sev = sev_from_score(dv) if dv is not None else fd["severity"]
                else:
                    sev = fd["severity"]
                if sev == "critical":
                    after += 1
    print(f"corpus criticals BEFORE: {before}")
    print(f"corpus criticals AFTER (CVSS-from-vector on SCA only): {after}")
    print(f"CVSS fix removes {before - after} critical FPs. Secrets fix measured live (5 repos).")


if __name__ == "__main__":
    main()
