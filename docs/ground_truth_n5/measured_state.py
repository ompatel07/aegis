"""Pass N5 Part E: which V2/F1 repositories change measured state, either direction.

A repository's security score is "measured" (confident) when more than half its
application code, by LOC, is in STRONG languages (utils/rule_coverage.py). This applies
that threshold to each repository's own per-language LOC (from its scan's
security_coverage) twice: under N4's declared tiers and under N5's computed tiers.

usage: python measured_state.py <scan_dir> <n5_tiers.json>
  n5_tiers.json: {"language": "strong"|"limited"|"none", ...}
"""
import json
import os
import sys

N4_STRONG = {"php", "javascript", "typescript", "java", "python"}
NON_APP = {"yaml", "json", "generic", "regex", "dockerfile", "hcl", "terraform"}
V2 = ["Dolibarr__dolibarr", "FreshRSS__FreshRSS", "OWASP__NodeGoat", "WebGoat__WebGoat",
      "chatwoot__chatwoot", "digininja__DVWA", "getredash__redash", "jellyfin__jellyfin",
      "juice-shop__juice-shop", "librenms__librenms", "mastodon__mastodon", "n8n-io__n8n",
      "nilsteampassnet__TeamPass", "nocodb__nocodb", "nopSolutions__nopCommerce"]
F1 = ["DVWA", "NodeGoat", "WebGoat", "dvpwa", "juice-shop"]


def confident(langs, strong):
    app = {l["language"]: l["loc"] for l in langs if l["language"] not in NON_APP and l["loc"] > 0}
    total = sum(app.values())
    if not total:
        return None, 0.0
    frac = sum(v for k, v in app.items() if k in strong) / total
    return frac > 0.5, frac


def main(scan_dir, tiers_path):
    n5 = json.load(open(tiers_path))
    n5_strong = {l for l, t in n5.items() if t == "strong"}
    rows = []
    for group, names in (("V2", V2), ("F1", F1)):
        for name in names:
            p = os.path.join(scan_dir, name + ".json")
            if not os.path.exists(p):
                rows.append((group, name, None, None, None, None, "no scan"))
                continue
            cov = json.load(open(p)).get("coverage")
            if not cov:
                rows.append((group, name, None, None, None, None, "no coverage (scan failed or timed out)"))
                continue
            before, fb = confident(cov["languages"], N4_STRONG)
            after, fa = confident(cov["languages"], n5_strong)
            top = ", ".join(f"{l['language']} {round(l['share'] * 100)}%" for l in cov["languages"][:3])
            rows.append((group, name, before, after, fb, fa, top))
    flips = [r for r in rows if r[2] is not None and r[2] != r[3]]
    for g, n, b, a, fb, fa, top in rows:
        mark = "FLIP" if (b is not None and b != a) else "    "
        st = lambda x: "measured" if x else ("not measured" if x is False else "-")
        print(f"{mark} {g} {n:28s} {st(b):13s} -> {st(a):13s} strong {fb or 0:.0%} -> {fa or 0:.0%}  [{top}]")
    print(f"\n{len(flips)} change state: "
          f"{sum(1 for r in flips if r[2] and not r[3])} measured -> not measured, "
          f"{sum(1 for r in flips if not r[2] and r[3])} not measured -> measured")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
