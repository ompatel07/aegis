"""Pass N6 Part E: the commercial number. Each V2/F1 repository's quadrant, from its own
per-language LOC (its scan's security_coverage) and the measured per-language gates:
a repository passes a gate when more than half its application code is in languages
that pass it (utils/rule_coverage.summarise).

usage: python quadrant_count.py <scan_dir> <gates.json>
  gates.json: {"language": [recall_ok, precision_ok], ...}
"""
import collections
import json
import os
import sys

NON_APP = {"yaml", "json", "generic", "regex", "dockerfile", "hcl", "terraform"}
V2 = ["Dolibarr__dolibarr", "FreshRSS__FreshRSS", "OWASP__NodeGoat", "WebGoat__WebGoat",
      "chatwoot__chatwoot", "digininja__DVWA", "getredash__redash", "jellyfin__jellyfin",
      "juice-shop__juice-shop", "librenms__librenms", "mastodon__mastodon", "n8n-io__n8n",
      "nilsteampassnet__TeamPass", "nocodb__nocodb", "nopSolutions__nopCommerce"]
F1 = ["DVWA", "NodeGoat", "WebGoat", "dvpwa", "juice-shop"]


def quadrant(r, p):
    return "full" if r and p else "problem-only" if p else "clean-only" if r else "withheld"


def main(scan_dir, gates_path):
    gates = json.load(open(gates_path))
    counts = collections.Counter()
    for group, names in (("V2", V2), ("F1", F1)):
        for name in names:
            p = os.path.join(scan_dir, name + ".json")
            cov = json.load(open(p)).get("coverage") if os.path.exists(p) else None
            if not cov:
                print(f"{group} {name:28s} no coverage")
                continue
            app = {l["language"]: l["loc"] for l in cov["languages"] if l["language"] not in NON_APP and l["loc"] > 0}
            total = sum(app.values())
            rf = sum(v for k, v in app.items() if gates.get(k, [False, False])[0]) / total
            pf = sum(v for k, v in app.items() if gates.get(k, [False, False])[1]) / total
            q = quadrant(rf > 0.5, pf > 0.5)
            counts[(group, q)] += 1
            top = ", ".join(f"{l['language']} {round(l['share'] * 100)}%" for l in cov["languages"][:3])
            print(f"{group} {name:28s} {q:12s} recall-certified {rf:.0%}  precision-certified {pf:.0%}  [{top}]")
    print()
    for g in ("V2", "F1"):
        print(g, {q: counts[(g, q)] for q in ("full", "problem-only", "clean-only", "withheld")})


if __name__ == "__main__":
    main(*sys.argv[1:3])
