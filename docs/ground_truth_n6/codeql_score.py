"""Pass N6 Part C: score CodeQL on the held-out ground truth, item by item, by the same
rule Aegis is scored by -- an alert of the item's class at the item.

`candidates` lists, for every in-scope held-out item of a corpus CodeQL ran on, the
CodeQL alerts in the item's file (within WINDOW lines when the item names a line), for a
reviewer. The decisions are recorded in codeql_decisions.py (item -> DET + the query),
and `status` writes codeql_status.json for build_ledger_n6.py.

usage: python codeql_score.py candidates <sarif_dir> <gt_items.json>
       python codeql_score.py status <sarif_dir> <gt_items.json> <out.json>
"""
import json
import os
import re
import sys

WINDOW = 5
VERSION = "CodeQL CLI 2.27.3 (codeql-bundle-v2.27.3)"
SUITE = "<lang>-security-extended.qls, default configuration"


def alerts(sarif_path):
    d = json.load(open(sarif_path, encoding="utf-8"))
    out = []
    for run in d["runs"]:
        rules = {}
        for r in run["tool"]["driver"].get("rules", []):
            tags = (r.get("properties") or {}).get("tags", [])
            rules[r["id"]] = [t.split("/")[-1].upper() for t in tags if "cwe" in t.lower()]
        for e in run.get("extensions", []) or []:
            for r in e.get("rules", []):
                tags = (r.get("properties") or {}).get("tags", [])
                rules.setdefault(r["id"], [t.split("/")[-1].upper() for t in tags if "cwe" in t.lower()])
        for res in run["results"]:
            loc = res["locations"][0]["physicalLocation"]
            out.append({"rule": res["ruleId"], "cwe": rules.get(res["ruleId"], []),
                        "file": loc["artifactLocation"]["uri"], "line": loc.get("region", {}).get("startLine", 0),
                        "msg": res["message"]["text"][:120]})
    return out


def target(location):
    """'a/b.py:12' -> ('a/b.py', 12); 'a/b.py' -> ('a/b.py', None); '-' -> (None, None)."""
    head = location.split(" ")[0].split("->")[0].strip()
    m = re.match(r"(.+?):(\d+)(?:-\d+)?$", head)
    if m:
        return m.group(1), int(m.group(2))
    return (head if head not in ("-", "") else None), None


def near(a, f, line):
    if not f or not (a["file"].endswith(f) or f.endswith(a["file"]) or ("*" in f and re.fullmatch(f.replace("*", ".*"), a["file"]))):
        return False
    return line is None or abs(a["line"] - line) <= WINDOW


def main():
    mode, sarif_dir, gt_path = sys.argv[1:4]
    gt = json.load(open(gt_path, encoding="utf-8"))
    if mode == "candidates":
        for name in sorted(os.listdir(sarif_dir)):
            if not name.endswith(".sarif"):
                continue
            corpus = name[:-6]
            al = alerts(os.path.join(sarif_dir, name))
            print(f"===== {corpus}: {len(al)} alerts")
            for it in gt[corpus]["items"]:
                if it["scope"] != "IN":
                    continue
                f, line = target(it["location"])
                c = [a for a in al if near(a, f, line)]
                print(f"  {it['id']:38s} [aegis {it['status']}] {it['location'][:60]}")
                for a in c:
                    print(f"      -> {a['rule']} {a['cwe'][:3]} {a['file'][-45:]}:{a['line']}")
    else:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import codeql_decisions as D
        out = {}
        for name in sorted(os.listdir(sarif_dir)):
            if not name.endswith(".sarif"):
                continue
            corpus = name[:-6]
            al = alerts(os.path.join(sarif_dir, name))
            out[corpus] = {"version": VERSION, "suite": SUITE.replace("<lang>", gt[corpus]["language"]),
                           "alerts": len(al),
                           "items": {iid: "DET" for iid in D.DETECTED.get(corpus, {})}}
        json.dump(out, open(sys.argv[4], "w"), indent=1)
        print({k: len(v["items"]) for k, v in out.items()})


if __name__ == "__main__":
    main()
