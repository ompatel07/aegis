"""Pass N5 Part E: re-score N4's 17 ground-truth corpora on the N5 scans.

N4's statuses were set by hand (docs/ground_truth_n4/gt_items.json). Only items a
changed rule can reach may move, so this lists, for review:
  LOST  an N4 detection whose catching rule no longer reports in the item's file/method
  NEW   a finding of an N5-changed rule in the file/method of a not-detected IN item
The decisions are recorded in OVERRIDES (in rescore_decisions.py) by id, with the reason.

usage: python rescore_n4.py <n4_gt_items.json> <vulnapp_items.json> <scan_dir>
"""
import fnmatch
import json
import os
import re
import sys

CHANGED = {"aegis-java-xss", "aegis-java-sql-injection", "aegis-py-command-injection",
           "aegis-py-shell-command-construction", "aegis-py-unsafe-deserialization",
           "aegis-py-flask-debug-enabled"}
RULE_RE = re.compile(r"(aegis-[a-z0-9-]+|ajinabraham\.[\w.]+)")


def item_files(loc):
    """'a/b.py:12', 'a/b.py:12-30', 'a/b.py', 'x/*/{n}.java', 'a.py:3 -> helpers.run_cmd'."""
    head = loc.split(" ")[0].split("->")[0].strip()
    head = re.sub(r":\d+(-\d+)?$", "", head)
    return head


def matches(path, pat):
    return fnmatch.fnmatch(path, "*" + pat) or path.endswith(pat)


def main(gt_path, va_path, scan_dir):
    gt = json.load(open(gt_path, encoding="utf-8"))
    va = {f"{t}@{it['method']}:{it['start']}": it for it in json.load(open(va_path)) for t in it["types"]}
    report = []
    for corpus, c in gt.items():
        p = os.path.join(scan_dir, corpus + ".json")
        if not os.path.exists(p):
            report.append(f"{corpus}: NO SCAN")
            continue
        fs = [f for f in json.load(open(p))["findings"] if f.get("pillar") in (None, "security")]
        for it in c["items"]:
            if it["scope"] != "IN":
                continue
            if corpus == "vulnerableapp":
                m = va.get(it["id"])
                near = [f for f in fs if m and f["file"] == m["file"] and m["start"] <= f["line"] <= m["end"]]
            else:
                pat = item_files(it["location"])
                near = [f for f in fs if matches(f["file"], pat)]
            rules_now = {f["rule"] for f in near}
            if it["status"] == "DET":
                caught = set(RULE_RE.findall(it["rule_or_reason"]))
                if caught and not (caught & rules_now):
                    report.append(f"LOST {corpus} {it['id']} {it['location']} was {sorted(caught)} now {sorted(rules_now)}")
            else:
                new = sorted({(f["rule"], f["line"]) for f in near if f["rule"] in CHANGED})
                if new:
                    report.append(f"NEW  {corpus} {it['id']} [{it['status']}] {it['item']} @ {it['location']} :: {new}")
    print("\n".join(report))


if __name__ == "__main__":
    main(*sys.argv[1:4])
