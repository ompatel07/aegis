"""P3: write the shipped triage (services/scanner/accuracy/triage.json) for the P3 rules.

real          replaced by the after-state ledger (p3_ledger.py --entries, over three
              product scans of each repository with P3's rules; the Python SQL rule's
              findings from py_rule_runs.py): every finding of a shipped coverage rule,
              by location, with its verdict and "stable" (in all three scans).
ground-truth  kept, with exactly the changes the rule edits made on those corpora
              (gt_diff.py): two recorded FPs no longer produced, dvpwa's SQL finding
              moved from the assignment to the execute call, and pygoat's new one.

usage: python build_triage_p3.py <after_entries.json> [--write]
"""
import collections
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TRIAGE = os.path.join(REPO, "services", "scanner", "accuracy", "triage.json")

REMOVED = {  # (corpus, file, line, rule): produced before P3, not after
    ("dvws-node", "src/controllers/passphrase.js", 62, "aegis-js-xss"),
    ("oopssec-store", "packages/create-oss-store/bin/create-oss-store.js", 31, "aegis-js-redos-nested-quantifier"),
}
MOVED = {("dvpwa-full", "sqli/dao/student.py", 42, "aegis-py-sql-string-construction"): 45}
ADDED = [{"corpus": "pygoat", "kind": "ground-truth", "language": "python",
          "file": "dockerized_labs/sql_injection_lab/app.py", "line": 57,
          "rule": "aegis-py-sql-string-construction", "verdict": "TP",
          "why": "P3: the lab's documented login SQL injection (an f-string reaching cursor.execute)"}]

after = json.load(open(sys.argv[1], encoding="utf-8"))
old = json.load(open(TRIAGE, encoding="utf-8"))
out = []
for t in old:
    if t["kind"] == "real":
        continue
    key = (t["corpus"], t["file"], t["line"], t["rule"])
    if key in REMOVED:
        continue
    if key in MOVED:
        t = dict(t, line=MOVED[key], why=t.get("why", "") + "; P3: now reported at the execute call")
    out.append(t)
out += ADDED
for e in after:
    if e["rule_kind"] != "coverage":
        continue
    out.append({k: e[k] for k in ("corpus", "kind", "language", "file", "line", "rule", "verdict", "why", "role",
                                  "stable")})
c = collections.Counter((t["kind"], t["verdict"]) for t in out)
print(len(old), "->", len(out), dict(sorted(c.items())))
if "--write" in sys.argv:
    json.dump(out, open(TRIAGE, "w", encoding="utf-8"), indent=1)
    print("wrote", TRIAGE)
