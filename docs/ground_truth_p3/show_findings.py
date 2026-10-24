"""P3 Part B: print the source line of every recorded real-repo finding of one rule on
the TUNING half, so each FP can be tied to a root cause. Reads triage.json and the
clones at their recorded commits (docs/d2/real_commits.txt).

usage (scanner container): python3 show_findings.py <rule> [<role>=tuning] [<clones>=/workspaces/_p3]
"""
import json
import os
import sys

rule = sys.argv[1]
role = sys.argv[2] if len(sys.argv) > 2 else "tuning"
clones = sys.argv[3] if len(sys.argv) > 3 else "/workspaces/_p3"
triage = json.load(open("/app/accuracy/triage.json", encoding="utf-8"))
for t in triage:
    if t["kind"] != "real" or t["rule"] != rule or t["role"] != role:
        continue
    root = os.path.join(clones, t["corpus"])
    path = next((os.path.join(dp, f) for dp, _, fs in os.walk(root) for f in fs
                 if os.path.join(dp, f).endswith("/" + t["file"])), None)
    line = "<file not found>"
    if path:
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
        line = lines[t["line"] - 1].strip() if t["line"] <= len(lines) else "<line out of range>"
    print(f"{t['verdict']:9s} {t['corpus']}:{t['file']}:{t['line']}  {line[:150]}")
