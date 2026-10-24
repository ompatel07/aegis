"""P3: print each sampled stored-XSS finding with the code before it, for triage.
usage (scanner container): python3 show_sample.py <sample.json> <from> <to> [<before>=12]"""
import json
import sys

s = json.load(open(sys.argv[1], encoding="utf-8"))["sample"]
lo, hi = int(sys.argv[2]), int(sys.argv[3])
before = int(sys.argv[4]) if len(sys.argv) > 4 else 12
for i, x in enumerate(s[lo:hi], lo):
    lines = open(f"/workspaces/_p3/{x['corpus']}/{x['file']}", encoding="utf-8", errors="replace").read().splitlines()
    print(f"===== [{i}] {x['corpus']} {x['file']}:{x['line']}")
    for n in range(max(1, x["line"] - before), x["line"] + 1):
        print(f"{'>>' if n == x['line'] else '  '}{n:5d} {lines[n - 1][:170]}")
