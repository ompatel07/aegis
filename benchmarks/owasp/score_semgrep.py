"""Score a raw Semgrep JSON output against OWASP Benchmark v1.2."""
import csv, json, re, sys
from collections import defaultdict

CSV = "/workspaces/owasp-benchmark/expectedresults-1.2.csv"
SEMGREP_JSON = sys.argv[1] if len(sys.argv) > 1 else "/v/semgrep_profileB.json"
CAT_CWES = {
    "cmdi": {"78"}, "crypto": {"327", "326", "310"}, "hash": {"328", "327", "326", "916"},
    "ldapi": {"90"}, "pathtraver": {"22", "23", "36", "73"}, "securecookie": {"614", "1004"},
    "sqli": {"89"}, "trustbound": {"501"}, "weakrand": {"330", "338"},
    "xpathi": {"643"}, "xss": {"79", "80"},
}

def tn(p):
    m = re.search(r"(BenchmarkTest\d+)", p or ""); return m.group(1) if m else None

expected = {}
with open(CSV) as fh:
    for row in csv.reader(fh):
        if row and row[0].startswith("BenchmarkTest"):
            expected[row[0].strip()] = (row[1].strip(), row[2].strip().lower() == "true")

# semgrep results -> per test file, set of CWE numbers
byfile = defaultdict(set)
data = json.load(open(SEMGREP_JSON))
for r in data.get("results", []):
    name = tn(r.get("path"))
    if not name:
        continue
    meta = (r.get("extra") or {}).get("metadata") or {}
    cwes = meta.get("cwe") or []
    if isinstance(cwes, str):
        cwes = [cwes]
    for c in cwes:
        m = re.search(r"(\d+)", c)
        if m:
            byfile[name].add(m.group(1))

TP = FP = FN = TN = 0
cats = defaultdict(lambda: [0, 0, 0, 0])  # tp,fp,fn,tn
for name, (cat, real) in expected.items():
    accept = CAT_CWES.get(cat, set())
    hit = bool(byfile.get(name, set()) & accept)
    i = 0 if (real and hit) else 2 if (real and not hit) else 1 if (not real and hit) else 3
    cats[cat][i] += 1
    if i == 0: TP += 1
    elif i == 2: FN += 1
    elif i == 1: FP += 1
    else: TN += 1

tpr = TP / (TP + FN) if TP + FN else 0
fpr = FP / (FP + TN) if FP + TN else 0
f1 = 2 * TP / (2 * TP + FP + FN) if (2 * TP + FP + FN) else 0
print(f"file={SEMGREP_JSON}")
print(f"TP={TP} FP={FP} FN={FN} TN={TN}")
print(f"TPR={tpr:.4f} FPR={fpr:.4f} F1={f1:.4f} Youden={tpr-fpr:.4f}")
print("per-cat (tp/fp/fn/tn):")
for cat, v in sorted(cats.items()):
    print(f"  {cat:14s} {v[0]:3d}/{v[1]:3d}/{v[2]:3d}/{v[3]:3d}")
