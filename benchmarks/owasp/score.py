"""Score Aegis against OWASP Benchmark v1.2. Computes TPR/FPR/F1 overall and
per category, matching a finding to a test case by file + expected CWE (with a
category fallback via rule-id/owasp when a rule omits its CWE)."""
import csv, json, os, re

BASE = "/workspaces/owasp-benchmark"
CSV = f"{BASE}/expectedresults-1.2.csv"
FINDINGS = "/v/_aegis_findings.json"

# Benchmark category -> acceptable CWE set (includes standard related CWEs, e.g.
# crypto 327 ~ 326/310; the OWASP scorer likewise credits related CWEs).
CAT_CWES = {
    "cmdi": {"78"}, "crypto": {"327", "326", "310"}, "hash": {"328", "327", "326", "916"},
    "ldapi": {"90"}, "pathtraver": {"22", "23", "36", "73"}, "securecookie": {"614", "1004"},
    "sqli": {"89"}, "trustbound": {"501"}, "weakrand": {"330", "338"},
    "xpathi": {"643"}, "xss": {"79", "80"},
}

# Fallback: map a finding's rule-id / owasp text to a Benchmark category.
RULE_HINTS = {
    "sqli": ["sql", "sqli", "injection.sql"], "xss": ["xss", "cross-site", "xss-"],
    "cmdi": ["command", "cmdi", "os-command", "exec"], "pathtraver": ["path", "traversal", "pathtraver"],
    "ldapi": ["ldap"], "xpathi": ["xpath"], "crypto": ["cipher", "crypto", "des", "weak-crypto", "insecure-cipher"],
    "hash": ["hash", "md5", "sha1", "message-digest"], "weakrand": ["random", "rand", "insecure-random"],
    "securecookie": ["cookie", "secure-flag"], "trustbound": ["trust", "session", "trustbound"],
}

def test_name(path):
    m = re.search(r"(BenchmarkTest\d+)", path or "")
    return m.group(1) if m else None

def cwe_num(v):
    m = re.search(r"(\d+)", v or "")
    return m.group(1) if m else None

# expected
expected = {}  # name -> (category, real_bool, cwe)
with open(CSV) as fh:
    for row in csv.reader(fh):
        if not row or row[0].startswith("#") or row[0] == "":
            continue
        name, cat, real, cwe = row[0].strip(), row[1].strip(), row[2].strip(), row[3].strip()
        if name.startswith("BenchmarkTest"):
            expected[name] = (cat, real.lower() == "true", cwe)

# findings grouped per test file
by_file = {}  # name -> {"cwes": set, "cats": set}
with open(FINDINGS) as fh:
    for f in json.load(fh):
        name = test_name(f.get("file"))
        if not name:
            continue
        d = by_file.setdefault(name, {"cwes": set(), "cats": set()})
        c = cwe_num(f.get("cwe"))
        if c:
            d["cwes"].add(c)
        text = (str(f.get("rule", "")) + " " + str(f.get("owasp", ""))).lower()
        for cat, hints in RULE_HINTS.items():
            if any(h in text for h in hints):
                d["cats"].add(cat)

def flagged(name, cat, exp_cwe, mode):
    d = by_file.get(name)
    if not d:
        return False
    accept = CAT_CWES.get(cat, {exp_cwe})
    if mode == "cwe":
        return bool(d["cwes"] & accept)
    # lenient: acceptable CWE OR category hint from rule/owasp text
    return bool(d["cwes"] & accept) or cat in d["cats"]

def score(mode):
    cats = {}
    TP = FP = FN = TN = 0
    for name, (cat, real, exp_cwe) in expected.items():
        hit = flagged(name, cat, exp_cwe, mode)
        c = cats.setdefault(cat, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
        if real and hit: TP += 1; c["tp"] += 1
        elif real and not hit: FN += 1; c["fn"] += 1
        elif not real and hit: FP += 1; c["fp"] += 1
        else: TN += 1; c["tn"] += 1
    tpr = TP / (TP + FN) if TP + FN else 0
    fpr = FP / (FP + TN) if FP + TN else 0
    f1 = 2 * TP / (2 * TP + FP + FN) if (2 * TP + FP + FN) else 0
    return {"mode": mode, "TP": TP, "FP": FP, "FN": FN, "TN": TN,
            "TPR": round(tpr, 4), "FPR": round(fpr, 4), "F1": round(f1, 4),
            "youden": round(tpr - fpr, 4), "by_cat": cats}

for mode in ("cwe", "lenient"):
    s = score(mode)
    print(f"\n=== MODE={mode} ===")
    print(f"TP={s['TP']} FP={s['FP']} FN={s['FN']} TN={s['TN']}")
    print(f"TPR={s['TPR']} FPR={s['FPR']} F1={s['F1']} Youden(TPR-FPR)={s['youden']}")
    print("per-category (cat: TP/FP/FN/TN):")
    for cat, c in sorted(s["by_cat"].items()):
        print(f"  {cat:14s} {c['tp']:3d}/{c['fp']:3d}/{c['fn']:3d}/{c['tn']:3d}")
