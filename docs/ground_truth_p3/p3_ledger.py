"""P3: real-repository precision from repeat scans (docs/D2_DETERMINISM.md §4).

For every real-repository corpus scanned N times on its commit (docs/d2/d2_run.py), a
finding is STABLE if it is in every run. Verdicts come, in order, from P3's own triage
(p3_verdicts.py), the shipped triage (accuracy/triage.json, same file/line/rule), and
N5's per-(repo, rule) defaults and exceptions (docs/ground_truth_n5/real_verdicts.py);
no source -> UNTRIAGED. Precision is computed on stable findings of shipped coverage
rules, per language and holdout role, with Wilson 95% intervals; silent-clean rules
(aegis-php-stored-xss) are reported on their own line and gate nothing.

usage (scanner container, /app = services/scanner):
  python3 p3_ledger.py <scan_dir> [--entries out.json] [--untriaged]
"""
import collections
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "ground_truth_n5"))
sys.path.insert(0, "/app")
import p3_verdicts as P  # noqa: E402
import real_verdicts as R  # noqa: E402
from utils import rule_coverage as rc  # noqa: E402
from utils import tier_bar as tb  # noqa: E402

EXT = {".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
       ".ts": "typescript", ".tsx": "typescript", ".py": "python", ".java": "java", ".go": "go",
       ".php": "php", ".inc": "php", ".phtml": "php"}
APPS = {"php", "python", "javascript", "typescript", "go", "java"}


def lang_of(path):
    return EXT.get(os.path.splitext(path)[1].lower(), "yaml" if path.endswith((".yml", ".yaml")) else "other")


def short(rule):
    i = rule.find("ajinabraham.")
    return rule[i:] if i >= 0 else rule.split(".")[-1]


def _except(table, corpus, file, line, rule):
    for (c, suffix, ln, r), v in table.items():
        if c == corpus and r == rule and ln == line and file.endswith(suffix):
            return v
    return None


def verdict(corpus, file, line, rule, shipped_v):
    """P3 exceptions, P3 defaults, N5 exceptions, the shipped verdict at this exact
    location, N5 defaults -- the most specific source first."""
    return (_except(P.EXCEPT, corpus, file, line, rule)
            or P.DEFAULT.get((corpus, rule))
            or _except(R.EXCEPT, corpus, file, line, rule)
            or shipped_v.get((corpus, file, line, rule))
            or R.DEFAULT.get((corpus, rule))
            or ("UNTRIAGED", ""))


def main():
    scan_dir = sys.argv[1]
    triage = json.load(open("/app/accuracy/triage.json", encoding="utf-8"))
    shipped_v = {(t["corpus"], t["file"], t["line"], t["rule"]): (t["verdict"], t.get("why", ""))
                 for t in triage if t["kind"] == tb.REAL}
    drawn = json.load(open("/app/accuracy/holdout_n6.json", encoding="utf-8"))["precision"]
    held = set(drawn["held_out"])
    coverage_rules = rc.shipped_rule_languages()
    silent = rc.silent_clean_rule_ids()

    def load(d_dir):
        out = collections.defaultdict(dict)
        for f in sorted(glob.glob(os.path.join(d_dir, "*.run*.json"))):
            d = json.load(open(f, encoding="utf-8"))
            out[d["repo"]][d["run"]] = {(short(r), fp, ln) for r, fp, ln in d["findings"]}
        return out

    loaded = load(scan_dir)
    if "--replace" in sys.argv:
        # --replace <rule> <dir>: that rule's findings come from <dir>, run by run
        rule_r, dir_r = sys.argv[sys.argv.index("--replace") + 1: sys.argv.index("--replace") + 3]
        repl = load(dir_r)
        for repo, by_run in loaded.items():
            for i, s in by_run.items():
                by_run[i] = {x for x in s if x[0] != rule_r} | {x for x in repl.get(repo, {}).get(i, set())
                                                                  if x[0] == rule_r}
    runs = {repo: [s for _, s in sorted(by_run.items())] for repo, by_run in loaded.items()}

    entries = []
    for corpus, sets in sorted(runs.items()):
        stable = set.intersection(*sets)
        for rule, file, line in sorted(set.union(*sets)):
            lang = lang_of(file)
            if rule in silent:
                kind = "silent-clean"
            elif lang in coverage_rules.get(rule, ()) or (lang == "yaml" and rule in coverage_rules):
                kind = "coverage"
            else:
                continue  # quality-pillar or non-security rule: not precision evidence
            v, why = verdict(corpus, file, line, rule, shipped_v)
            entries.append({"corpus": corpus, "kind": tb.REAL, "language": lang, "file": file, "line": line,
                            "rule": rule, "verdict": v, "why": why,
                            "role": tb.HELD_OUT if corpus in held else tb.TUNING,
                            "stable": (rule, file, line) in stable, "rule_kind": kind})

    def table(rows, title):
        print(f"\n{title}")
        print("| language | role | TP | FP | UNC | UNTRIAGED | precision (95% CI) | unstable |")
        print("|---|---|---|---|---|---|---|---|")
        agg = collections.defaultdict(collections.Counter)
        for e in rows:
            k = (e["language"], e["role"])
            agg[k]["unstable" if not e["stable"] else e["verdict"]] += 1
        for (lang, role), c in sorted(agg.items()):
            n = c["TP"] + c["FP"]
            w = tb.wilson(c["TP"], n)
            ci = f"{c['TP']}/{n} = {c['TP'] / n:.0%} [{w[0]:.0%}, {w[1]:.0%}]" if w else "-"
            print(f"| {lang} | {role} | {c['TP']} | {c['FP']} | {c['UNCERTAIN']} | {c['UNTRIAGED']} | {ci} | {c['unstable']} |")

    apps = [e for e in entries if e["language"] in APPS]
    table([e for e in apps if e["rule_kind"] == "coverage"], "coverage rules (the precision gate: held_out rows)")
    table([e for e in apps if e["rule_kind"] == "silent-clean"], "silent-clean rules (gate nothing)")
    if "--untriaged" in sys.argv:
        for e in entries:
            if e["verdict"] == "UNTRIAGED" and e["language"] in APPS:
                print("UNTRIAGED", e["corpus"], e["file"], e["line"], e["rule"], "stable" if e["stable"] else "unstable")
    if "--entries" in sys.argv:
        json.dump(entries, open(sys.argv[sys.argv.index("--entries") + 1], "w", encoding="utf-8"), indent=0)


if __name__ == "__main__":
    main()
