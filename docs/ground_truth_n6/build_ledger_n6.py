"""Pass N6: extend N5's evidence (services/scanner/accuracy/) with
  - the five JS/TS corpora (jsts_items.py, scored by score_jsts.py), role from the N6 draw;
  - the precision-holdout role of every real-repository finding (holdout_n6.json);
  - CodeQL's status on every held-out item of the corpora it ran on (codeql_status.json,
    produced by codeql_score.py), and why it did not run elsewhere.
No N5 status or verdict changes: N6 changes no rule.

usage: python build_ledger_n6.py <jsts_scan_dir> [<codeql_status.json>] [--write]
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
ACC = os.path.join(REPO, "services", "scanner", "accuracy")
sys.path.insert(0, HERE)
import score_jsts  # noqa: E402

# Why CodeQL did not run on a held-out corpus (docs/SECURITY_GATES_N6.md §0.4).
NOT_RUN = {
    "php": "CodeQL has no PHP support",
    "java-sec-code": "no license file: not an Open Source Codebase under CodeQL's terms",
    "govwa": "no license file: not an Open Source Codebase under CodeQL's terms",
}


def build(jsts_dir, codeql_path=None):
    gt = json.load(open(os.path.join(ACC, "gt_items.json"), encoding="utf-8"))
    triage = json.load(open(os.path.join(ACC, "triage.json"), encoding="utf-8"))
    hold = json.load(open(os.path.join(ACC, "holdout_n6.json"), encoding="utf-8"))

    items, jt, problems = score_jsts.run(jsts_dir)
    roles = {c: "held_out" for d in hold["languages"].values() for c in d["held_out"]}
    for name, c in items.items():
        gt[name] = {**c, "role": roles.get(name, "tuning")}
    triage = [t for t in triage if t["corpus"] not in items] + [
        {k: t[k] for k in ("corpus", "kind", "language", "file", "line", "rule", "verdict", "why")} for t in jt]

    held_real = set(hold["precision"]["held_out"])
    for t in triage:
        if t["kind"] == "real":
            t["role"] = "held_out" if t["corpus"] in held_real else "tuning"

    status = json.load(open(codeql_path, encoding="utf-8")) if codeql_path else {}
    for name, c in gt.items():
        if c.get("role") != "held_out":
            continue
        if name in status:
            c["codeql"] = {"ran": True, "version": status[name]["version"], "suite": status[name]["suite"],
                           "alerts": status[name]["alerts"]}
            for it in c["items"]:
                if it["scope"] == "IN":
                    it["codeql"] = status[name]["items"].get(it["id"], "MISS")
        else:
            c["codeql"] = {"ran": False, "reason": NOT_RUN.get(name) or NOT_RUN.get(c["language"])
                           or "not run"}
    return gt, triage, problems


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    gt, triage, problems = build(*args)
    for p in problems:
        print("CHECK", p)
    un = [t for t in triage if t["verdict"] == "UNTRIAGED" and t["language"] not in ("yaml", "other")]
    print(f"{len(gt)} corpora, {len(triage)} findings, {len(un)} untriaged (application languages)")
    if "--write" in sys.argv:
        json.dump(gt, open(os.path.join(ACC, "gt_items.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        json.dump(triage, open(os.path.join(ACC, "triage.json"), "w", encoding="utf-8"), indent=0, ensure_ascii=False)
        print("written", ACC)
