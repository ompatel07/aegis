"""Pass N5: assemble the evidence the STRONG bar is computed from, and write it into the
scanner image (services/scanner/accuracy/gt_items.json, triage.json).

  gt_items  every documented item of every qualifying ground-truth corpus: N4's 17
            (re-scored on N5 scans, decisions in rescore_decisions.py), the original
            five's (orig5_items.py) and N5's PHP three (php_gt.py); each corpus carries
            its role from the holdout (accuracy/holdout.json), commit and list.
  triage    a verdict for every security finding of the final scans, on the
            ground-truth corpora and on the real-repository corpus. Sources in order:
            N4 triage, N5 PHP triage, N5 ground-truth decisions, N2b (njsscan), N3
            (weakness rules), N5 real-repo triage. No source -> UNTRIAGED.

usage: python build_ledger.py <final_scan_dir> [--write]
"""
import collections
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import orig5_items as O  # noqa: E402
import php_gt as P  # noqa: E402
import real_verdicts as R  # noqa: E402
import rescore_decisions as D  # noqa: E402
import score_php  # noqa: E402

EXT = {".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
       ".ts": "typescript", ".tsx": "typescript", ".py": "python", ".java": "java", ".go": "go",
       ".php": "php", ".inc": "php"}
RULE_RE = re.compile(r"(aegis-[a-z0-9-]+|ajinabraham\.[\w.]+)")
PROMOTED = {("vulnerableapp", "aegis-java-weak-cipher"), ("dvga-go", "aegis-go-weak-hash-credential"),
            ("dvga-go", "aegis-go-insecure-session-cookie")}  # N4 promotions: their own evidence
# The real-repository corpus: V2's 15 at recorded commits, N3's extended cmp-* repositories
# and spring-petclinic. NodeGoat, juice-shop, DVWA and WebGoat are ground-truth corpora and
# are counted once, there. n8n's SAST times out (T2), so it yields no finding.
GT_ALIASES = {"OWASP__NodeGoat", "juice-shop__juice-shop", "digininja__DVWA", "WebGoat__WebGoat"}


def lang_of(path):
    return EXT.get(os.path.splitext(path)[1].lower(), "yaml" if path.endswith((".yml", ".yaml")) else "other")


def security(scan):
    return [f for f in scan["findings"] if f.get("pillar") in (None, "security")]


def prior_verdicts():
    v = {}
    for x in json.load(open(os.path.join(REPO, "docs/njsscan_n2b/verdicts.json"))):
        v[(x["slug"].replace("/", "__"), x["file"], x["line"], x["rule"])] = (x["verdict"], x.get("note") or "N2b", "n2b")
    for x in json.load(open(os.path.join(REPO, "docs/owasp_n3/verdicts.json")))["final_findings"]:
        for r in [x["repo"]] + x.get("seen_in", []):
            v[(r, x["file"], x["line"], x["rule"])] = (x["verdict"], x.get("note") or "N3", "n3")
    for x in json.load(open(os.path.join(REPO, "docs/ground_truth_n4/triage.json"))):
        v[(x["corpus"], x["file"], x["line"], x["rule"])] = (x["verdict"], x.get("why") or "N4", "n4")
    return v


def verdict(prior, keys, corpus, f):
    for k in keys:
        hit = prior.get((k, f["file"], f["line"], f["rule"]))
        if hit:
            return hit
    for (c, suf, ln, rule), (vv, why) in D.GT_VERDICTS.items():
        if c == corpus and f["file"].endswith(suf) and f["line"] == ln and f["rule"] == rule:
            return vv, why, "n5"
    for (c, suf, ln, rule), (vv, why) in R.EXCEPT.items():
        if c == corpus and f["file"].endswith(suf) and f["line"] == ln and f["rule"].endswith(rule):
            return vv, why, "n5"
    for (c, rule), (vv, why) in list(R.DEFAULT.items()) + list(D.GT_DEFAULT.items()):
        if c == corpus and f["rule"].endswith(rule):
            return vv, why, "n5"
    if f["rule"].startswith(("aegis-cicd", "aegis-compose")):
        return "TP", "per rule semantics (unpinned action tag / 0.0.0.0 bind)", "n4-convention"
    return "UNTRIAGED", "", ""


def n4_items(scan_dir, holdout, candidates):
    gt = json.load(open(os.path.join(REPO, "docs/ground_truth_n4/gt_items.json"), encoding="utf-8"))
    roles = {c: "held_out" for l in holdout["languages"].values() for c in l["held_out"]}
    commits = {c["repo"].split("/")[-1].lower(): c["commit"] for c in candidates}
    out = {}
    for corpus, c in gt.items():
        items = []
        for it in c["items"]:
            it = dict(it)
            ov = D.OVERRIDES.get((corpus, it["id"]))
            if ov:
                it["status"], it["rules"], it["rule_or_reason"] = ov[0], ov[1], ov[2]
                it["n5"] = "re-scored"
            else:
                it["rules"] = sorted(set(RULE_RE.findall(it["rule_or_reason"]))) if it["status"] == "DET" else []
            if any((corpus, r) in PROMOTED for r in it["rules"]):
                it["promotion_evidence"] = True
            items.append(it)
        out[corpus] = {"language": c["language"], "documented_list": c["documented_list"],
                       "role": roles.get(corpus, "tuning"), "commit": D.N4_COMMITS[corpus], "items": items}
    return out


def build(scan_dir):
    holdout = json.load(open(os.path.join(REPO, "services/scanner/accuracy/holdout.json")))
    candidates = json.load(open(os.path.join(REPO, "docs/ground_truth_n4/candidates.json")))
    gt = n4_items(scan_dir, holdout, candidates)
    for corpus, (lang, listdesc, rows) in O.ITEMS.items():
        gt[corpus] = {"language": lang, "documented_list": listdesc, "role": "tuning", "commit": O.COMMITS[corpus],
                      "items": [dict(zip(("id", "item", "location", "scope", "status", "rules", "rule_or_reason"), r))
                                for r in rows]}
    php_items, php_triage, problems = score_php.run(scan_dir)
    gt.update(php_items)

    prior = prior_verdicts()
    triage = []
    for t in php_triage:
        triage.append({**t, "source": "n5"})
    for corpus, scan_name, keys in D.GT_SCANS:
        p = os.path.join(scan_dir, scan_name + ".json")
        for f in security(json.load(open(p))):
            v, why, src = verdict(prior, keys, corpus, f)
            triage.append({"corpus": corpus, "kind": "ground-truth", "language": lang_of(f["file"]),
                           "file": f["file"], "line": f["line"], "rule": f["rule"], "verdict": v,
                           "why": why, "source": src})
    for name in sorted(os.listdir(scan_dir)):
        repo = name[:-5]
        if not (repo in D.REAL) or repo in GT_ALIASES:
            continue
        for f in security(json.load(open(os.path.join(scan_dir, name)))):
            v, why, src = verdict(prior, [repo], repo, f)
            triage.append({"corpus": repo, "kind": "real", "language": lang_of(f["file"]), "file": f["file"],
                           "line": f["line"], "rule": f["rule"], "verdict": v, "why": why, "source": src})
    return gt, triage, problems


if __name__ == "__main__":
    gt, triage, problems = build(sys.argv[1])
    for p in problems:
        print("CHECK", p)
    un = [t for t in triage if t["verdict"] == "UNTRIAGED" and t["language"] not in ("yaml", "other")]
    print(f"{len(triage)} findings, {len(un)} untriaged (application languages)")
    for t in un[:400]:
        print("  UNTRIAGED", t["corpus"], t["file"], t["line"], t["rule"])
    c = collections.Counter((t["language"], t["kind"], t["verdict"]) for t in triage)
    for k in sorted(c):
        print(" ", k, c[k])
    if "--write" in sys.argv:
        acc = os.path.join(REPO, "services/scanner/accuracy")
        slim = [{k: t[k] for k in ("corpus", "kind", "language", "file", "line", "rule", "verdict", "why")} for t in triage]
        json.dump(gt, open(os.path.join(acc, "gt_items.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        json.dump(slim, open(os.path.join(acc, "triage.json"), "w", encoding="utf-8"), indent=0, ensure_ascii=False)
        print("written", acc)
