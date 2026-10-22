"""Score the PHP ground truth (php_gt.py) against a scan directory and triage every
security finding. usage: python score_php.py <scan_dir> <out.json>

Checks the hand statuses against the scan: a DET item must have a TRUE-POSITIVE finding of
one of its rules in its file (or the back-end / include file named for it), and a non-DET
IN item with such a finding is reported for review."""
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import php_gt as G  # noqa: E402

PREFIX = {"bwapp": "app/", "mutillidae": "src/", "xvwa": ""}


def verdict(corpus, f):
    for (c, suf, ln, rs), (v, why) in G.TRIAGE.items():
        if c == corpus and f["file"].endswith(suf) and f["line"] == ln and f["rule"].endswith(rs):
            return v, why
    return "TP", ""


def run(scan_dir):
    triage, items, problems = [], {}, []
    for corpus in ("bwapp", "mutillidae", "xvwa"):
        fs = [f for f in json.load(open(os.path.join(scan_dir, corpus + ".json")))["findings"]
              if f.get("pillar") in (None, "security")]
        tps = collections.defaultdict(set)  # file -> rules with a TP finding
        for f in fs:
            v, why = verdict(corpus, f)
            lang = "php" if f["file"].endswith((".php", ".inc")) else "yaml"
            triage.append({"corpus": corpus, "kind": "ground-truth", "language": lang, "file": f["file"],
                           "line": f["line"], "rule": f["rule"], "verdict": v, "why": why})
            if v == "TP":
                tps[f["file"][len(PREFIX[corpus]):]].add(f["rule"])
        rows = []
        if corpus == "bwapp":
            for fn, (scope, st, rules, why) in G.BWAPP.items():
                files = [fn] + G.BWAPP_FAMILY.get(fn, [])
                rows.append((fn, fn, files, scope, st, rules, why))
        elif corpus == "mutillidae":
            for page, iid, text, scope, st, rules, why in G.MUT:
                files = [page, G.MUT_FILE.get(page, page)]
                rows.append((f"{page}#{iid}", text, files, scope, st, rules, why))
            for page, text, why in G.MUT_OUT:
                rows.append((f"{page}#{text}", text, [page], "OUT:" + why, "n/a", [], ""))
        else:
            for mod, text, scope, st, rules, why in G.XVWA:
                rows.append((mod, text, [f"vulnerabilities/{mod}/home.php", f"vulnerabilities/{mod}/index.php",
                                         f"vulnerabilities/{mod}/redirect.php", f"vulnerabilities/{mod}/export.php"],
                             scope, st, rules, why))
        out = []
        for iid, text, files, scope, st, rules, why in rows:
            got = set().union(*(tps.get(f, set()) for f in files))
            if st == DET_ and not (got & set(rules)):
                problems.append(f"{corpus} {iid}: DET but no TP finding of {rules} in {files}")
            if scope == "IN" and st != DET_ and got:
                problems.append(f"{corpus} {iid}: {st} but TP findings {sorted(got)} in {files} -- review")
            out.append({"id": iid, "item": text, "location": PREFIX[corpus] + files[0], "scope": scope,
                        "status": st, "rules": rules if st == DET_ else [], "rule_or_reason": why})
        items[corpus] = {"language": "php", "commit": G.COMMITS[corpus], "documented_list": G.LISTS[corpus],
                         "role": "held_out", "items": out}
    return items, triage, problems


DET_ = G.DET
if __name__ == "__main__":
    items, triage, problems = run(sys.argv[1])
    json.dump({"items": items, "triage": triage}, open(sys.argv[2], "w"), indent=1)
    for p in problems:
        print("CHECK", p)
    for c, v in items.items():
        ins = [i for i in v["items"] if i["scope"] == "IN"]
        d = sum(i["status"] == "DET" for i in ins)
        print(f"{c:11s} documented {len(v['items']):3d} in-scope {len(ins):3d} detected {d:3d} "
              f"recall {d/len(ins):.0%} gap {sum(i['status']=='GAP' for i in ins)} ceil {sum(i['status']=='CEIL' for i in ins)}")
    t = collections.Counter((x["corpus"], x["language"], x["verdict"]) for x in triage)
    for k, n in sorted(t.items()):
        print(" ", k, n)
