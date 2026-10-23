"""D2: fixpoint-timeout rate of aegis-php-xss on one file under CPU load, for three
versions of the rule: plain (shipped), augmented (the product: 65 project escapers as 65
sanitizer patterns), and collapsed (the same escapers as ONE pattern + metavariable-regex).

usage: python3 d2_variants.py <repo> <target> <k> <rounds>
"""
import copy
import json
import os
import re
import subprocess
import sys
import tempfile

import yaml

sys.path.insert(0, "/app")
from engines import semgrep_engine as se  # noqa: E402

repo, target, k, rounds = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
base = yaml.safe_load(open(os.path.join(se._custom_rules_dir(), "php.yaml")))
aug_dir, _ = se._augmented_taint_dir(repo, se._custom_rules_dir())
aug = yaml.safe_load(open(os.path.join(aug_dir, "php.yaml")))
wrappers = sorted(se._php_escaper_wrappers(repo))


def only_xss(doc):
    d = copy.deepcopy(doc)
    d["rules"] = [r for r in d["rules"] if r["id"] == "aegis-php-xss"]
    return d


collapsed = only_xss(aug)
for san in collapsed["rules"][0]["pattern-sanitizers"]:
    pe = san.get("pattern-either")
    if isinstance(pe, list):
        san["pattern-either"] = [p for p in pe if not (isinstance(p, dict) and p.get("pattern", "").endswith("(...)")
                                                       and p["pattern"][:-5] in wrappers)]
        san["pattern-either"].append({"patterns": [
            {"pattern": "$AEGIS_ESC(...)"},
            {"metavariable-regex": {"metavariable": "$AEGIS_ESC",
                                    "regex": "^(" + "|".join(re.escape(w) for w in wrappers) + ")$"}}]})

variants = {"plain": only_xss(base), "augmented": only_xss(aug), "collapsed": collapsed}
tmp = tempfile.mkdtemp()
env = dict(os.environ, SEMGREP_LOG_LEVEL="warning", SEMGREP_LOG_SRCS="tainting")
for name, doc in variants.items():
    cfg = os.path.join(tmp, f"{name}.yaml")
    yaml.safe_dump(doc, open(cfg, "w"), sort_keys=False)
    args = ["semgrep", "scan", "--json", "--metrics", "off", "--disable-version-check", "--timeout", "60",
            "--config", cfg, "--debug", target]
    fp, results = 0, []
    for r in range(rounds):
        ps = [subprocess.Popen(args, cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
              for _ in range(k)]
        for p in ps:
            out, err = p.communicate()
            fp += sum(1 for l in err.splitlines() if "Fixpoint timeout" in l)
            results.append(tuple(sorted(x["start"]["line"] for x in json.loads(out)["results"])))
    print(f"{name:10s} k={k} runs={len(results)} fixpoint_warnings={fp} distinct_results={len(set(results))} "
          f"{sorted(set(results))[:4]}", flush=True)
