"""D2: does aegis-php-xss on one file depend on CPU load? Build the product's augmented
taint rules, then run semgrep on the target alone (k=1) and as k concurrent copies,
recording the findings at the watched lines and any 'fixpoint' lines semgrep logs.

usage: python3 d2_load.py <repo> <target> <k> <rounds> <line,line,...>
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, "/app")
from engines import semgrep_engine as se  # noqa: E402

repo, target, k, rounds = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
watch = {int(x) for x in sys.argv[5].split(",")}
aug, _ = se._augmented_taint_dir(repo, se._custom_rules_dir())
cfg = os.path.join(aug, "php.yaml")
args = [a for a in ["semgrep", "scan", "--json", "--metrics", "off", "--disable-version-check", "--timeout", os.environ.get("D2_TIMEOUT", "60"),
        "--config", cfg, os.environ.get("D2_LOG", "--debug"), target] if a]
for r in range(rounds):
    procs = [subprocess.Popen(args, cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
             for _ in range(k)]
    for p in procs:
        out, err = p.communicate()
        res = json.loads(out)["results"]
        lines = sorted(x["start"]["line"] for x in res if x["check_id"].endswith("aegis-php-xss"))
        fix = [l for l in err.splitlines() if "ixpoint" in l]
        print(f"k={k} round={r} xss={len(lines)} watched={sorted(watch & set(lines))} fixpoint={len(fix)}",
              fix[:1], flush=True)
