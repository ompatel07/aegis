"""P3: re-measure one changed rule file on the real corpus, N runs per repository, with
the product's semgrep arguments and exclusions, written in d2_run.py's format so
p3_ledger.py reads it. Used for aegis-py-sql-string-construction after its f-string
fix: the full after-state scans ran with the earlier version, and only this rule's
findings are replaced (every other rule is unchanged, so its findings stand).

usage (scanner container): python3 py_rule_runs.py <rules_file> <out_dir> <runs> <repo> [...]
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, "/app")
from config import get_settings  # noqa: E402
from engines import semgrep_engine as se  # noqa: E402
from utils import bundled_assets  # noqa: E402

rules, out_dir, runs, repos = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4:]
os.makedirs(out_dir, exist_ok=True)
settings = get_settings()
skip = set(se._WALK_SKIP) | set(se._DEFAULT_EXCLUDE_DIRS)
for i in range(1, runs + 1):
    for repo in repos:
        name = os.path.basename(repo.rstrip("/"))
        assets, _, _ = bundled_assets.find_bundled(repo, skip)
        args = se._build_args(settings, [rules], repo, extra_excludes=assets)
        p = subprocess.run(args, cwd=repo, capture_output=True, text=True,
                           env=dict(os.environ, SEMGREP_LOG_LEVEL="warning"))
        doc = json.loads(p.stdout)
        partial = se.partial_analysis(p.stderr, doc, repo)
        findings = sorted({(r["check_id"].split(".")[-1], os.path.relpath(r["path"], repo), r["start"]["line"])
                           for r in doc["results"]})
        json.dump({"repo": name, "run": i, "status": "EngineStatus.COMPLETED", "findings": findings,
                   "partially_analysed": partial}, open(os.path.join(out_dir, f"{name}.run{i}.json"), "w"))
        print(name, i, len(findings), "partial" if partial else "", flush=True)
