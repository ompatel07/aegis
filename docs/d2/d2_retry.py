"""D2 prototype: main pass with fixpoint-timeout detection, then a single-job pass over
every file that hit a fixpoint or rule timeout; the retried files' findings replace the
main pass's. Reports final findings, the files still incomplete after the retry, and time.

usage: python3 d2_retry.py <out_json> <repo>
"""
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, "/app")
from config import get_settings  # noqa: E402
from engines import semgrep_engine as se  # noqa: E402
from utils import bundled_assets  # noqa: E402

out, repo = sys.argv[1], sys.argv[2]
settings = get_settings()
aug, _ = se._augmented_taint_dir(repo, se._custom_rules_dir())
cfgs = se._local_configs_only(se._select_configs(settings, ["php", "javascript"], []) +
                              [aug, se._bundled_rules_dir(se._IAC_RULES_DIR), se._bundled_rules_dir(se._CICD_RULES_DIR),
                               se._bundled_rules_dir(se._QUALITY_RULES_DIR)])
skip = set(se._WALK_SKIP) | set(se._DEFAULT_EXCLUDE_DIRS)
assets, _, _ = bundled_assets.find_bundled(repo, skip)
env = dict(os.environ, SEMGREP_LOG_LEVEL="warning")
FX = re.compile(r"Fixpoint timeout while performing \S+.*?\[rule: \S+ file: (\S+)")


def run(targets, jobs):
    args = se._build_args(settings, cfgs, repo, extra_excludes=assets)
    args[args.index("--quiet")] = "--debug"
    args[args.index("--jobs") + 1] = str(jobs)
    args = args[:-1] + targets
    t0 = time.time()
    p = subprocess.run(args, cwd=repo, capture_output=True, text=True, env=env)
    doc = json.loads(p.stdout)
    hit = {m.group(1) for m in map(FX.search, p.stderr.splitlines()) if m}
    hit |= {e["path"] for e in doc["errors"] if "Timeout" in json.dumps(e.get("type")) and e.get("path")}
    norm = lambda f: f if f.startswith("/") else os.path.join(repo, f)
    return doc, {norm(f) for f in hit}, time.time() - t0


key = lambda r: (r["check_id"].split(".")[-1], os.path.relpath(r["path"], repo), r["start"]["line"])
main, hit, t_main = run([repo], se._semgrep_jobs(settings))
final = {key(r) for r in main["results"] if r["path"] not in hit}
pending, union, t_retry, attempts = set(hit), {}, 0.0, []
for attempt in range(3):
    if not pending:
        break
    doc, again, dt = run(sorted(pending), 1)
    t_retry += dt
    attempts.append(len(pending))
    for r in doc["results"]:
        union.setdefault(r["path"], set()).add(key(r))
    done = pending - again
    for f in done:  # complete: its own result, exactly
        final |= {key(r) for r in doc["results"] if r["path"] == f}
    pending = again & pending
still = pending
for f in still:  # never completed: the union of the partial results, disclosed
    final |= union.get(f, set())
json.dump({"main_seconds": round(t_main), "retry_seconds": round(t_retry), "retried": sorted(hit),
           "still_incomplete": sorted(still), "main": sorted(key(r) for r in main["results"]),
           "final": sorted(final)}, open(out, "w"), indent=0)
print(f"main={t_main:.0f}s retried={len(hit)} attempts={attempts} retry={t_retry:.0f}s still_incomplete={len(still)} "
      f"main_findings={len(main['results'])} final={len(final)}", flush=True)
