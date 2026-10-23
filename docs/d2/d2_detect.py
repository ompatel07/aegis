"""D2: one full product-argument semgrep pass with fixpoint-timeout detection switched on
(--debug, core log level held at warning). Reports stderr size, wall time, and the
(kind, rule, file) of every fixpoint timeout and rule timeout.

usage: python3 d2_detect.py <repo> [srcs]
"""
import collections
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

repo = sys.argv[1]
settings = get_settings()
aug, _ = se._augmented_taint_dir(repo, se._custom_rules_dir())
cfgs = se._local_configs_only(se._select_configs(settings, ["php", "javascript"], []) +
                              [aug, se._bundled_rules_dir(se._IAC_RULES_DIR), se._bundled_rules_dir(se._CICD_RULES_DIR),
                               se._bundled_rules_dir(se._QUALITY_RULES_DIR)])
skip = set(se._WALK_SKIP) | set(se._DEFAULT_EXCLUDE_DIRS)
assets, _, _ = bundled_assets.find_bundled(repo, skip)
args = se._build_args(settings, cfgs, repo, extra_excludes=assets)
args[args.index("--quiet")] = "--debug"
env = dict(os.environ, SEMGREP_LOG_LEVEL="warning")
if len(sys.argv) > 2:
    env["SEMGREP_LOG_SRCS"] = sys.argv[2]
t0 = time.time()
p = subprocess.run(args, cwd=repo, capture_output=True, text=True, env=env)
dt = time.time() - t0
if not p.stdout.strip():
    print("rc", p.returncode, "secs", round(dt), "stderr bytes", len(p.stderr)); print(p.stderr[-2500:]); sys.exit()
doc = json.loads(p.stdout)
fx = re.compile(r"Fixpoint timeout while performing (\S+).*?\[rule: (\S+) file: (\S+)")
hits = [m.groups() for m in map(fx.search, p.stderr.splitlines()) if m]
print(f"seconds={dt:.0f} stderr_bytes={len(p.stderr)} results={len(doc['results'])} "
      f"fixpoint_warnings={len(hits)} files={len({h[2] for h in hits})}")
print(collections.Counter(h[0] for h in hits))
print(collections.Counter(h[1].split('.')[-1] for h in hits).most_common(12))
for f, n in collections.Counter(h[2] for h in hits).most_common(15):
    print("  ", n, f)
print("rule timeouts:", sorted({(e.get("path"), e.get("rule_id", "").split(".")[-1]) for e in doc["errors"]
                                if "Timeout" in json.dumps(e.get("type"))}))
