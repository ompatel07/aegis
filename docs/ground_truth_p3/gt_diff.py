"""P3 Part C: what the rule edits did on the ground-truth corpora.

Only three rule files changed (php.yaml, python.yaml, javascript.yaml -- the vendored
header rule catches no documented item), so each PHP / Python / JS / TS corpus is
scanned with the OLD and the NEW version of its file, with the product's arguments,
exclusions and per-project PHP augmentation. Reports, per corpus and rule, findings lost
and gained, and checks every documented item (accuracy/gt_items.json, status DET) whose
catching rule lives in a changed file: is a finding of that rule still in the item's file
(within WINDOW lines when the item names one)?

usage (scanner container, /app = services/scanner):
  python3 gt_diff.py <old_taint_dir> <out.json> name=path [name=path ...]
"""
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, "/app")
from config import get_settings  # noqa: E402
from engines import semgrep_engine as se  # noqa: E402
from utils import bundled_assets  # noqa: E402

WINDOW = 10
FILES = {"php": "php.yaml", "python": "python.yaml", "javascript": "javascript.yaml",
         "typescript": "javascript.yaml"}
old_dir, out = sys.argv[1], sys.argv[2]
corpora = dict(a.split("=", 1) for a in sys.argv[3:])
new_dir = se._custom_rules_dir()
gt = json.load(open("/app/accuracy/gt_items.json", encoding="utf-8"))
settings = get_settings()
skip = set(se._WALK_SKIP) | set(se._DEFAULT_EXCLUDE_DIRS)


def ids_in(path):
    return set(re.findall(r"^  - id: (\S+)", open(path, encoding="utf-8").read(), re.M))


def scan(root, taint_dir, fname):
    aug, _ = se._augmented_taint_dir(root, taint_dir) if fname == "php.yaml" else (None, [])
    cfg = os.path.join(aug or taint_dir, fname)
    assets, _, _ = bundled_assets.find_bundled(root, skip)
    args = se._build_args(settings, [cfg], root, extra_excludes=assets)
    p = subprocess.run(args, cwd=root, capture_output=True, text=True,
                       env=dict(os.environ, SEMGREP_LOG_LEVEL="warning"))
    res = json.loads(p.stdout)["results"]
    return {(r["check_id"].split(".")[-1], os.path.relpath(r["path"], root), r["start"]["line"]) for r in res}


def where(location):
    head = location.split(" ")[0].split("->")[0].strip()
    m = re.match(r"(.+?):(\d+)(?:-\d+)?$", head)
    return (m.group(1), int(m.group(2))) if m else (head, None)


report = {}
for name, root in corpora.items():
    c = gt[name]
    fname = FILES.get(c["language"])
    if not fname:
        continue
    before, after = scan(root, old_dir, fname), scan(root, new_dir, fname)
    changed_ids = ids_in(os.path.join(old_dir, fname)) | ids_in(os.path.join(new_dir, fname))
    items = []
    for it in c["items"]:
        if it.get("scope") != "IN" or it.get("status") != "DET":
            continue
        rules = [r for r in it.get("rules") or [] if r in changed_ids]
        if not rules:
            continue
        f, line = where(it["location"])

        def hit(fs):
            return any(r in rules and (p.endswith(f) or f.endswith(p)) and (line is None or abs(ln - line) <= WINDOW)
                       for r, p, ln in fs)
        items.append({"id": it["id"], "rules": rules, "location": it["location"],
                      "before": hit(before), "after": hit(after)})
    report[name] = {"language": c["language"], "role": c["role"],
                    "lost": sorted(before - after), "gained": sorted(after - before), "items": items}
    lost_items = [i["id"] for i in items if i["before"] and not i["after"]]
    unmatched = [i["id"] for i in items if not i["before"]]
    print(f"{name:20s} {c['role']:8s} findings {len(before)} -> {len(after)} "
          f"(-{len(before - after)} +{len(after - before)})  items checked {len(items)}  "
          f"LOST {lost_items}  not-matched-before {unmatched}", flush=True)
json.dump(report, open(out, "w", encoding="utf-8"), indent=1)
