"""P3: draw the triage sample for aegis-php-stored-xss's OWN precision.

The rule fires thousands of times on the held-out real repositories (Dolibarr alone
~2,700), too many to triage by hand, so its precision is estimated from a simple random
sample of its STABLE held-out findings, with a Wilson 95% interval. The seed is the
commit that introduced the rule (79b3fa0), fixed before any finding was read, and the
population is sorted first, so the draw is reproducible and cannot be steered.

usage (scanner container): python3 sample_stored_xss.py <scan_dir> <n> <out.json>
"""
import glob
import json
import os
import random
import sys

SEED = "79b3fa0905a3f2e17fc2fd862a23a6b51661f3e8"
RULE = "aegis-php-stored-xss"
HELD = set(json.load(open("/app/accuracy/holdout_n6.json", encoding="utf-8"))["precision"]["held_out"])

scan_dir, n, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
runs = {}
for f in sorted(glob.glob(os.path.join(scan_dir, "*.run*.json"))):
    d = json.load(open(f, encoding="utf-8"))
    if d["repo"] not in HELD:
        continue
    runs.setdefault(d["repo"], []).append({(fp, ln) for r, fp, ln in d["findings"] if r.endswith(RULE)})
population = sorted((repo, fp, ln) for repo, sets in runs.items() for fp, ln in set.intersection(*sets))
sample = random.Random(SEED).sample(population, min(n, len(population)))
by_repo = {}
for repo, _, _ in population:
    by_repo[repo] = by_repo.get(repo, 0) + 1
json.dump({"seed": SEED, "population": len(population), "by_repo": by_repo,
           "sample": [{"corpus": c, "file": f, "line": l} for c, f, l in sorted(sample)]},
          open(out, "w", encoding="utf-8"), indent=1)
print(len(population), by_repo, "sampled", len(sample))
