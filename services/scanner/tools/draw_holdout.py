"""Pass N5 Part C: choose the held-out ground-truth corpora BEFORE any rule changes.

The N4 rule-gap list was read off the same corpora that N5's rules will be measured on,
so recall on those corpora after the fixes is inflated by construction. This script holds
corpora out by a seeded draw, so the choice is not mine and cannot be steered toward a
result:

  * the pool per language is every qualifying N4 corpus EXCEPT one already used to write
    or change a rule (listed in EXCLUDED with the reason);
  * the seed is the commit N4 ended on (b0725480...), fixed before N5 began;
  * the pool is shuffled with that seed, and corpora are held out in that order until
    the held-out set holds at least min(20, half the language's in-scope items).

Writes accuracy/holdout.json. Re-running it gives the same answer.
usage: python tools/draw_holdout.py <gt_items.json>
"""
import json
import math
import os
import random
import sys

SEED_COMMIT = "b07254804600f5aa849bdb8d7d574c0d1c85de11"
EXCLUDED = {  # corpus -> why it cannot be held out
    "securityshepherd": "N4 fixed aegis-java-insecure-session-cookie on it; N5's aegis-java-xss precision work comes from its findings",
    "pygoat": "N4 fixed aegis-py-insecure-session-cookie on it; N5's shell=True fix comes from it",
    "vulnerableapp": "N4 promoted aegis-java-weak-cipher on its findings",
    "dvga-go": "N4 promoted aegis-go-weak-hash-credential and aegis-go-insecure-session-cookie on its findings",
    "dvpwa-full": "an F1 ground-truth corpus; every pass since F1 gates rule changes on it",
}


def draw(gt: dict) -> dict:
    out = {"seed_commit": SEED_COMMIT, "excluded": EXCLUDED, "languages": {}}
    rng = random.Random(int(SEED_COMMIT, 16))
    for lang in ("go", "java", "python"):
        corpora = {k: v for k, v in gt.items() if v["language"] == lang}
        in_scope = {k: sum(1 for i in v["items"] if i["scope"] == "IN") for k, v in corpora.items()}
        need = min(20, math.ceil(sum(in_scope.values()) / 2))
        pool = sorted(k for k in corpora if k not in EXCLUDED)
        rng.shuffle(pool)
        held, n = [], 0
        for k in pool:
            if n >= need:
                break
            held.append(k)
            n += in_scope[k]
        out["languages"][lang] = {
            "draw_order": pool, "need_in_scope": need, "held_out": sorted(held),
            "held_out_in_scope": n, "tuning": sorted(k for k in corpora if k not in held),
            "tuning_in_scope": sum(v for k, v in in_scope.items() if k not in held)}
    return out


if __name__ == "__main__":
    res = draw(json.load(open(sys.argv[1], encoding="utf-8")))
    dst = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "accuracy", "holdout.json")
    json.dump(res, open(dst, "w", encoding="utf-8"), indent=1)
    print(json.dumps(res["languages"], indent=1))
