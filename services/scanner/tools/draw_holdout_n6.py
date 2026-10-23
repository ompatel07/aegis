"""Pass N6: draw the JS/TS held-out ground-truth corpora and the real-repository
PRECISION holdout, before any of them is used to measure or change anything.

Seed: the commit N5 ended on (65d29f94...), fixed before N6 began.

1. JS/TS recall holdout (N5's rule, unchanged): the pool is the new N6 corpora (NodeGoat
   and juice-shop are tuning corpora every pass has gated on); it is shuffled with the
   seed and corpora are held out in that order until the held-out set has at least
   min(20, half the language's in-scope items).
2. Precision holdout: the real-repository corpus (production OSS, not built to be
   vulnerable -- see REAL below) is shuffled with the seed and the first half (rounded
   up) is held out. A precision fix may be written from the tuning half only, and the
   precision gate is evaluated on the held-out half.

Writes accuracy/holdout_n6.json. Re-running it gives the same answer.
usage: python tools/draw_holdout_n6.py <docs/ground_truth_n6/jsts_items.py dir>
"""
import importlib.util
import json
import math
import os
import random
import sys

SEED_COMMIT = "65d29f94e958277b916aed8d3bbc23bef620a748"

# The real-repository corpus. V2's 15 minus the four deliberately vulnerable apps among
# them (NodeGoat, juice-shop, DVWA, WebGoat are ground-truth corpora), N3's cmp-*
# repositories, and spring-petclinic. N3's dvpwa and django.nV are vulnerable by design
# and are ground truth too. Everything deliberately vulnerable is the STRESS set.
REAL = sorted([
    "Dolibarr__dolibarr", "FreshRSS__FreshRSS", "chatwoot__chatwoot", "getredash__redash",
    "jellyfin__jellyfin", "librenms__librenms", "mastodon__mastodon", "n8n-io__n8n",
    "nilsteampassnet__TeamPass", "nocodb__nocodb", "nopSolutions__nopCommerce", "spring-petclinic",
] + [f"cmp-{n}" for n in ("ansible", "cobra", "consul", "django", "express", "fastapi", "flask", "gin",
                           "guava", "jackson", "kafka", "nest", "netty", "nextauth", "prisma", "react",
                           "spring", "terraform", "vault")])
TUNING_FIXED = {"javascript": {"nodegoat": 7}, "typescript": {"juice-shop": 12}}  # in-scope, from N5


def _jsts(path):
    spec = importlib.util.spec_from_file_location("jsts_items", os.path.join(path, "jsts_items.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.CORPORA


def draw(corpora: dict) -> dict:
    rng = random.Random(int(SEED_COMMIT, 16))
    out = {"seed_commit": SEED_COMMIT, "languages": {}, "precision": {}}
    for lang in ("javascript", "typescript"):
        new = {k: sum(1 for i in v["items"] if i[3] == "IN") for k, v in corpora.items() if v["language"] == lang}
        total = sum(new.values()) + sum(TUNING_FIXED[lang].values())
        need = min(20, math.ceil(total / 2))
        pool = sorted(new)
        rng.shuffle(pool)
        held, n = [], 0
        for k in pool:
            if n >= need:
                break
            held.append(k)
            n += new[k]
        out["languages"][lang] = {
            "draw_order": pool, "need_in_scope": need, "held_out": sorted(held), "held_out_in_scope": n,
            "tuning": sorted(set(new) - set(held)) + sorted(TUNING_FIXED[lang]),
            "tuning_in_scope": sum(v for k, v in new.items() if k not in held) + sum(TUNING_FIXED[lang].values())}
    real = list(REAL)
    rng.shuffle(real)
    k = math.ceil(len(real) / 2)
    out["precision"] = {"real_corpus": REAL, "draw_order": real,
                        "held_out": sorted(real[:k]), "tuning": sorted(real[k:])}
    return out


if __name__ == "__main__":
    res = draw(_jsts(sys.argv[1]))
    dst = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "accuracy", "holdout_n6.json")
    json.dump(res, open(dst, "w", encoding="utf-8"), indent=1)
    print(json.dumps({k: v for k, v in res.items() if k != "precision"} | {"precision": {
        "held_out": res["precision"]["held_out"], "tuning": res["precision"]["tuning"]}}, indent=1))
