#!/usr/bin/env python3
"""Vendor the third-party rule packs Aegis ships, from their UPSTREAM source.

Since Pass N1 (2026-09-19) that is exactly one pack: njsscan (LGPL-3.0-or-later),
built from its upstream git repository at a pinned commit. Nothing is fetched from
the Semgrep registry -- not by this script, not by the scanner. The 16 registry
packs this script used to pin carried the Semgrep Rules License v1.0, which does not
permit commercial shipping; Semgrep declined an OEM licence and relicensing, so they
were removed. See docs/RULE_REMOVAL_N1.md.

Why vendoring at all (G2, still true):
  * Reproducibility -- rule_pack_version hashes rule CONTENT; a pinned file makes
    two scans of unchanged code agree.
  * Customer-visible stability -- upstream moving must not change a customer's
    results between two scans. Freshness is a reviewed, scheduled act.
  * Licence visibility -- the exact rule set and each rule's licence is an artefact
    we can read, diff and audit (tools/check_rule_licences.py).

The pack is rebuilt from upstream: every rule's logic, message, severity, languages
and upstream metadata are copied as-is, EXCEPT where Pass N2b (2026-10-22) measured
a rule on real code and pruned or constrained it (`PRUNED`, `CONSTRAINED` below --
the evidence is docs/NJSSCAN_TRIAGE_N2B.md). Added to every rule, derived from
upstream, never from the registry:
  * the id is namespaced `ajinabraham.njsscan.<dir>.<file>.<id>` -- the form these
    rules have always had in Aegis findings, so fingerprints and lifecycle continue;
  * `metadata.license` (read from upstream's LICENSE, which is checked to be LGPL-3.0)
    and `metadata.source` (the upstream blob URL at the pinned commit).
A constrained rule also carries `metadata.aegis-modified` stating what was changed
and when. That, and rules/vendor/NOTICE.md, are the LGPL-3.0 / GPL-3.0 s5(a) notice
that this is a modified version; the file stays LGPL-3.0-or-later and stays source.

USAGE
    python scripts/vendor_rules.py --verify                 # vendored file matches the manifest
    python scripts/vendor_rules.py --refresh                # build from upstream HEAD, diff, report
    python scripts/vendor_rules.py --refresh --commit SHA   # ...at a specific commit
    python scripts/vendor_rules.py --refresh --write        # ...and re-pin (review the diff first!)

REFRESH CADENCE: monthly (rule-pack-drift.yml reports; it never re-pins). A refresh
is a reviewed change: read the diff, re-run the accuracy gates, then --write.
"""
from __future__ import annotations

import argparse
import collections
import datetime
import hashlib
import json
import os
import subprocess
import sys
import tempfile

import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(REPO_ROOT, "services", "scanner", "rules")
VENDOR_DIR = os.path.join(RULES_DIR, "vendor")
MANIFEST = os.path.join(RULES_DIR, "manifest.yaml")

UPSTREAM = {
    "pack": "nodejsscan",
    "git": "https://github.com/ajinabraham/njsscan",
    "path": "njsscan/rules/semantic_grep",
    "id_prefix": "ajinabraham.njsscan",
    "licence": "LGPL-3.0-or-later",
    "licence_file": "vendor/LICENSES/nodejsscan-LGPL-3.0.txt",
}
PERMITTED_LICENCES = ["LGPL-3.0-or-later"]

# ── Pass N2b (2026-10-22): measured on 475 findings across the V2 + F1 corpora ──────
# Every njsscan finding was hand-triaged in its source at the scanned commit. Rules
# whose false positives ARE the rule -- the matching logic itself is the heuristic,
# so no narrow constraint exists -- are not shipped. The figures are TP/findings.
_N2B = "2026-10-22"
PRUNED = {
    # Fires on `<regex>.test(<input>)` inside ANY two-parameter function and never
    # looks at the regex: 0/257, and none of the 1,469 regexes in the flagged files
    # backtracks catastrophically when executed. aegis-js-redos-nested-quantifier
    # checks the regex's shape and catches NodeGoat's documented ReDoS (GT7).
    "ajinabraham.njsscan.dos.regex_dos.regex_dos": "0/257; regex never inspected",
    # Any Math.random() call: 3/73 (UI ids, jitter, colours, demo data). Purpose is
    # the whole question and the rule cannot see it -- weak random is N3's to rebuild.
    "ajinabraham.njsscan.crypto.crypto_node.node_insecure_random_generator": "3/73; API name only",
    # Comparisons involving a variable named password/secret/token: 1/13 (password vs
    # its confirmation, `=== null` the rule's own exclusions miss, a moment locale).
    "ajinabraham.njsscan.crypto.timing_attack_node.node_timing_attack": "1/13; identifier name only",
    # `$X = '<string>'` where $X's NAME matches user/api_key/secret/password: 1/50
    # (error messages, event constants, bootstrap's DATA_API_KEY). The value is never
    # examined; hardcoded credentials are the secrets pillar's job (gitleaks: format
    # and entropy, on every language).
    "ajinabraham.njsscan.generic.hardcoded_secrets.node_username": "0/27; identifier name only",
    "ajinabraham.njsscan.generic.hardcoded_secrets.node_api_key": "0/16; identifier name only",
    "ajinabraham.njsscan.generic.hardcoded_secrets.node_secret": "0/2; identifier name only",
    "ajinabraham.njsscan.generic.hardcoded_secrets.node_password": "1/5; identifier name only",
    # console.error(err) / console.trace(): 0/18. Logging is not disclosure to a
    # client; node_error_disclosure (the response-side rule) is kept.
    "ajinabraham.njsscan.generic.error_disclosure.generic_error_disclosure": "0/18; flags logging",
    # Cookie attributes whose ABSENCE is not a weakness (host-only path/domain, session
    # lifetime). Excluded at run time since before N1; pruned here instead so the
    # coverage count matches what executes.
    "ajinabraham.njsscan.headers.header_cookie.cookie_session_no_domain": "absence is safe default",
    "ajinabraham.njsscan.headers.header_cookie.cookie_session_no_path": "absence is safe default",
    "ajinabraham.njsscan.headers.header_cookie.cookie_session_no_maxage": "absence is safe default",
}
# njsscan's `good/` rules report that a control IS present (helmet headers, csurf,
# rate limiting). They are not detections, carry no CWE, and surfaced as findings.
PRUNED_DIRS = {"ajinabraham.njsscan.good.": "reports a control that is present; not a detection"}

_REQ_NAMED = {"metavariable-regex": {"metavariable": "$REQ", "regex": "(?i)^(req|request)$"}}


def _require_req_named(rule: dict) -> None:
    """$REQ was unconstrained, so any two-parameter function was a 'request handler'
    and any `a.b` was request data. Upstream's own taint rules constrain it exactly
    this way (node_nosqli_injection's sources)."""
    rule["patterns"] = list(rule["patterns"]) + [_REQ_NAMED]


def _not_orm_where(rule: dict) -> None:
    """findOne({where: ...}) is the Sequelize/TypeORM query shape, not Mongo's (Mongo's
    operator is `$where`). Upstream meant to exclude Sequelize with
    `pattern-not-sinks`, a key semgrep does not implement, so it never applied."""
    rule["pattern-sinks"] = [{"patterns": [
        {"pattern": "$OBJ.findOne($QUERY, ...)"},
        {"pattern-not": "$OBJ.findOne({..., where: $W, ...}, ...)"},
    ]}]


# rule id -> (what changed, how[, which pass, when N2b's]). Each verified on the corpus it
# was measured on: every FP of the mechanism removed, every TP kept.
CONSTRAINED = {
    "ajinabraham.njsscan.eval.eval_node.eval_nodejs":
        ("$REQ must be named req/request (was: any 2-parameter function)", _require_req_named),
    "ajinabraham.njsscan.eval.eval_require.eval_require":
        ("$REQ must be named req/request (was: any 2-parameter function)", _require_req_named),
    "ajinabraham.njsscan.dos.regex_injection.regex_injection_dos":
        ("$REQ must be named req/request (was: any 2-parameter function)", _require_req_named),
    # P3 (2026-10-23), from the real-repository TUNING half: 8 of 8 findings false, every
    # one the same mechanism -- `state.set(instr.id, ...)` in a compiler pass read as a
    # response header because any 2-parameter function was a request handler.
    "ajinabraham.njsscan.headers.header_injection.generic_header_injection":
        ("$REQ must be named req/request (was: any 2-parameter function)", _require_req_named,
         "2026-10-23 Aegis Pass P3"),
    "ajinabraham.njsscan.traversal.express_hbs_lfr.express_lfr_warning":
        ("$REQ must be named req/request (was: any object, e.g. process.env)", _require_req_named),
    "ajinabraham.njsscan.database.nosql_find_injection.node_nosqli_injection":
        ("findOne({where: ...}) (Sequelize/TypeORM) is not a sink; upstream's "
         "pattern-not-sinks is not a semgrep key and never applied", _not_orm_where),
}


def _pruned(rule_id: str) -> str | None:
    if rule_id in PRUNED:
        return PRUNED[rule_id]
    return next((why for pre, why in PRUNED_DIRS.items() if rule_id.startswith(pre)), None)


def apply_n2b(rules: list[dict]) -> tuple[list[dict], list[str]]:
    """Drop the pruned rules and constrain the constrained ones. Fails loudly if a
    named rule no longer exists upstream: a prune that silently stops applying would
    ship the rule again with nobody noticing."""
    ids = {r["id"] for r in rules}
    gone = sorted((set(PRUNED) | set(CONSTRAINED)) - ids)
    if gone:
        raise SystemExit(f"N2b prune/constraint names rules upstream no longer has: {gone} "
                         "-- re-measure before re-pinning")
    kept, dropped = [], []
    for r in rules:
        if _pruned(r["id"]):
            dropped.append(r["id"])
            continue
        if r["id"] in CONSTRAINED:
            what, fn, *by = CONSTRAINED[r["id"]]
            fn(r)
            r["metadata"]["aegis-modified"] = f"{by[0] if by else _N2B + ' Aegis Pass N2b'}: {what}"
        kept.append(r)
    return kept, dropped


LOGIC_KEYS = ("pattern", "patterns", "pattern-either", "pattern-regex", "mode", "pattern-sources",
              "pattern-sinks", "pattern-not-sinks", "pattern-sanitizers", "pattern-propagators",
              "languages", "message", "severity")


def _git(*args: str, cwd: str | None = None) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def _checkout(commit: str | None) -> tuple[str, str]:
    work = tempfile.mkdtemp(prefix="aegis-vendor-")
    _git("clone", "--quiet", UPSTREAM["git"], work)
    if commit:
        _git("checkout", "--quiet", commit, cwd=work)
    return work, _git("rev-parse", "HEAD", cwd=work)


def _check_licence(work: str) -> None:
    text = open(os.path.join(work, "LICENSE"), encoding="utf-8").read()
    if "GNU LESSER GENERAL PUBLIC LICENSE" not in text or "Version 3" not in text:
        raise SystemExit("upstream LICENSE is no longer LGPL-3.0 -- stop and take it to counsel")


def build(work: str, commit: str) -> list[dict]:
    root = os.path.join(work, UPSTREAM["path"])
    rules: list[dict] = []
    for dirpath, _dirs, files in os.walk(root):
        for name in sorted(files):
            if not name.endswith((".yaml", ".yml")):
                continue
            rel = os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/")
            sub, fname = rel.rsplit("/", 1) if "/" in rel else ("", rel)
            stem = fname.rsplit(".", 1)[0]
            with open(os.path.join(dirpath, name), encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
            for r in doc.get("rules") or []:
                r = dict(r)
                r["id"] = ".".join(x for x in (UPSTREAM["id_prefix"], sub.replace("/", "."), stem, r["id"]) if x)
                meta = dict(r.get("metadata") or {})
                meta["license"] = UPSTREAM["licence"]
                meta["source"] = f"{UPSTREAM['git']}/blob/{commit}/{UPSTREAM['path']}/{rel}"
                r["metadata"] = meta
                rules.append(r)
    # Deterministic serialisation: an unchanged upstream hashes identically.
    rules.sort(key=lambda r: r["id"])
    return rules


def _logic(r: dict) -> str:
    return json.dumps({k: r.get(k) for k in LOGIC_KEYS if k in r}, sort_keys=True, default=str)


def load_manifest() -> dict:
    if not os.path.isfile(MANIFEST):
        return {}
    with open(MANIFEST, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def refresh(write: bool, commit: str | None) -> int:
    work, head = _checkout(commit)
    _check_licence(work)
    upstream_rules = build(work, head)
    rules, dropped = apply_n2b(upstream_rules)
    print(f"  upstream rules: {len(upstream_rules)}   pruned (N2b): {len(dropped)}   "
          f"constrained (N2b): {len(CONSTRAINED)}")
    body = yaml.safe_dump({"rules": rules}, sort_keys=False, allow_unicode=True)
    sha = hashlib.sha256(body.encode()).hexdigest()

    target = os.path.join(VENDOR_DIR, f"{UPSTREAM['pack']}.yaml")
    old = {}
    if os.path.isfile(target):
        with open(target, encoding="utf-8") as fh:
            old = {r["id"]: r for r in (yaml.safe_load(fh) or {}).get("rules") or []}
    new = {r["id"]: r for r in rules}
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed = sorted(i for i in set(new) & set(old) if _logic(new[i]) != _logic(old[i]))
    print(f"  upstream {UPSTREAM['git']} @ {head}")
    print(f"  rules: {len(rules)}   added {len(added)}   removed {len(removed)}   logic changed {len(changed)}")
    for tag, ids in (("ADDED", added), ("REMOVED", removed), ("CHANGED", changed)):
        for i in ids:
            print(f"    {tag:8s} {i}")

    if not write:
        if added or removed or changed:
            print("\n  (dry run -- re-run with --write to re-pin after reviewing the diff)")
        return 0

    with open(target, "w", encoding="utf-8", newline="") as fh:
        fh.write(body)
    lic = collections.Counter(r["metadata"]["license"] for r in rules)
    man = load_manifest()
    man.update({
        "pinned_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"),
        "source_policy": "upstream-git-only",
        "permitted_licences": PERMITTED_LICENCES,
        "packs": [{
            "pack": UPSTREAM["pack"],
            "source": UPSTREAM["git"],
            "upstream_commit": head,
            "upstream_path": UPSTREAM["path"],
            "file": f"vendor/{UPSTREAM['pack']}.yaml",
            "sha256": sha,
            "rules": len(rules),
            "upstream_rules": len(upstream_rules),
            "excluded": len(dropped),
            "excluded_rules": dropped,
            "constrained_rules": sorted(CONSTRAINED),
            "licenses": dict(lic),
            "licence_text": UPSTREAM["licence_file"],
        }],
    })
    man.pop("registry", None)
    with open(MANIFEST, "w", encoding="utf-8", newline="") as fh:
        yaml.safe_dump(man, fh, sort_keys=False, allow_unicode=True)
    print(f"\n  pinned {UPSTREAM['pack']} @ {head[:12]} -> {os.path.relpath(MANIFEST, REPO_ROOT)}")
    return 0


def verify() -> int:
    man = load_manifest()
    if not man:
        print("no manifest")
        return 1
    bad = 0
    for p in man.get("packs") or []:
        path = os.path.join(RULES_DIR, p["file"])
        if not os.path.isfile(path):
            print(f"  MISSING  {p['file']}")
            bad += 1
            continue
        with open(path, "rb") as fh:
            sha = hashlib.sha256(fh.read()).hexdigest()
        if sha != p["sha256"]:
            print(f"  MISMATCH {p['file']}  manifest={p['sha256'][:10]} actual={sha[:10]}")
            bad += 1
    total = sum(p["rules"] for p in man.get("packs") or [])
    print(f"  pinned {man.get('pinned_at')}  packs={len(man.get('packs') or [])}  rules={total}  mismatches={bad}")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--refresh", action="store_true", help="build from upstream and diff against the pin")
    ap.add_argument("--write", action="store_true", help="with --refresh: re-pin (review the diff first)")
    ap.add_argument("--commit", help="with --refresh: upstream commit to build from (default: HEAD)")
    ap.add_argument("--verify", action="store_true", help="check vendored files match the manifest")
    a = ap.parse_args()
    if a.verify:
        return verify()
    if a.refresh:
        return refresh(write=a.write, commit=a.commit)
    ap.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
