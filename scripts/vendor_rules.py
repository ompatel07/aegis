#!/usr/bin/env python3
"""Vendor the Semgrep registry packs Aegis depends on into a pinned, reviewable manifest.

WHY THIS EXISTS (three independent reasons, none of them the legal question):

  1. Licence exposure. G2 measured that 83.5% of every SAST finding Aegis has ever
     produced comes from rules carrying the Semgrep Rules License v1.0. We cannot
     reason about — or bound — an exposure we re-download on every scan. Vendoring
     makes the exact rule set, and its licences, an artefact we can read and diff.
  2. Reproducibility. `rule_pack_version` was not reproducible (F1 row 1b). A pinned
     manifest lets the id be a hash of actual rule CONTENT rather than of config
     paths, so two identical scans agree.
  3. Customer-visible stability. A live `--config p/...` fetch means the registry can
     change a customer's results between two scans of unchanged code, with no signal.
     Freshness should be a reviewed, scheduled act — not a side effect of scanning.

USAGE
    python scripts/vendor_rules.py --refresh     # fetch, diff against the pin, report
    python scripts/vendor_rules.py --refresh --write   # ...and re-pin (review the diff first!)
    python scripts/vendor_rules.py --verify      # check vendored files match the manifest

REFRESH CADENCE: monthly, and on demand when a CVE class demands it. The refresh is a
reviewed change — `--refresh` prints the rule-level diff, a human reads it, and only
then is `--write` run. That review is the point; an unreviewed auto-fetch would put us
back where we started.
"""
from __future__ import annotations

import argparse
import collections
import datetime
import hashlib
import json
import os
import sys
import urllib.request

import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(REPO_ROOT, "services", "scanner", "rules")
VENDOR_DIR = os.path.join(RULES_DIR, "vendor")
MANIFEST = os.path.join(RULES_DIR, "manifest.yaml")

REGISTRY = "https://semgrep.dev/c/"

# Every pack Aegis loads. Kept in one place so the manifest and the engine cannot drift.
PACKS = [
    # always-on base packs (config.py: semgrep_rulesets)
    "p/owasp-top-ten", "p/r2c-security-audit", "p/default", "p/secrets",
    "p/supply-chain", "p/cwe-top-25",
    # per-language (semgrep_engine._LANGUAGE_RULESETS)
    "p/python", "p/javascript", "p/typescript", "p/nodejsscan", "p/java",
    "p/golang", "p/ruby", "p/php", "p/csharp",
    # IaC (semgrep_engine._IAC_RULESETS)
    "p/dockerfile", "p/terraform",
]

# Rule ids dropped at vendor time. The `p/` shortcut gave us no way to exclude these;
# vendoring does. AGPL-3.0 is a strong network-copyleft licence and these 18 rules are
# mixed inside p/default, so they arrived on every scan whether we wanted them or not.
EXCLUDE_PREFIXES = ("trailofbits.",)   # the 18 AGPL-3.0 rules inside p/default
EXCLUDE_IDS: set[str] = set()          # exact-id escape hatch


def _slug(pack: str) -> str:
    return pack.replace("p/", "").replace("/", "_")


def _fetch(pack: str, attempts: int = 5) -> dict:
    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(REGISTRY + pack, headers={"User-Agent": "aegis-vendor"})
            with urllib.request.urlopen(req, timeout=180) as r:
                return yaml.safe_load(r.read())
        except Exception as exc:  # noqa: BLE001 - transient TLS/network, retry
            last = exc
            print(f"    retry {i + 1}/{attempts} for {pack}: {type(exc).__name__}", file=sys.stderr)
    raise RuntimeError(f"could not fetch {pack}: {last}")


def _excluded(rule_id: str) -> bool:
    return rule_id in EXCLUDE_IDS or rule_id.startswith(EXCLUDE_PREFIXES)


def refresh(write: bool) -> int:
    os.makedirs(VENDOR_DIR, exist_ok=True)
    old = load_manifest()
    old_packs = {p["pack"]: p for p in (old.get("packs") or [])}

    packs_meta, changed, total_excluded = [], [], 0
    for pack in PACKS:
        print(f"  fetching {pack} ...")
        doc = _fetch(pack)
        rules, dropped = [], []
        for r in doc.get("rules") or []:
            (dropped if _excluded(r.get("id", "")) else rules).append(r)
        total_excluded += len(dropped)

        # Deterministic serialisation: sorting by id means an unchanged pack hashes
        # identically no matter what order the registry returned it in.
        rules.sort(key=lambda r: r.get("id", ""))
        body = yaml.safe_dump({"rules": rules}, sort_keys=False, allow_unicode=True)
        sha = hashlib.sha256(body.encode()).hexdigest()

        lic = collections.Counter(
            (r.get("metadata") or {}).get("license") or "(none declared)" for r in rules
        )
        meta = {
            "pack": pack,
            "source": REGISTRY + pack,
            "file": f"vendor/{_slug(pack)}.yaml",
            "sha256": sha,
            "rules": len(rules),
            "excluded": len(dropped),
            "licenses": {k: v for k, v in lic.most_common()},
        }
        packs_meta.append(meta)

        prev = old_packs.get(pack)
        if prev is None:
            changed.append(f"    NEW      {pack} ({len(rules)} rules)")
        elif prev.get("sha256") != sha:
            changed.append(
                f"    CHANGED  {pack} {prev.get('rules')} -> {len(rules)} rules"
                f"  {str(prev.get('sha256'))[:10]} -> {sha[:10]}"
            )

        if write:
            # newline="" keeps the bytes on disk identical to the hashed string on
            # every platform; Windows text mode would rewrite the line endings and
            # break --verify.
            out = os.path.join(VENDOR_DIR, f"{_slug(pack)}.yaml")
            with open(out, "w", encoding="utf-8", newline="") as fh:
                fh.write(body)

    print(f"\n  excluded {total_excluded} rule(s) by policy "
          f"(prefixes={list(EXCLUDE_PREFIXES)}, ids={len(EXCLUDE_IDS)})")
    if changed:
        print("\n  DIFF vs current pin:")
        for c in changed:
            print(c)
    else:
        print("\n  no change vs current pin")

    if write:
        manifest = {
            "pinned_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"),
            "registry": REGISTRY,
            "refresh_cadence": "monthly, reviewed — see scripts/vendor_rules.py docstring",
            "exclude_prefixes": list(EXCLUDE_PREFIXES),
            "exclude_ids": sorted(EXCLUDE_IDS),
            "packs": packs_meta,
        }
        with open(MANIFEST, "w", encoding="utf-8", newline="") as fh:
            yaml.safe_dump(manifest, fh, sort_keys=False, allow_unicode=True)
        print(f"\n  pinned {len(packs_meta)} packs -> {os.path.relpath(MANIFEST, REPO_ROOT)}")
    elif changed:
        print("\n  (dry run — re-run with --write to re-pin after reviewing the diff)")
    return 0


def load_manifest() -> dict:
    if not os.path.isfile(MANIFEST):
        return {}
    with open(MANIFEST, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def verify() -> int:
    man = load_manifest()
    if not man:
        print("no manifest — run --refresh --write first")
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
    lic: collections.Counter = collections.Counter()
    for p in man.get("packs") or []:
        for k, v in (p.get("licenses") or {}).items():
            lic[k] += v
    print(f"  pinned {man.get('pinned_at')}  packs={len(man.get('packs') or [])}  rules={total}  mismatches={bad}")
    for k, v in lic.most_common():
        print(f"     {v:>5}  {k[:72]}")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--refresh", action="store_true", help="fetch packs and diff against the pin")
    ap.add_argument("--write", action="store_true", help="with --refresh: re-pin (review the diff first)")
    ap.add_argument("--verify", action="store_true", help="check vendored files match the manifest")
    a = ap.parse_args()
    if a.verify:
        return verify()
    if a.refresh:
        return refresh(write=a.write)
    ap.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
