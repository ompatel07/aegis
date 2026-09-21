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

The pack is rebuilt verbatim from upstream: every rule's logic, message, severity,
languages and upstream metadata are copied as-is. Two things are added, both
derived from upstream, never from the registry:
  * the id is namespaced `ajinabraham.njsscan.<dir>.<file>.<id>` -- the form these
    rules have always had in Aegis findings, so fingerprints and lifecycle continue;
  * `metadata.license` (read from upstream's LICENSE, which is checked to be LGPL-3.0)
    and `metadata.source` (the upstream blob URL at the pinned commit).

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
    rules = build(work, head)
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
            "excluded": 0,
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
