#!/usr/bin/env python3
"""Fail the build if the compliance framework mappings exist in more than one
place, or if any mapping references an identifier no engine can emit (J2).

Both classes had already been fixed once and came back:

* **Divergent copies.** Two framework trees existed — the one the loader reads
  (`services/scanner/compliance/frameworks/`) and a stale duplicate at the
  repository root with its own README. J1 fixed only the loaded copy, so the root
  copy kept the wrong HIPAA control title, CC6.3's over-broad CWE-732 and CC8.1's
  wrong title — and being at the root, it is the copy a person browsing the
  repository finds first. Nothing stopped someone editing it and wondering why
  reports never changed.

* **Dead evidence.** A control whose evidence rule can never fire reports
  "no findings" when the honest answer is "never checked". J1 found CWE-937 and
  CWE-1035 mapped across six frameworks and emitted by nothing at all.

The equivalent pytest checks live in tests/test_compliance_mappings.py, but the
divergence one can only run on a full checkout: inside the scanner image
`services/scanner` is mounted as the root and there is no repository to inspect,
so that test skips. This script is what actually enforces it in CI.

Run: python services/scanner/tools/check_single_framework_tree.py
"""
from __future__ import annotations

import os
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
EXPECTED = os.path.join("services", "scanner", "compliance", "frameworks")
SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__", ".next", "dist", "build", ".mypy_cache"}


def find_framework_trees() -> list[str]:
    found = []
    for dirpath, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        if os.path.basename(dirpath) != "frameworks":
            continue
        if any(f.endswith((".yaml", ".yml")) for f in files):
            found.append(os.path.relpath(dirpath, ROOT))
    return sorted(found)


def emittable() -> tuple[set[str], set[str]]:
    path = os.path.join(ROOT, "services", "scanner", "compliance", "emittable_identifiers.yaml")
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    cwe = {c.upper() for c in doc["declared"]["cwe"]} | {c.upper() for c in doc["observed"]["cwe"]}
    ow = set(doc["declared"]["owasp"]) | set(doc["observed"]["owasp"])
    return cwe, ow


def main() -> int:
    problems: list[str] = []

    trees = find_framework_trees()
    if len(trees) != 1:
        problems.append(
            f"expected exactly one compliance framework tree, found {len(trees)}: {trees}\n"
            f"    A second copy diverges silently -- whichever one the loader does not read\n"
            f"    keeps its defects while looking authoritative."
        )
    elif trees[0].replace(os.sep, "/") != EXPECTED.replace(os.sep, "/"):
        problems.append(f"framework tree is at {trees[0]}, expected {EXPECTED}")

    if trees:
        live_cwe, live_ow = emittable()
        tree = os.path.join(ROOT, trees[0])
        for name in sorted(os.listdir(tree)):
            if not name.endswith((".yaml", ".yml")):
                continue
            with open(os.path.join(tree, name), encoding="utf-8") as fh:
                fw = yaml.safe_load(fh)
            for ctrl in fw.get("controls", []):
                if ctrl.get("aegis_scope") in ("out-of-scope", "not-assessed"):
                    continue
                ev = ctrl.get("evidence") or {}
                dead = [c for c in ev.get("cwe", []) if c.upper() not in live_cwe]
                dead += [o for o in ev.get("owasp", []) if o not in live_ow]
                if dead:
                    problems.append(
                        f"{name}: control {ctrl['id']} references identifiers no engine can emit: {dead}"
                    )
                usable = [c for c in ev.get("cwe", []) if c.upper() in live_cwe]
                usable += [o for o in ev.get("owasp", []) if o in live_ow]
                if not usable:
                    problems.append(
                        f"{name}: control {ctrl['id']} is scored but nothing can produce its evidence; "
                        f"mark it aegis_scope: not-assessed"
                    )

    if problems:
        print("compliance structure check FAILED:\n")
        for p in problems:
            print(f"  - {p}")
        print(
            "\nIf you added a detector that emits a new identifier, refresh the inventory:\n"
            "  python scripts/refresh_emittable_identifiers.py"
        )
        return 1

    print(f"compliance structure OK: single framework tree at {trees[0]}, all evidence identifiers emittable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
