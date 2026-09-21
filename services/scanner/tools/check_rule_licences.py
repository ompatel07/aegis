#!/usr/bin/env python3
"""Fail the build if a rule with a non-permitted licence can reach a scan (N1).

Pass N1 removed the 16 Semgrep-registry packs (Semgrep Rules License v1.0) after
Semgrep declined an OEM licence and declined relicensing. This script makes that
cut structurally permanent rather than a state someone has to remember:

  1. Every pack under rules/vendor/ is listed in rules/manifest.yaml, its sha256
     matches, and EVERY rule in it declares a licence in `permitted_licences`.
     The licence is read from each rule's own `metadata.license`, never inferred
     from the file name or the manifest.
  2. No vendored file exists that the manifest does not describe (an orphan pack
     would be loaded by nothing today and by anything tomorrow).
  3. Every rule OUTSIDE vendor/ is Aegis-authored: an `aegis-` id and none of the
     fingerprints a registry rule carries (`metadata.license`, `metadata.source`,
     `metadata.semgrep.dev`). A registry rule pasted into rules/taint/ fails here.
  4. No rule anywhere carries a known-restricted licence (Semgrep Rules License,
     AGPL, Commons Clause) or the AGPL `trailofbits.` id prefix -- and no rule's
     MATCHING LOGIC equals that of a rule removed in N1
     (tools/restricted_rule_fingerprints.txt, hashes only). That last check is
     what catches a registry rule pasted in with its metadata stripped and an
     `aegis-` id: metadata can be edited away, the patterns cannot without
     writing a different rule.
  5. The scanner cannot be configured to fetch rules: the shipped default for
     `semgrep_base_configs` names no registry pack, and the source contains no
     registry-fetch construct (`p/semgrep-rule-lints` via `--validate`, `--config
     auto`, a `semgrep.dev/c/` URL).

The behavioural half of (5) -- the engine refusing a `p/...` config even when an
operator sets one -- is tested in tests/test_rule_licences.py.

Run: python services/scanner/tools/check_rule_licences.py
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys

import yaml

SCANNER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(SCANNER, "rules")
VENDOR = os.path.join(RULES, "vendor")
MANIFEST = os.path.join(RULES, "manifest.yaml")

RESTRICTED = re.compile(r"semgrep rules license|affero|\bagpl\b|commons clause", re.IGNORECASE)
REGISTRY_FINGERPRINTS = ("license", "source", "semgrep.dev")
FINGERPRINTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "restricted_rule_fingerprints.txt")
LOGIC_KEYS = ("pattern", "patterns", "pattern-either", "pattern-regex", "mode", "pattern-sources",
              "pattern-sinks", "pattern-sanitizers", "pattern-propagators", "languages")


def logic_fingerprint(rule: dict) -> str:
    """SHA-256 of a rule's matching logic -- the same function that built the list."""
    logic = {k: rule.get(k) for k in LOGIC_KEYS if k in rule}
    return hashlib.sha256(json.dumps(logic, sort_keys=True, default=str).encode()).hexdigest()


def restricted_fingerprints() -> set[str]:
    with open(FINGERPRINTS, encoding="utf-8") as fh:
        return {ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")}


# Source constructs that fetch rules from the Semgrep registry.
FETCH_CONSTRUCTS = [
    (re.compile(r"""["']--validate["']"""), "`semgrep --validate` downloads p/semgrep-rule-lints from the registry"),
    (re.compile(r"""["']--config["']\s*,\s*["']auto["']"""), "`--config auto` fetches registry rules"),
    (re.compile(r"semgrep\.dev/c/"), "a semgrep.dev/c/ registry URL"),
]
SOURCE_SKIP = {"tests", "tools", ".venv", "__pycache__", "rules", "node_modules"}


def _rule_docs(path: str) -> list[dict] | None:
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
        return None
    return doc["rules"]


def main() -> int:
    problems: list[str] = []

    with open(MANIFEST, encoding="utf-8") as fh:
        man = yaml.safe_load(fh) or {}
    permitted = set(man.get("permitted_licences") or [])
    if not permitted:
        problems.append("manifest.yaml declares no permitted_licences")
    if man.get("registry"):
        problems.append(f"manifest.yaml still names a registry: {man['registry']}")

    # 1 + 2: vendored packs
    described = {}
    for p in man.get("packs") or []:
        described[os.path.normpath(os.path.join(RULES, p["file"]))] = p
        src = str(p.get("source", ""))
        if "semgrep.dev" in src:
            problems.append(f"manifest pack {p['pack']} is sourced from the Semgrep registry: {src}")
    for name in sorted(os.listdir(VENDOR)):
        if not name.endswith((".yaml", ".yml")):
            continue
        path = os.path.normpath(os.path.join(VENDOR, name))
        p = described.get(path)
        if p is None:
            problems.append(f"vendor/{name} is not described by manifest.yaml (orphan pack)")
            continue
        with open(path, "rb") as fh:
            sha = hashlib.sha256(fh.read()).hexdigest()
        if sha != p.get("sha256"):
            problems.append(f"vendor/{name}: sha256 {sha[:12]} does not match manifest {str(p.get('sha256'))[:12]}")
        rules = _rule_docs(path) or []
        if len(rules) != p.get("rules"):
            problems.append(f"vendor/{name}: {len(rules)} rules, manifest says {p.get('rules')}")
        for r in rules:
            meta = r.get("metadata") or {}
            lic = meta.get("license")
            if lic not in permitted:
                problems.append(f"vendor/{name}: rule {r.get('id')} has licence {lic!r}, not in {sorted(permitted)}")
            # A copy obtained through the Semgrep registry carries its annotations
            # (semgrep.dev block, sg.run shortlink, semgrep.dev/r source). Vendored
            # packs are built from upstream source only (scripts/vendor_rules.py).
            if "semgrep.dev" in meta or "shortlink" in meta or "semgrep.dev" in str(meta.get("source", "")):
                problems.append(f"vendor/{name}: rule {r.get('id')} carries Semgrep-registry metadata; "
                                f"rebuild the pack from upstream with scripts/vendor_rules.py")
    for path in described:
        if not os.path.isfile(path):
            problems.append(f"manifest describes {os.path.relpath(path, RULES)} but the file is missing")

    # 3 + 4: every rule file anywhere under rules/
    restricted = restricted_fingerprints()
    if len(restricted) < 1000:
        problems.append(f"restricted_rule_fingerprints.txt holds only {len(restricted)} hashes; expected 1,141")
    n_own = n_vendor = 0
    for dirpath, _dirs, files in os.walk(RULES):
        in_vendor = os.path.normpath(dirpath).startswith(os.path.normpath(VENDOR))
        for name in files:
            if not name.endswith((".yaml", ".yml")):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, RULES)
            try:
                rules = _rule_docs(path)
            except yaml.YAMLError as exc:
                problems.append(f"{rel}: unparseable ({exc.__class__.__name__})")
                continue
            if rules is None:
                continue
            for r in rules:
                rid = str(r.get("id", ""))
                meta = r.get("metadata") or {}
                if rid.startswith("trailofbits."):
                    problems.append(f"{rel}: {rid} is a trailofbits (AGPL-3.0) rule")
                if RESTRICTED.search(str(meta.get("license", ""))):
                    problems.append(f"{rel}: {rid} carries a restricted licence: {meta.get('license')}")
                if logic_fingerprint(r) in restricted:
                    problems.append(f"{rel}: {rid} has the same matching logic as a Semgrep-licensed "
                                    f"rule removed in N1")
                if in_vendor:
                    n_vendor += 1
                    continue
                n_own += 1
                if not rid.startswith("aegis-"):
                    problems.append(f"{rel}: rule {rid!r} outside vendor/ must be Aegis-authored (aegis- id)")
                marks = [k for k in REGISTRY_FINGERPRINTS if k in meta]
                if marks:
                    problems.append(f"{rel}: rule {rid} carries registry-rule metadata {marks}")

    # 5: no configured or coded registry fetch
    cfg = open(os.path.join(SCANNER, "config.py"), encoding="utf-8").read()
    m = re.search(r"semgrep_base_configs:[^\n]*\n?[^\n]*default\s*=\s*(['\"])(.*?)\1", cfg)
    if m is None:
        problems.append("config.py: could not locate the semgrep_base_configs default")
    elif m.group(2).strip():
        problems.append(f"config.py: semgrep_base_configs defaults to {m.group(2)!r}; it must be empty")
    for dirpath, dirs, files in os.walk(SCANNER):
        dirs[:] = [d for d in dirs if d not in SOURCE_SKIP]
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(dirpath, name)
            text = open(path, encoding="utf-8", errors="ignore").read()
            for rx, why in FETCH_CONSTRUCTS:
                for hit in rx.finditer(text):
                    line = text.count("\n", 0, hit.start()) + 1
                    problems.append(f"{os.path.relpath(path, SCANNER)}:{line}: {why}")

    if problems:
        print("rule licence check FAILED:\n")
        for p in problems:
            print(f"  - {p}")
        print("\nOnly rules we wrote, or rules under a licence in manifest.yaml:permitted_licences,"
              "\nmay ship. See services/scanner/rules/vendor/NOTICE.md and docs/RULE_REMOVAL_N1.md.")
        return 1

    print(f"rule licences OK: {n_own} Aegis-authored rules, {n_vendor} vendored rules "
          f"({', '.join(sorted(permitted))}), no registry fetch path")
    return 0


if __name__ == "__main__":
    sys.exit(main())
